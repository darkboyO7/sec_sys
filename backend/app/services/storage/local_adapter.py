"""
Local Filesystem Evidence Storage Adapter.
Provides atomic staging, write-once-read-many (WORM) filesystem enforcement,
SHA-256 integrity checks, and prevents silent replacement of preserved evidence.
"""
import os
import stat
import json
import uuid
import shutil
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.core.config import settings
from app.models.base import utc_now
from app.services.storage.base import (
    BaseEvidenceStorageAdapter,
    EvidenceStorageError,
    EvidenceNotFoundError,
    EvidenceIntegrityError,
    EvidenceOverwriteError,
)


class LocalStorageAdapter(BaseEvidenceStorageAdapter):
    """
    Local filesystem storage adapter implementing strict immutable evidence retention.
    """

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = Path(root_dir) if root_dir else settings.get_evidence_path()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_path(self, key: str) -> Path:
        """Sanitizes key to prevent directory traversal and returns absolute Path."""
        clean_key = Path(key.lstrip("/\\")).as_posix()
        if ".." in clean_key:
            raise EvidenceStorageError(f"Directory traversal prohibited in storage key: '{key}'")
        target = (self.root_dir / clean_key).resolve()
        if not str(target).startswith(str(self.root_dir.resolve())):
            raise EvidenceStorageError(f"Resolved path escapes evidence root directory: '{key}'")
        return target

    def store_evidence(
        self,
        key: str,
        payload: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """
        Atomically writes evidence to a staging file and commits to final location.
        Raises EvidenceOverwriteError if the object already exists.
        """
        final_path = self._resolve_path(key)
        final_path.parent.mkdir(parents=True, exist_ok=True)

        # Invariant: Never silently replace previously preserved evidence
        if final_path.exists():
            raise EvidenceOverwriteError(f"Evidence object '{key}' already exists and cannot be overwritten.")

        calculated_sha256 = hashlib.sha256(payload).hexdigest()
        meta_dict = {
            "key": key,
            "sha256": calculated_sha256,
            "size_bytes": len(payload),
            "content_type": content_type,
            "stored_at": utc_now().isoformat(),
            "metadata": metadata or {},
        }

        # Atomic staging: write to .tmp file first
        tmp_id = uuid.uuid4().hex[:8]
        tmp_path = final_path.parent / f".tmp_{final_path.name}_{tmp_id}"
        meta_tmp_path = final_path.parent / f".tmp_{final_path.name}_{tmp_id}.meta.json"
        meta_final_path = final_path.parent / f"{final_path.name}.meta.json"

        try:
            with open(tmp_path, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())

            with open(meta_tmp_path, "w", encoding="utf-8") as f:
                json.dump(meta_dict, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Commit atomically via rename
            os.replace(tmp_path, final_path)
            os.replace(meta_tmp_path, meta_final_path)

            # Enforce read-only permission (WORM local simulation)
            try:
                os.chmod(final_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            except Exception:
                pass

            return {
                "key": key,
                "sha256": calculated_sha256,
                "size_bytes": len(payload),
                "storage_backend": "LOCAL",
                "path": str(final_path),
            }
        except Exception as e:
            # Clean up temporary staging on failure
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            if meta_tmp_path.exists():
                try:
                    meta_tmp_path.unlink()
                except Exception:
                    pass
            raise EvidenceStorageError(f"Failed to store evidence object '{key}': {str(e)}") from e

    def retrieve_evidence(
        self,
        key: str,
        expected_sha256: Optional[str] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieves evidence object and verifies cryptographic digest.
        """
        final_path = self._resolve_path(key)
        if not final_path.exists():
            raise EvidenceNotFoundError(f"Evidence object '{key}' not found in storage.")

        with open(final_path, "rb") as f:
            data = f.read()

        actual_sha256 = hashlib.sha256(data).hexdigest()

        # Integrity verification
        if expected_sha256 and actual_sha256 != expected_sha256.lower().strip():
            raise EvidenceIntegrityError(
                f"Evidence integrity compromised for '{key}': expected {expected_sha256}, got {actual_sha256}"
            )

        meta_path = final_path.parent / f"{final_path.name}.meta.json"
        metadata = {}
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
            except Exception:
                metadata = {"sha256": actual_sha256, "size_bytes": len(data)}
        else:
            metadata = {"sha256": actual_sha256, "size_bytes": len(data)}

        return data, metadata

    def verify_object(self, key: str, expected_sha256: str) -> bool:
        """
        Non-mutating hash verification of stored evidence.
        """
        try:
            _, meta = self.retrieve_evidence(key, expected_sha256=expected_sha256)
            return True
        except EvidenceStorageError:
            return False

    def check_worm_status(self, key: Optional[str] = None) -> Dict[str, Any]:
        """
        Truthfully reports WORM capability. Never claims hardware/cloud WORM on local disk.
        """
        return {
            "provider": "LOCAL_FILESYSTEM",
            "worm_compliant": False,
            "worm_mode": "OS_READONLY_SIMULATION",
            "object_lock_supported": False,
            "legal_holds_supported": False,
            "note": "Local filesystem uses read-only file attributes (0o444). Cloud/hardware Object Lock is only available on configured S3/WORM providers.",
        }

    def delete_evidence(self, key: str, tombstone_digest: str) -> bool:
        """
        Authorized deletion requiring a non-empty cryptographic tombstone digest.
        """
        if not tombstone_digest or len(tombstone_digest) < 32:
            raise EvidenceStorageError("Deletion rejected: cryptographically signed tombstone digest required.")

        final_path = self._resolve_path(key)
        if not final_path.exists():
            return False

        # Reset read-only attribute to permit deletion
        try:
            os.chmod(final_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

        final_path.unlink()
        meta_path = final_path.parent / f"{final_path.name}.meta.json"
        if meta_path.exists():
            try:
                meta_path.unlink()
            except Exception:
                pass
        return True

    def list_evidence(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Lists stored evidence files."""
        items = []
        for p in self.root_dir.rglob("*"):
            if p.is_file() and not p.name.startswith(".tmp_") and not p.name.endswith(".meta.json"):
                rel_key = p.relative_to(self.root_dir).as_posix()
                if not prefix or rel_key.startswith(prefix):
                    items.append({
                        "key": rel_key,
                        "size_bytes": p.stat().st_size,
                        "modified_at": p.stat().st_mtime,
                    })
        return items

    def get_storage_health(self) -> Dict[str, Any]:
        """Checks writability and storage capacity."""
        probe_path = self.root_dir / f".probe_{uuid.uuid4().hex[:6]}.tmp"
        writable = False
        try:
            probe_path.write_text("health_probe", encoding="utf-8")
            probe_path.unlink()
            writable = True
        except Exception:
            writable = False

        total, used, free = shutil.disk_usage(self.root_dir)
        return {
            "backend": "LOCAL",
            "path": str(self.root_dir),
            "writable": writable,
            "total_bytes": total,
            "free_bytes": free,
            "used_bytes": used,
            "free_pct": round((free / total) * 100.0, 1) if total > 0 else 0.0,
        }

"""
Evidence Storage Adapter Factory.
Provides a unified factory method to retrieve the configured evidence storage provider.
"""
from typing import Optional
from app.core.config import settings
from app.services.storage.base import BaseEvidenceStorageAdapter
from app.services.storage.local_adapter import LocalStorageAdapter
from app.services.storage.s3_adapter import S3CompatibleStorageAdapter

_cached_adapter: Optional[BaseEvidenceStorageAdapter] = None


def get_evidence_storage_adapter(force_fresh: bool = False) -> BaseEvidenceStorageAdapter:
    """
    Returns the configured evidence storage adapter instance.
    Supports LOCAL filesystem and S3 / S3-compatible remote object storage.
    """
    global _cached_adapter
    if _cached_adapter is not None and not force_fresh:
        return _cached_adapter

    backend = (settings.EVIDENCE_STORAGE_BACKEND or "LOCAL").strip().upper()
    if backend in ("S3", "S3_COMPATIBLE", "AWS_S3", "MINIO", "GCS_S3"):
        adapter = S3CompatibleStorageAdapter()
    elif backend in ("LOCAL", "FILESYSTEM", "FILE"):
        adapter = LocalStorageAdapter()
    else:
        # Default fallback to LocalStorageAdapter for safety and stability
        adapter = LocalStorageAdapter()

    if not force_fresh:
        _cached_adapter = adapter
    return adapter


def reset_evidence_storage_adapter() -> None:
    """Resets cached adapter instance (useful during unit and integration tests)."""
    global _cached_adapter
    _cached_adapter = None

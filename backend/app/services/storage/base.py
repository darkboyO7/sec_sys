"""
Base Evidence Storage Adapter Interface & Contracts.
Defines storage abstractions for immutable evidence preservation,
remote S3-compatible object storage, local WORM simulation, and hash verification.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple


class EvidenceStorageError(Exception):
    """Base exception for evidence storage operations."""
    pass


class EvidenceNotFoundError(EvidenceStorageError):
    """Raised when the requested evidence object does not exist in storage."""
    pass


class EvidenceIntegrityError(EvidenceStorageError):
    """Raised when retrieved evidence object hash does not match expected SHA-256 digest."""
    pass


class EvidenceOverwriteError(EvidenceStorageError):
    """Raised when an attempt is made to overwrite previously preserved evidence."""
    pass


class WormComplianceError(EvidenceStorageError):
    """Raised when WORM immutability or Object Lock restrictions are violated."""
    pass


class BaseEvidenceStorageAdapter(ABC):
    """
    Abstract contract for forensic evidence storage providers.
    Enforces write-once-read-many (WORM) semantics, atomic staging,
    hash verification on ingress/egress, and zero silent overwrites.
    """

    @abstractmethod
    def store_evidence(
        self,
        key: str,
        payload: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """
        Stores an evidence payload immutably.
        Must use atomic staging (temporary file/key) to prevent partial uploads.
        Must raise EvidenceOverwriteError if the key already exists.
        """
        pass

    @abstractmethod
    def retrieve_evidence(
        self,
        key: str,
        expected_sha256: Optional[str] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieves evidence payload and metadata.
        If expected_sha256 is supplied, recomputes SHA-256 of retrieved bytes
        and raises EvidenceIntegrityError if there is any mismatch.
        """
        pass

    @abstractmethod
    def verify_object(self, key: str, expected_sha256: str) -> bool:
        """
        Verifies the cryptographic digest of an object in storage without altering it.
        """
        pass

    @abstractmethod
    def check_worm_status(self, key: Optional[str] = None) -> Dict[str, Any]:
        """
        Tests whether Object Lock / WORM immutability is genuinely enforced
        by the underlying storage provider. Never claims WORM without verification.
        """
        pass

    @abstractmethod
    def delete_evidence(self, key: str, tombstone_digest: str) -> bool:
        """
        Deletes or tombstones an evidence object under strict governance rules.
        Requires a cryptographically signed tombstone digest.
        """
        pass

    @abstractmethod
    def list_evidence(self, prefix: str = "") -> List[Dict[str, Any]]:
        """
        Lists stored evidence objects and their digests under a given prefix.
        """
        pass

    @abstractmethod
    def get_storage_health(self) -> Dict[str, Any]:
        """
        Returns health status, writability, free space, and provider metadata.
        """
        pass

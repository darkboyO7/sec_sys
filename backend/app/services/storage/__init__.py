"""
Forensic Evidence Storage Package.
Provides storage interfaces, local WORM storage, S3 object storage adapters,
and factory initialization.
"""
from app.services.storage.base import (
    BaseEvidenceStorageAdapter,
    EvidenceStorageError,
    EvidenceNotFoundError,
    EvidenceIntegrityError,
    EvidenceOverwriteError,
    WormComplianceError,
)
from app.services.storage.local_adapter import LocalStorageAdapter
from app.services.storage.s3_adapter import S3CompatibleStorageAdapter
from app.services.storage.factory import (
    get_evidence_storage_adapter,
    reset_evidence_storage_adapter,
)

__all__ = [
    "BaseEvidenceStorageAdapter",
    "EvidenceStorageError",
    "EvidenceNotFoundError",
    "EvidenceIntegrityError",
    "EvidenceOverwriteError",
    "WormComplianceError",
    "LocalStorageAdapter",
    "S3CompatibleStorageAdapter",
    "get_evidence_storage_adapter",
    "reset_evidence_storage_adapter",
]

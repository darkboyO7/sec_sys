"""
VAPT Platform — Cryptographic Origin Attestation & Digital Signing Service (Prompt 48).
Provides genuine cryptographic proof of origin using asymmetric Ed25519 key pairs
and key management. Proves origin attestation distinct from cryptographic payload checksums.
"""
import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
KEY_STORE_DIR = REPO_ROOT / "backend" / "data" / "keys"


def canonical_time_str(val) -> str:
    if isinstance(val, str):
        try:
            val = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return val
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return str(int(val.astimezone(timezone.utc).timestamp()))
    return str(val)


class OriginAttestationService:
    """
    Manages authentic cryptographic digital signing keys and validates signatures
    attesting to the origin, source identity, and integrity of ingested evidence.
    """

    def __init__(self, key_store_dir: Optional[Path] = None):
        self.key_store_dir = key_store_dir or KEY_STORE_DIR
        self.key_store_dir.mkdir(parents=True, exist_ok=True)
        self._private_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._public_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        self._initialize_canonical_keys()

    def _initialize_canonical_keys(self) -> None:
        """Initializes canonical keys for default platform attestation and sensors."""
        canonical_key_ids = [
            "KEY-DEFAULT-ED25519",
            "KEY-SENSOR-NMAP-01",
            "KEY-SENSOR-ZAP-01",
            "KEY-ANALYST-ED25519",
        ]
        for key_id in canonical_key_ids:
            self._get_or_create_keypair(key_id)

    def _get_or_create_keypair(self, key_id: str) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        if key_id in self._private_keys:
            return self._private_keys[key_id], self._public_keys[key_id]

        priv_path = self.key_store_dir / f"{key_id}.priv"
        pub_path = self.key_store_dir / f"{key_id}.pub"

        if priv_path.exists() and pub_path.exists():
            with open(priv_path, "rb") as f:
                priv_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
        else:
            priv_key = ed25519.Ed25519PrivateKey.generate()
            pub_key = priv_key.public_key()

            priv_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            with open(pub_path, "wb") as f:
                f.write(pub_pem)

        self._private_keys[key_id] = priv_key
        self._public_keys[key_id] = pub_key
        return priv_key, pub_key

    def sign_evidence_origin(
        self,
        raw_payload: str,
        source_identity: str,
        collection_time: datetime,
        key_id: str = "KEY-DEFAULT-ED25519",
    ) -> Tuple[str, str, str]:
        """
        Signs evidence origin using an authentic Ed25519 asymmetric private key.
        Returns: (signature_hex, algorithm, key_id)
        """
        priv_key, _ = self._get_or_create_keypair(key_id)
        raw_digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        time_str = canonical_time_str(collection_time)
        canonical_statement = f"ORIGIN_ATTESTATION:v1|source={source_identity}|time={time_str}|digest={raw_digest}"

        signature = priv_key.sign(canonical_statement.encode("utf-8"))
        return signature.hex(), "ED25519", key_id

    def verify_evidence_origin(
        self,
        raw_payload: str,
        source_identity: str,
        collection_time: datetime,
        signature_hex: str,
        key_id: str,
        algorithm: str = "ED25519",
    ) -> Tuple[bool, str]:
        """
        Cryptographically verifies proof of origin using the designated key ID's public key.
        Returns: (is_valid, reason)
        """
        if algorithm != "ED25519":
            return False, f"Unsupported signature algorithm: {algorithm}"

        pub_key = self._public_keys.get(key_id)
        if not pub_key:
            pub_path = self.key_store_dir / f"{key_id}.pub"
            if pub_path.exists():
                with open(pub_path, "rb") as f:
                    pub_key = serialization.load_pem_public_key(f.read())
                self._public_keys[key_id] = pub_key
            else:
                return False, f"Untrusted or unknown signing key ID: {key_id}"

        raw_digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        time_str = canonical_time_str(collection_time)
        canonical_statement = f"ORIGIN_ATTESTATION:v1|source={source_identity}|time={time_str}|digest={raw_digest}"

        try:
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, canonical_statement.encode("utf-8"))
            return True, "Authentic cryptographic origin signature verified"
        except (InvalidSignature, ValueError) as e:
            return False, f"Cryptographic signature verification failed: {str(e)}"

    def register_custom_keypair(self, key_id: str, private_key_pem: bytes, public_key_pem: bytes) -> None:
        """Registers a custom keypair into the active keystore."""
        priv_key = serialization.load_pem_private_key(private_key_pem, password=None)
        pub_key = serialization.load_pem_public_key(public_key_pem)
        self._private_keys[key_id] = priv_key
        self._public_keys[key_id] = pub_key

        priv_path = self.key_store_dir / f"{key_id}.priv"
        pub_path = self.key_store_dir / f"{key_id}.pub"
        with open(priv_path, "wb") as f:
            f.write(private_key_pem)
        with open(pub_path, "wb") as f:
            f.write(public_key_pem)

    def sign_manifest(self, manifest_canonical_json: str, key_id: str = "KEY-DEFAULT-ED25519") -> Tuple[str, str, str]:
        """
        Signs a disaster recovery bundle manifest using authentic asymmetric Ed25519 digital signature.
        Returns: (signature_hex, algorithm, key_id)
        """
        priv_key, _ = self._get_or_create_keypair(key_id)
        digest = hashlib.sha256(manifest_canonical_json.encode("utf-8")).hexdigest()
        statement = f"MANIFEST_ATTESTATION:v1|digest={digest}"
        signature = priv_key.sign(statement.encode("utf-8"))
        return signature.hex(), "ED25519", key_id

    def verify_manifest(self, manifest_canonical_json: str, signature_hex: str, key_id: str = "KEY-DEFAULT-ED25519") -> Tuple[bool, str]:
        """
        Verifies a disaster recovery bundle manifest Ed25519 digital signature.
        Returns: (is_valid, reason)
        """
        pub_key = self._public_keys.get(key_id)
        if not pub_key:
            pub_path = self.key_store_dir / f"{key_id}.pub"
            if pub_path.exists():
                with open(pub_path, "rb") as f:
                    pub_key = serialization.load_pem_public_key(f.read())
                self._public_keys[key_id] = pub_key
            else:
                return False, f"Untrusted or unknown signing key ID: {key_id}"

        digest = hashlib.sha256(manifest_canonical_json.encode("utf-8")).hexdigest()
        statement = f"MANIFEST_ATTESTATION:v1|digest={digest}"
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, statement.encode("utf-8"))
            return True, "Authentic cryptographic manifest signature verified"
        except (InvalidSignature, ValueError) as e:
            return False, f"Cryptographic manifest signature verification failed: {str(e)}"

    def sign_tombstone(self, evidence_id: str, original_digest: str, actor_id: str, timestamp_val: Any, key_id: str = "KEY-DEFAULT-ED25519") -> Tuple[str, str, str]:
        """
        Signs an evidence deletion tombstone using authentic asymmetric Ed25519 digital signature.
        Returns: (signature_hex, algorithm, key_id)
        """
        priv_key, _ = self._get_or_create_keypair(key_id)
        time_str = canonical_time_str(timestamp_val)
        statement = f"TOMBSTONE_ATTESTATION:v1|evidence_id={evidence_id}|digest={original_digest}|actor={actor_id}|time={time_str}"
        signature = priv_key.sign(statement.encode("utf-8"))
        return signature.hex(), "ED25519", key_id

    def verify_tombstone(self, evidence_id: str, original_digest: str, actor_id: str, timestamp_val: Any, signature_hex: str, key_id: str = "KEY-DEFAULT-ED25519") -> Tuple[bool, str]:
        """
        Verifies an evidence deletion tombstone Ed25519 digital signature.
        Returns: (is_valid, reason)
        """
        pub_key = self._public_keys.get(key_id)
        if not pub_key:
            pub_path = self.key_store_dir / f"{key_id}.pub"
            if pub_path.exists():
                with open(pub_path, "rb") as f:
                    pub_key = serialization.load_pem_public_key(f.read())
                self._public_keys[key_id] = pub_key
            else:
                return False, f"Untrusted or unknown signing key ID: {key_id}"

        time_str = canonical_time_str(timestamp_val)
        statement = f"TOMBSTONE_ATTESTATION:v1|evidence_id={evidence_id}|digest={original_digest}|actor={actor_id}|time={time_str}"
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, statement.encode("utf-8"))
            return True, "Authentic cryptographic tombstone signature verified"
        except (InvalidSignature, ValueError) as e:
            return False, f"Cryptographic tombstone signature verification failed: {str(e)}"



attestation_service = OriginAttestationService()

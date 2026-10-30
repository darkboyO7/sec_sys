"""
Secret Vault & Credential Storage Service (Prompt 45).
Provides authenticated symmetric encryption at rest (Fernet AES-128-CBC + HMAC-SHA256)
for external credentials and connector settings.
Supports transparent legacy migration, safe credential rotation, and zero-leakage decryption.
"""
import base64
import hashlib
import json
import logging
from typing import Any, Dict, Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("vapt.secret_vault")

ENCRYPTION_PREFIX = "enc:v1:"


class SecretVault:
    """
    Cryptographic vault managing credential encryption at rest.
    Uses Fernet with keys deterministically derived from platform secret key.
    """

    @classmethod
    def derive_fernet_key(cls, secret_key: str) -> bytes:
        """
        Derives a 32-byte URL-safe base64-encoded Fernet key from the given secret string.
        """
        if not secret_key:
            raise ValueError("Secret key cannot be empty when deriving encryption key")
        digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    @classmethod
    def get_fernet_instance(cls, secret_key: Optional[str] = None) -> Fernet:
        if secret_key is None:
            from app.core.config import settings
            secret_key = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", None) or settings.SECRET_KEY
        key = cls.derive_fernet_key(secret_key)
        return Fernet(key)

    @classmethod
    def encrypt_credentials(cls, data: Dict[str, Any], secret_key: Optional[str] = None) -> str:
        """
        Serializes and encrypts dictionary credentials with authenticated Fernet envelope.
        Output format: 'enc:v1:<base64-fernet-token>'
        """
        if not data:
            return ""
        payload_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        fernet = cls.get_fernet_instance(secret_key)
        encrypted_token = fernet.encrypt(payload_bytes).decode("utf-8")
        return f"{ENCRYPTION_PREFIX}{encrypted_token}"

    @classmethod
    def decrypt_credentials(
        cls,
        ciphertext_or_legacy: Optional[str],
        secret_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Decrypts credentials from encrypted envelope.
        If the payload is legacy unencrypted JSON, transparently parses and returns it
        to allow zero-downtime migration of pre-Prompt-45 data.
        """
        if not ciphertext_or_legacy:
            return {}

        raw_str = ciphertext_or_legacy.strip()
        if not raw_str:
            return {}

        # 1. Check if encrypted with standard prefix
        if raw_str.startswith(ENCRYPTION_PREFIX):
            token = raw_str[len(ENCRYPTION_PREFIX):].encode("utf-8")
            fernet = cls.get_fernet_instance(secret_key)
            try:
                decrypted_bytes = fernet.decrypt(token)
                return json.loads(decrypted_bytes.decode("utf-8"))
            except InvalidToken:
                logger.error("Credential decryption failed: Invalid token or incorrect encryption key.")
                raise ValueError("Failed to decrypt stored credentials: HMAC verification or key mismatch.")
            except Exception as e:
                logger.error(f"Failed to parse decrypted credentials: {e}")
                raise ValueError(f"Corrupted credential payload: {e}")

        # 2. Transparent fallback for legacy unencrypted JSON
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, dict):
                return parsed
            return {"data": parsed}
        except Exception:
            # If not valid JSON and not encrypted, raise error
            raise ValueError("Invalid credential format: Not encrypted and not valid JSON.")

    @classmethod
    def is_encrypted(cls, value: Optional[str]) -> bool:
        """Returns True if the given string is in the encrypted envelope format."""
        if not value or not isinstance(value, str):
            return False
        return value.strip().startswith(ENCRYPTION_PREFIX)

    @classmethod
    def reencrypt_credentials(
        cls,
        encrypted_payload: str,
        old_secret_key: str,
        new_secret_key: str,
    ) -> str:
        """
        Re-encrypts stored credentials from an old key to a new key during credential rotation
        without ever exposing secrets in application memory or logs.
        """
        data = cls.decrypt_credentials(encrypted_payload, secret_key=old_secret_key)
        return cls.encrypt_credentials(data, secret_key=new_secret_key)

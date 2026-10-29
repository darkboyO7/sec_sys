"""
Domain exception hierarchy for the VAPT System.
"""
from typing import Optional


class VAPTException(Exception):
    """Base application exception."""
    def __init__(self, message: str = "", details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(VAPTException):
    """Resource not found."""
    pass


class ConflictError(VAPTException):
    """Resource conflict or duplicate version."""
    pass


class ValidationError(VAPTException):
    """Business rule or input validation violation."""
    pass


class AuthorizationError(VAPTException):
    """Access control, SoD, or permission failure."""
    pass

import uuid
import time
import logging
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException as FastAPIHTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError
from app.core.config import settings
from app.core.database import Base, engine, get_db
from app.api.v1.router import api_router
from app.schemas.error import APIErrorResponse, APIErrorCode
from app.services.network_security_service import (
    DestinationRestrictedError,
    OversizedResponseError,
    NetworkSecurityTimeoutError,
)
from app.core.logging import (
    setup_structured_logging,
    sanitize_correlation_id,
    set_correlation_id,
    get_correlation_id,
)
from app.services.metrics_service import metrics_service

# Configure root structured logging with correlation context and redaction
logger = setup_structured_logging(level=logging.INFO if not settings.DEBUG else logging.DEBUG)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract and sanitize correlation/request ID to defend against log injection
        raw_header = request.headers.get("X-Correlation-ID") or request.headers.get("X-Request-ID")
        corr_id = sanitize_correlation_id(raw_header)
        set_correlation_id(corr_id)

        # Attach to request state
        request.state.correlation_id = corr_id
        request.state.request_id = corr_id

        start_time = time.perf_counter()
        response = await call_next(request)
        duration = (time.perf_counter() - start_time) * 1000

        # Attach telemetry headers
        response.headers["X-Correlation-ID"] = corr_id
        response.headers["X-Request-ID"] = corr_id
        response.headers["X-Response-Time-MS"] = f"{duration:.2f}"

        # Record operational metrics
        try:
            metrics_service.record_api_request(
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration,
            )
        except Exception:
            pass

        logger.info(
            f"corr_id={corr_id} method={request.method} path={request.url.path} status={response.status_code} duration_ms={duration:.2f}"
        )
        return response


class ContentLengthLimitMiddleware(BaseHTTPMiddleware):
    """
    Guards against denial-of-service via unbounded HTTP request payloads.
    Rejects requests exceeding the maximum permitted size with HTTP 413 Payload Too Large.
    """
    def __init__(self, app, max_content_length: int = 10 * 1024 * 1024):  # 10MB default
        super().__init__(app)
        self.max_content_length = max_content_length

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
                limit = self.max_content_length
                # Tighten limit for standard JSON endpoints to 2MB to defend against payload bombs
                if request.url.path.startswith("/api/v1/") and not any(p in request.url.path for p in ["/reports/export", "/recovery/"]):
                    limit = min(limit, 2 * 1024 * 1024)

                if cl > limit:
                    corr_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or getattr(request.state, "correlation_id", "unknown")
                    err = APIErrorResponse(
                        error_code=APIErrorCode.PAYLOAD_TOO_LARGE.value,
                        message=f"Request payload exceeds maximum permitted limit ({limit} bytes).",
                        detail=f"Request payload exceeds maximum permitted limit ({limit} bytes).",
                        request_id=corr_id,
                        retryable=False,
                    )
                    return JSONResponse(
                        status_code=413,
                        content=err.model_dump(),
                        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
                    )
            except ValueError:
                corr_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or getattr(request.state, "correlation_id", "unknown")
                err = APIErrorResponse(
                    error_code=APIErrorCode.VALIDATION_ERROR.value,
                    message="Invalid Content-Length header.",
                    detail="Invalid Content-Length header.",
                    request_id=corr_id,
                    retryable=False,
                )
                return JSONResponse(
                    status_code=400,
                    content=err.model_dump(),
                    headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Enforces defense-in-depth HTTP security headers according to OWASP Secure Headers:
    - Content-Security-Policy (CSP)
    - X-Frame-Options (Clickjacking defense)
    - X-Content-Type-Options (MIME-sniffing defense)
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    - Strict-Transport-Security (HSTS)
    - Cache-Control (Strict no-store for API payloads)
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        if settings.ENVIRONMENT == "production" or request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        if request.url.path.startswith(settings.API_V1_STR):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure SQLite / local DB tables are initialized
    logger.info(f"Starting {settings.APP_NAME} in '{settings.ENVIRONMENT}' environment...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized and verified.")
    yield
    # Shutdown
    logger.info(f"Shutting down {settings.APP_NAME}...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Vulnerability Assessment and Penetration Testing (VAPT) Platform — Control Plane",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG or settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.DEBUG or settings.ENVIRONMENT == "development" else None,
    openapi_url="/openapi.json" if settings.DEBUG or settings.ENVIRONMENT == "development" else None,
    lifespan=lifespan,
)

# Request context and audit middleware
app.add_middleware(RequestContextMiddleware)
app.add_middleware(ContentLengthLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Cross-Origin Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root-level liveness and readiness probes for orchestrators (Kubernetes, AWS ALB, ECS)
@app.get("/health", include_in_schema=False)
@app.get("/health/live", include_in_schema=False)
def root_liveness():
    from app.api.v1.endpoints.health import liveness_check
    return liveness_check()


@app.get("/ready", include_in_schema=False)
@app.get("/health/ready", include_in_schema=False)
def root_readiness(db: Session = Depends(get_db)):
    from app.api.v1.endpoints.health import readiness_check
    return readiness_check(db)


@app.get("/metrics", include_in_schema=False)
def root_metrics(
    request: Request,
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
    authorization: Optional[str] = Header(None),
):
    from app.api.v1.endpoints.metrics import get_metrics_prometheus
    return get_metrics_prometheus(request, x_operator_token=x_operator_token, authorization=authorization)


@app.exception_handler(StarletteHTTPException)
@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    status_code = exc.status_code
    if isinstance(exc.detail, (dict, list)):
        detail_val = exc.detail
        detail_msg = "An HTTP error occurred."
    else:
        detail_val = str(exc.detail) if exc.detail else "An HTTP error occurred."
        detail_msg = detail_val

    status_code_map = {
        400: APIErrorCode.VALIDATION_ERROR.value,
        401: APIErrorCode.UNAUTHENTICATED.value,
        403: APIErrorCode.PERMISSION_DENIED.value,
        404: APIErrorCode.RESOURCE_NOT_FOUND.value,
        409: APIErrorCode.RESOURCE_CONFLICT.value,
        413: APIErrorCode.PAYLOAD_TOO_LARGE.value,
        422: APIErrorCode.VALIDATION_ERROR.value,
        429: APIErrorCode.RATE_LIMIT_EXCEEDED.value,
        503: APIErrorCode.DATABASE_BUSY.value,
    }
    code = status_code_map.get(status_code, APIErrorCode.INTERNAL_ERROR.value)

    err = APIErrorResponse(
        error_code=code,
        message=detail_msg,
        detail=detail_val,
        request_id=corr_id,
        correlation_id=corr_id,
        retryable=(status_code in (429, 503)),
    )
    headers = dict(exc.headers) if exc.headers else {}
    headers["X-Correlation-ID"] = corr_id
    headers["X-Request-ID"] = corr_id
    return JSONResponse(status_code=status_code, content=err.model_dump(), headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    details = []
    for err in exc.errors():
        details.append({
            "field": ".".join(str(loc) for loc in err.get("loc", [])),
            "issue": err.get("msg", "Invalid value"),
            "location": [str(loc) for loc in err.get("loc", [])],
        })

    msg = "Validation failed for one or more request fields."
    err = APIErrorResponse(
        error_code=APIErrorCode.VALIDATION_ERROR.value,
        message=msg,
        detail=msg,
        request_id=corr_id,
        details=details,
        retryable=False,
    )
    return JSONResponse(
        status_code=422,
        content=err.model_dump(),
        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
    )


@app.exception_handler(DestinationRestrictedError)
async def destination_restricted_handler(request: Request, exc: DestinationRestrictedError):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    msg = str(exc)
    err = APIErrorResponse(
        error_code=APIErrorCode.DESTINATION_RESTRICTED.value,
        message=msg,
        detail=msg,
        request_id=corr_id,
        retryable=False,
    )
    return JSONResponse(
        status_code=400,
        content=err.model_dump(),
        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
    )


@app.exception_handler(OversizedResponseError)
async def oversized_response_handler(request: Request, exc: OversizedResponseError):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    msg = str(exc)
    err = APIErrorResponse(
        error_code=APIErrorCode.PAYLOAD_TOO_LARGE.value,
        message=msg,
        detail=msg,
        request_id=corr_id,
        retryable=False,
    )
    return JSONResponse(
        status_code=413,
        content=err.model_dump(),
        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
    )


@app.exception_handler(NetworkSecurityTimeoutError)
async def network_timeout_handler(request: Request, exc: NetworkSecurityTimeoutError):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    msg = str(exc)
    err = APIErrorResponse(
        error_code=APIErrorCode.NETWORK_TIMEOUT.value,
        message=msg,
        detail=msg,
        request_id=corr_id,
        retryable=True,
    )
    return JSONResponse(
        status_code=504,
        content=err.model_dump(),
        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id, "Retry-After": "5"},
    )


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception):
    corr_id = getattr(request.state, "correlation_id", getattr(request.state, "request_id", "unknown"))
    logger.exception(f"Unhandled system exception [corr_id={corr_id}]: {str(exc)}")

    # Handle transient database contention / outage gracefully with HTTP 503
    if isinstance(exc, (SQLAlchemyOperationalError,)) or "database is locked" in str(exc).lower() or "operationalerror" in type(exc).__name__.lower():
        metrics_service.record_db_contention("unhandled_db_interruption")
        msg = "Database engine temporarily unavailable or busy. Request can be safely retried."
        err = APIErrorResponse(
            error_code=APIErrorCode.DATABASE_BUSY.value,
            message=msg,
            detail=msg,
            request_id=corr_id,
            correlation_id=corr_id,
            retryable=True,
        )
        return JSONResponse(
            status_code=503,
            content=err.model_dump(),
            headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id, "Retry-After": "1"},
        )

    if settings.ENVIRONMENT == "production":
        msg = "An internal error occurred. Please contact the administrator."
        err = APIErrorResponse(
            error_code=APIErrorCode.INTERNAL_ERROR.value,
            message=msg,
            detail=msg,
            request_id=corr_id,
            retryable=False,
        )
        return JSONResponse(
            status_code=500,
            content=err.model_dump(),
            headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
        )

    msg = f"Unhandled error: {str(exc)}"
    err = APIErrorResponse(
        error_code=APIErrorCode.INTERNAL_ERROR.value,
        message=msg,
        detail=msg,
        request_id=corr_id,
        retryable=False,
    )
    return JSONResponse(
        status_code=500,
        content=err.model_dump(),
        headers={"X-Correlation-ID": corr_id, "X-Request-ID": corr_id},
    )


# Register API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

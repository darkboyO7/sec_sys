import uuid
import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import Base, engine, get_db
from app.api.v1.router import api_router

# Configure root logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("vapt.platform")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.perf_counter()

        # Attach request id to state
        request.state.request_id = req_id

        response = await call_next(request)

        duration = (time.perf_counter() - start_time) * 1000
        response.headers["X-Request-ID"] = req_id
        response.headers["X-Response-Time-MS"] = f"{duration:.2f}"

        logger.info(
            f"req_id={req_id} method={request.method} path={request.url.path} status={response.status_code} duration_ms={duration:.2f}"
        )
        return response


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
def root_liveness():
    return {"status": "ok", "environment": settings.ENVIRONMENT, "app": settings.APP_NAME}


@app.get("/ready", include_in_schema=False)
def root_readiness(db: Session = Depends(get_db)):
    from app.api.v1.endpoints.health import readiness_check
    return readiness_check(db)


# Register API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

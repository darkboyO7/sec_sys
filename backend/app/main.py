import uuid
import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.core.database import Base, engine
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

# Cross-Origin Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

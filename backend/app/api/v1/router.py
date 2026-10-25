from fastapi import APIRouter
from app.api.v1.endpoints import health, auth, projects, scopes, audit

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health & Readiness"])
api_router.include_router(auth.router, prefix="/auth", tags=["Identity & Authentication"])
api_router.include_router(projects.router, prefix="/projects", tags=["Organizations & Projects"])
api_router.include_router(scopes.router, tags=["Scopes & Authorization"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Ledger"])

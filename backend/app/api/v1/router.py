from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    auth,
    projects,
    scopes,
    audit,
    assessments,
    findings,
    assets,
    graph,
    risk,
    integrity,
    verification,
    reports,
    digital_twin,
    regression,
    ai_analyst,
    learning,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health & Readiness"])
api_router.include_router(auth.router, prefix="/auth", tags=["Identity & Authentication"])
api_router.include_router(projects.router, prefix="/projects", tags=["Organizations & Projects"])
api_router.include_router(scopes.router, tags=["Scopes & Authorization"])
api_router.include_router(assessments.router, tags=["Assessments & Orchestration"])
api_router.include_router(findings.router, tags=["Finding Lifecycle & Deduplication"])
api_router.include_router(assets.router, tags=["Asset Inventory & Observations"])
api_router.include_router(graph.router, tags=["Universal Security Knowledge Graph"])
api_router.include_router(risk.router, tags=["Contextual Risk & Attack Paths"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Ledger"])
api_router.include_router(integrity.router, tags=["Cryptographic Integrity & Merkle Proofs"])
api_router.include_router(verification.router, tags=["Independent Remediation Verification"])
api_router.include_router(reports.router, tags=["Reporting & Export"])
api_router.include_router(digital_twin.router, tags=["Historical Security Digital Twin"])
api_router.include_router(regression.router, tags=["Regression Detection & Change Intelligence"])
api_router.include_router(ai_analyst.router, tags=["Controlled AI Security Analyst"])
api_router.include_router(learning.router, tags=["Controlled Learning & Model Governance"])

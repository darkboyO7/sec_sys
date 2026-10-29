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
    adaptive_defense,
    lifecycle,
    integrations,
    monitoring,
    decisions,
    intelligence,
    operations,
    diagnostics,
    orchestration,
    metrics,
    quality,
    drift,
    knowledge,
    governance,
    recovery,
    supply_chain,
    performance,
    security_controls,
    deployment,
    evidence_lifecycle,
    operations_cockpit,
    alerts,
    compliance,
    scheduling,
    threat_intel,
    authorization,
    canonical_identity,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health & Readiness"])
api_router.include_router(metrics.router, tags=["Operational Metrics & Observability"])
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
api_router.include_router(adaptive_defense.router, tags=["Morph-State Adaptive Defense & Recovery"])
api_router.include_router(lifecycle.router, tags=["Backup, Recovery & Data Lifecycle"])
api_router.include_router(integrations.router, tags=["Enterprise Integrations"])
api_router.include_router(monitoring.router, tags=["Continuous Monitoring & Recurring Assessments"])
api_router.include_router(decisions.router, tags=["Autonomous Security Decisions & Closed Loop"])
api_router.include_router(intelligence.router, tags=["Security Intelligence & Adaptive Planning"])
api_router.include_router(operations.router, prefix="/operations", tags=["Unified Autonomous Security Operations"])
api_router.include_router(diagnostics.router, prefix="/diagnostics", tags=["Self-Diagnostics & Controlled Recovery"])
api_router.include_router(orchestration.router, prefix="/orchestration", tags=["Autonomous Security Orchestration & Closed-Loop Optimization"])
api_router.include_router(quality.router, tags=["Detection Quality & Intelligence Validation"])
api_router.include_router(drift.router, tags=["Asset Identity, Exposure Drift & Change Intelligence"])
api_router.include_router(knowledge.router, tags=["Knowledge Integrity, Epistemic Explainability & Reconciliation"])
api_router.include_router(governance.router, tags=["Governance & Separation of Duties"])
api_router.include_router(recovery.router, tags=["Disaster Recovery & Data Integrity"])
api_router.include_router(supply_chain.router, prefix="/system/supply-chain", tags=["Software Supply-Chain Security & Verifiable Provenance"])
api_router.include_router(performance.router, prefix="/system/performance", tags=["Performance Engineering & Workload Isolation"])
api_router.include_router(security_controls.router, prefix="/system/verification", tags=["Security Control Verification & Mutation Testing"])
api_router.include_router(deployment.router, prefix="/system/deployment", tags=["Secure Windows Deployment & Configuration Governance"])
api_router.include_router(evidence_lifecycle.router, prefix="/system/lifecycle", tags=["Evidence Lifecycle Governance & Data Retention"])
api_router.include_router(operations_cockpit.router, prefix="/system/operations/cockpit", tags=["Unified Security Operations Cockpit"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Reliable Security Alerting & Event Intelligence"])
api_router.include_router(compliance.router, tags=["Compliance Intelligence, Security Baselines & Drift Governance"])
api_router.include_router(scheduling.router, tags=["Intelligent Scheduling & Orchestration"])
api_router.include_router(threat_intel.router, tags=["Threat Intelligence & Vulnerability Correlation"])
api_router.include_router(authorization.router, tags=["Identity Security & Authorization Governance"])
api_router.include_router(canonical_identity.router, prefix="/projects", tags=["Asset Identity Resolution & Data Quality"])

import uuid
import time
from datetime import datetime, timezone
import pytest
from sqlalchemy import text, inspect
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.core.database import Base, engine
from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity
from app.services.knowledge_graph_service import KnowledgeGraphService


def test_performance_composite_indexes_exist(db: Session):
    """
    Verify that Phase 23 performance composite indexes are present and registered.
    """
    inspector = inspect(db.get_bind())

    # Check assessment_jobs indexes
    job_indexes = {idx["name"]: idx["column_names"] for idx in inspector.get_indexes("assessment_jobs")}
    assert "ix_assessment_jobs_project_status_created" in job_indexes
    assert job_indexes["ix_assessment_jobs_project_status_created"] == ["project_id", "status", "created_at"]

    # Check assessment_findings indexes
    finding_indexes = {idx["name"]: idx["column_names"] for idx in inspector.get_indexes("assessment_findings")}
    assert "ix_assessment_findings_project_severity" in finding_indexes
    assert finding_indexes["ix_assessment_findings_project_severity"] == ["project_id", "severity"]

    # Check audit_events indexes
    audit_indexes = {idx["name"]: idx["column_names"] for idx in inspector.get_indexes("audit_events")}
    assert "ix_audit_events_project_timestamp" in audit_indexes
    assert audit_indexes["ix_audit_events_project_timestamp"] == ["project_id", "timestamp"]

    # Check regression_alerts indexes
    alert_indexes = {idx["name"]: idx["column_names"] for idx in inspector.get_indexes("regression_alerts")}
    assert "ix_regression_alerts_project_status_severity" in alert_indexes
    assert alert_indexes["ix_regression_alerts_project_status_severity"] == ["project_id", "status", "severity"]


def test_query_plan_uses_composite_indexes(db: Session, test_project: Project, tester_user):
    """
    Verify SQLite query planner utilizes composite indexes on hot query patterns.
    """
    # Insert sample rows to allow index optimization
    for i in range(5):
        job = AssessmentJob(
            project_id=test_project.id,
            adapter_name="scanner.passive_header",
            target_input=f"host{i}.test.local",
            created_by_id=tester_user.id,
            status=AssessmentStatus.QUEUED,
        )
        db.add(job)
    db.commit()

    # Query with EXPLAIN QUERY PLAN
    explain_sql = text(
        "EXPLAIN QUERY PLAN SELECT * FROM assessment_jobs "
        "WHERE project_id = :p_id AND status = :status ORDER BY created_at"
    )
    result = db.execute(explain_sql, {"p_id": test_project.id, "status": "QUEUED"}).fetchall()
    plan_text = " ".join([str(row) for row in result])
    # Verify index is referenced in query plan
    assert "ix_assessment_jobs" in plan_text or "INDEX" in plan_text


def test_bounded_pagination_limits(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
):
    """
    Verify bounded pagination:
    Querying with limit > permitted max bounds is rejected with HTTP 422 Unprocessable Content.
    Querying with negative offset or zero limit is rejected.
    """
    # Excessive limit on assessments (le=100)
    res_excessive = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?limit=5000",
        headers=tester_headers,
    )
    assert res_excessive.status_code == 422, "Excessive pagination limit should be rejected with 422"

    # Zero limit
    res_zero = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?limit=0",
        headers=tester_headers,
    )
    assert res_zero.status_code == 422, "Limit 0 should be rejected"

    # Negative offset
    res_neg_offset = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?offset=-5",
        headers=tester_headers,
    )
    assert res_neg_offset.status_code == 422, "Negative offset should be rejected"

    # Normal bounded pagination succeeds
    res_valid = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?limit=20&offset=0",
        headers=tester_headers,
    )
    assert res_valid.status_code == 200


def test_queue_backpressure_enforcement(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user,
    tester_headers: dict,
):
    """
    Verify queue backpressure:
    Attempting to queue more than MAX_ACTIVE_JOBS_PER_PROJECT active jobs
    is rejected with HTTP 429 Too Many Requests.
    """
    # Authorize scope target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.200.1.1",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=tester_user.id,
        created_by_id=tester_user.id,
        authorized_at=datetime.now(timezone.utc),
    )
    db.add(target)
    db.commit()

    # Create 10 active jobs (capacity limit)
    for i in range(10):
        job = AssessmentJob(
            project_id=test_project.id,
            adapter_name="scanner.passive_header",
            target_input="10.200.1.1",
            created_by_id=tester_user.id,
            status=AssessmentStatus.QUEUED,
        )
        db.add(job)
    db.commit()

    # Attempt to create 11th job via API
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "10.200.1.1",
            "fixture_profile": "HARDENED_HOST_BASELINE",
            "idempotency_key": f"backpressure-{uuid.uuid4().hex[:8]}",
        },
        headers=tester_headers,
    )
    assert resp.status_code == 429, f"Expected 429 Too Many Requests, got {resp.status_code}: {resp.text}"
    assert "capacity exceeded" in resp.json()["detail"].lower()


def test_bounded_knowledge_graph_traversal(db: Session, test_project: Project):
    """
    Verify knowledge graph traversal enforces bounded depth and node limits,
    preventing circular graph traversal memory exhaustion.
    """
    from app.models.graph import GraphNodeCategory, RelationshipType

    # Create cyclical graph: Node A -> Node B -> Node C -> Node A
    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="Node A",
        db=db,
    )
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="Node B",
        db=db,
    )
    node_c = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SOFTWARE_COMPONENT,
        label="Node C",
        db=db,
    )

    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        db=db,
    )
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_b.id,
        target_node_id=node_c.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        db=db,
    )
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_c.id,
        target_node_id=node_a.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        db=db,
    )
    db.commit()

    # Traverse cyclical neighborhood with depth 5
    t0 = time.perf_counter()
    neighborhood = KnowledgeGraphService.get_bounded_neighborhood(
        project_id=test_project.id,
        root_node_id=node_a.id,
        max_depth=5,
        max_nodes=100,
        db=db,
    )
    elapsed = time.perf_counter() - t0

    # Must complete rapidly without infinite loop
    assert elapsed < 0.5, f"Graph traversal took too long: {elapsed:.3f}s"
    assert len(neighborhood["nodes"]) == 3
    assert len(neighborhood["relationships"]) == 3


def test_control_plane_health_and_readiness(client: TestClient):
    """
    Verify /health and /ready response contracts and operational latency.
    """
    t0 = time.perf_counter()
    health_res = client.get("/api/v1/health")
    health_latency_ms = (time.perf_counter() - t0) * 1000

    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"
    assert health_latency_ms < 50, f"Health check latency {health_latency_ms:.2f}ms exceeds threshold"

    t1 = time.perf_counter()
    ready_res = client.get("/api/v1/ready")
    ready_latency_ms = (time.perf_counter() - t1) * 1000

    assert ready_res.status_code == 200
    data = ready_res.json()
    assert data["status"] == "ready"
    assert data["checks"]["database"] is True
    assert data["checks"]["storage_writable"] is True
    assert ready_latency_ms < 100, f"Readiness check latency {ready_latency_ms:.2f}ms exceeds threshold"

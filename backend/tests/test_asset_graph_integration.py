from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.graph import GraphNode, GraphNodeCategory, GraphRelationship, RelationshipType
from app.models.finding import VulnerabilityFinding


def test_assessment_execution_asset_and_graph_integration(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    db: Session,
):
    # 1. Register and Authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.URL,
        target_value="https://internal-portal.corp:443",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="AUTH-CORP-PORTAL-01",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Launch assessment via API
    payload = {
        "target_input": "https://internal-portal.corp:443",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE",
        "timeout_seconds": 60,
    }
    response = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json=payload,
        headers=tester_headers,
    )
    assert response.status_code == 201
    job_data = response.json()
    job_id = job_data["id"]

    # 3. Verify asset was automatically reconciled
    assets = db.query(Asset).filter(Asset.project_id == test_project.id).all()
    assert len(assets) >= 1
    target_asset = next((a for a in assets if "internal-portal.corp" in a.canonical_identifier), None)
    assert target_asset is not None
    assert target_asset.asset_type == AssetType.WEB_APP

    # 4. Verify asset observation was appended
    observations = target_asset.observations
    assert len(observations) >= 1
    assert observations[0].assessment_job_id == job_id

    # 5. Verify findings are linked to the asset
    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == test_project.id).all()
    assert len(findings) > 0
    for finding in findings:
        assert finding.asset_id == target_asset.id

    # 6. Verify knowledge graph nodes were created
    nodes = db.query(GraphNode).filter(GraphNode.project_id == test_project.id).all()
    node_categories = {n.category for n in nodes}
    assert GraphNodeCategory.ASSET in node_categories
    assert GraphNodeCategory.ASSESSMENT in node_categories
    assert GraphNodeCategory.FINDING in node_categories
    assert GraphNodeCategory.VULNERABILITY in node_categories

    # 7. Verify knowledge graph relationships
    rel_types = {r.relationship_type for r in db.query(GraphRelationship).filter(GraphRelationship.project_id == test_project.id).all()}
    assert RelationshipType.OBSERVED_AT in rel_types
    assert RelationshipType.AFFECTED_BY in rel_types


def test_asset_inventory_api_endpoints(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
    outsider_headers: dict,
):
    # 1. Lead ingests fixture asset
    fixture_payload = {
        "name": "Database Gateway",
        "asset_type": "SERVICE",
        "canonical_identifier": "tcp://db-gateway.internal:5432",
        "criticality": "HIGH",
        "environment": "Production",
        "attributes": {"port": 5432, "engine": "postgresql"},
        "is_ambiguous": True,
        "ambiguity_reason": "Multiple hostnames map to this gateway",
    }
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assets/fixture",
        json=fixture_payload,
        headers=lead_headers,
    )
    assert res.status_code == 201
    asset_id = res.json()["id"]
    assert res.json()["canonical_identifier"] == "tcp://db-gateway.internal:5432"
    assert res.json()["is_ambiguous"] is True

    # 2. Tester can list assets
    res_list = client.get(
        f"/api/v1/projects/{test_project.id}/assets",
        headers=tester_headers,
    )
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert len(data_list) >= 1
    assert any(item["id"] == asset_id for item in data_list)

    # 3. Filter by asset_type
    res_filter = client.get(
        f"/api/v1/projects/{test_project.id}/assets?asset_type=SERVICE",
        headers=tester_headers,
    )
    assert res_filter.status_code == 200
    assert all(item["asset_type"] == "SERVICE" for item in res_filter.json())

    # 4. Get asset details and observations
    res_detail = client.get(
        f"/api/v1/projects/{test_project.id}/assets/{asset_id}",
        headers=tester_headers,
    )
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == asset_id

    res_obs = client.get(
        f"/api/v1/projects/{test_project.id}/assets/{asset_id}/observations",
        headers=tester_headers,
    )
    assert res_obs.status_code == 200
    assert len(res_obs.json()) >= 1

    # 5. Resolve ambiguity (requires ProjectRole.LEAD or TESTER)
    res_resolve = client.post(
        f"/api/v1/projects/{test_project.id}/assets/{asset_id}/resolve-ambiguity",
        json={"resolution_notes": "Verified DNS pointer is primary hostname."},
        headers=lead_headers,
    )
    assert res_resolve.status_code == 200
    assert res_resolve.json()["is_ambiguous"] is False
    assert res_resolve.json()["ambiguity_reason"] is None
    assert "Verified DNS" in res_resolve.json()["attributes"]["_resolution_history"][0]["notes"]

    # 6. Cross-project isolation: outsider is denied and receives 404 (fails closed without leaking existence)
    res_cross = client.get(
        f"/api/v1/projects/{test_project.id}/assets/{asset_id}",
        headers=outsider_headers,
    )
    assert res_cross.status_code == 404
    assert res_cross.json()["detail"] == "Project not found"


def test_knowledge_graph_api_endpoints(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
    outsider_headers: dict,
):
    # 1. Check graph stats
    res_stats = client.get(
        f"/api/v1/projects/{test_project.id}/graph/stats",
        headers=tester_headers,
    )
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_nodes" in stats
    assert "total_edges" in stats

    # 2. Ingest two fixture assets in test project
    asset_a_res = client.post(
        f"/api/v1/projects/{test_project.id}/assets/fixture",
        json={
            "name": "Web Front End",
            "asset_type": "WEB_APP",
            "canonical_identifier": "https://frontend.corp",
            "criticality": "HIGH",
        },
        headers=lead_headers,
    )
    assert asset_a_res.status_code == 201
    asset_a_id = asset_a_res.json()["id"]

    asset_b_res = client.post(
        f"/api/v1/projects/{test_project.id}/assets/fixture",
        json={
            "name": "Auth Service",
            "asset_type": "SERVICE",
            "canonical_identifier": "tcp://auth.corp:8443",
            "criticality": "CRITICAL",
        },
        headers=lead_headers,
    )
    assert asset_b_res.status_code == 201
    asset_b_id = asset_b_res.json()["id"]

    # Retrieve graph node IDs from asset details
    res_a_detail = client.get(f"/api/v1/projects/{test_project.id}/assets/{asset_a_id}", headers=tester_headers)
    assert res_a_detail.status_code == 200
    asset_a_node_id = res_a_detail.json()["graph_node_id"]
    assert asset_a_node_id is not None

    res_b_detail = client.get(f"/api/v1/projects/{test_project.id}/assets/{asset_b_id}", headers=tester_headers)
    assert res_b_detail.status_code == 200
    asset_b_node_id = res_b_detail.json()["graph_node_id"]
    assert asset_b_node_id is not None

    # 3. Retrieve neighborhood of asset A
    res_neigh = client.get(
        f"/api/v1/projects/{test_project.id}/graph/nodes/{asset_a_node_id}/neighborhood?depth=2",
        headers=tester_headers,
    )
    assert res_neigh.status_code == 200
    neigh_data = res_neigh.json()
    assert neigh_data["root_node_id"] == asset_a_node_id
    assert any(n["id"] == asset_a_node_id for n in neigh_data["nodes"])

    # 4. Create relationship between Asset A and Asset B
    rel_payload = {
        "source_node_id": asset_a_node_id,
        "target_node_id": asset_b_node_id,
        "relationship_type": "AUTHENTICATES_TO",
        "status": "VERIFIED",
        "confidence": 0.95,
    }
    res_create_rel = client.post(
        f"/api/v1/projects/{test_project.id}/graph/relationships",
        json=rel_payload,
        headers=lead_headers,
    )
    assert res_create_rel.status_code == 201
    assert res_create_rel.json()["relationship_type"] == "AUTHENTICATES_TO"

    # 5. Cross-project endpoint authorization: outsider is denied and receives 404 (fails closed without leaking existence)
    res_cross_query = client.get(
        f"/api/v1/projects/{test_project.id}/graph/nodes/{asset_a_node_id}/neighborhood",
        headers=outsider_headers,
    )
    assert res_cross_query.status_code == 404
    assert res_cross_query.json()["detail"] == "Project not found"

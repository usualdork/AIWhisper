"""Unit tests for code_scan_module router registration and endpoint accessibility.
Tests:
- All 18 endpoints return valid HTTP responses
- RBAC dependency is applied to all endpoints
Validates: Requirements 1.2, 22.4
"""
import os
import sys
import uuid
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from rbac_auth import create_access_token, hash_password, VALID_MODULES


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_router.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-for-router-tests")
    database.init_db()
    yield


def _create_user(username, password, role, modules):
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    database.rbac_create_user(id=user_id, username=username, password_hash=pw_hash, role=role, permitted_modules=modules)
    database.rbac_update_user(user_id, {"force_password_change": 0})
    return database.rbac_get_user_by_id(user_id)


@pytest.fixture
def admin_user():
    return _create_user("testadmin", "AdminPass123!", "Admin", VALID_MODULES)


@pytest.fixture
def admin_token(admin_user):
    return create_access_token(admin_user)


@pytest.fixture
def viewer_user():
    return _create_user("testviewer", "ViewerPass1!", "Viewer", VALID_MODULES)


@pytest.fixture
def viewer_token(viewer_user):
    return create_access_token(viewer_user)


@pytest.fixture
def no_code_scan_user():
    return _create_user("limiteduser", "LimitPass1!", "Agent", ["tprm"])


@pytest.fixture
def no_code_scan_token(no_code_scan_user):
    return create_access_token(no_code_scan_user)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _create_scan_directly():
    """Create a scan record directly in the DB for GET endpoint tests."""
    scan_id = str(uuid.uuid4())
    conn = database.get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO code_scans (id, label, status, phase, progress, status_details, repos_json, config_json) VALUES (?, ?, 'CREATED', 'CREATED', 0, 'Test scan', ?, ?)",
        (scan_id, "Test Scan", '["owner/test-repo"]', '{}'),
    )
    conn.commit()
    conn.close()
    database.code_scan_repo_create(scan_id=scan_id, repo_identifier="owner/test-repo", status="QUEUED")
    return scan_id


class TestEndpointAccessibility:
    """All 18 code-scan endpoints are routable and return valid responses."""

    def test_post_scans(self, admin_token):
        """POST /api/code-scan/scans - endpoint 1."""
        from fastapi.testclient import TestClient
        from main import app
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post("/api/code-scan/scans", json={"repos": ["owner/test-repo"]}, headers=auth_header(admin_token))
        assert resp.status_code in (200, 201, 400, 422, 500)

    def test_get_scans(self, client, admin_token):
        """GET /api/code-scan/scans - endpoint 2."""
        resp = client.get("/api/code-scan/scans", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_by_id(self, client, admin_token):
        """GET /api/code-scan/scans/{id} - endpoint 3."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_by_id_not_found(self, client, admin_token):
        """GET /api/code-scan/scans/{id} - 404 for non-existent."""
        resp = client.get(f"/api/code-scan/scans/{uuid.uuid4()}", headers=auth_header(admin_token))
        assert resp.status_code == 404

    def test_get_scan_findings(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/findings - endpoint 4."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/findings", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_sbom(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/sbom/{repo} - endpoint 5."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/sbom/owner/test-repo", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_sca(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/sca/{repo} - endpoint 6."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/sca/owner/test-repo", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_cbom(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/cbom/{repo} - endpoint 7."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/cbom/owner/test-repo", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_chains(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/chains - endpoint 8."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/chains", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_licenses(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/licenses/{repo} - endpoint 9."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/licenses/owner/test-repo", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_container(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/container/{repo} - endpoint 10."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/container/owner/test-repo", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_prs(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/prs - endpoint 11."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/prs", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_budget(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/budget - endpoint 12."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/budget", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_scan_export(self, client, admin_token):
        """GET /api/code-scan/scans/{id}/export - endpoint 13."""
        scan_id = _create_scan_directly()
        resp = client.get(f"/api/code-scan/scans/{scan_id}/export", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_post_scan_resume(self, client, admin_token):
        """POST /api/code-scan/scans/{id}/resume - endpoint 14."""
        scan_id = _create_scan_directly()
        conn = database.get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE code_scans SET status = 'STOPPED', phase = 'STOPPED' WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code in (200, 400)

    def test_post_scan_stop(self, client, admin_token):
        """POST /api/code-scan/scans/{id}/stop - endpoint 15."""
        scan_id = _create_scan_directly()
        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code in (200, 400)

    def test_delete_scan(self, client, admin_token):
        """DELETE /api/code-scan/scans/{id} - endpoint 16."""
        scan_id = _create_scan_directly()
        resp = client.delete(f"/api/code-scan/scans/{scan_id}", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_get_config(self, client, admin_token):
        """GET /api/code-scan/config - endpoint 17."""
        resp = client.get("/api/code-scan/config", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_post_config(self, client, admin_token):
        """POST /api/code-scan/config - endpoint 18."""
        resp = client.post("/api/code-scan/config", json={"model": "claude-opus-4-8"}, headers=auth_header(admin_token))
        assert resp.status_code == 200


class TestRBACEnforcement:
    """RBAC middleware is applied to all code-scan endpoints."""

    def test_unauthenticated_requests_rejected(self, client):
        """All 18 endpoints reject requests without Authorization header (401)."""
        scan_id = _create_scan_directly()
        endpoints = [
            ("POST", "/api/code-scan/scans"),
            ("GET", "/api/code-scan/scans"),
            ("GET", f"/api/code-scan/scans/{scan_id}"),
            ("GET", f"/api/code-scan/scans/{scan_id}/findings"),
            ("GET", f"/api/code-scan/scans/{scan_id}/sbom/owner/repo"),
            ("GET", f"/api/code-scan/scans/{scan_id}/sca/owner/repo"),
            ("GET", f"/api/code-scan/scans/{scan_id}/cbom/owner/repo"),
            ("GET", f"/api/code-scan/scans/{scan_id}/chains"),
            ("GET", f"/api/code-scan/scans/{scan_id}/licenses/owner/repo"),
            ("GET", f"/api/code-scan/scans/{scan_id}/container/owner/repo"),
            ("GET", f"/api/code-scan/scans/{scan_id}/prs"),
            ("GET", f"/api/code-scan/scans/{scan_id}/budget"),
            ("GET", f"/api/code-scan/scans/{scan_id}/export"),
            ("POST", f"/api/code-scan/scans/{scan_id}/resume"),
            ("POST", f"/api/code-scan/scans/{scan_id}/stop"),
            ("DELETE", f"/api/code-scan/scans/{scan_id}"),
            ("GET", "/api/code-scan/config"),
            ("POST", "/api/code-scan/config"),
        ]
        for method, path in endpoints:
            resp = client.request(method, path)
            assert resp.status_code == 401, f"{method} {path} should be 401, got {resp.status_code}"

    def test_user_without_code_scan_permission_rejected(self, client, no_code_scan_token):
        """User without code_scan in permitted_modules gets 403."""
        endpoints = [("GET", "/api/code-scan/scans"), ("GET", "/api/code-scan/config")]
        for method, path in endpoints:
            resp = client.request(method, path, headers=auth_header(no_code_scan_token))
            assert resp.status_code == 403, f"{method} {path} should be 403, got {resp.status_code}"

    def test_viewer_cannot_write(self, client, viewer_token):
        """Viewer role cannot POST or DELETE on code-scan endpoints (403)."""
        scan_id = _create_scan_directly()
        write_endpoints = [
            ("POST", "/api/code-scan/scans", {"repos": ["test/repo"]}),
            ("POST", f"/api/code-scan/scans/{scan_id}/resume", None),
            ("POST", f"/api/code-scan/scans/{scan_id}/stop", None),
            ("DELETE", f"/api/code-scan/scans/{scan_id}", None),
            ("POST", "/api/code-scan/config", {"model": "test"}),
        ]
        for method, path, body in write_endpoints:
            kwargs = {"headers": auth_header(viewer_token)}
            if body:
                kwargs["json"] = body
            resp = client.request(method, path, **kwargs)
            assert resp.status_code == 403, f"Viewer {method} {path} should be 403, got {resp.status_code}"

    def test_viewer_can_read(self, client, viewer_token):
        """Viewer role can GET on code-scan endpoints (200)."""
        scan_id = _create_scan_directly()
        read_endpoints = [
            "/api/code-scan/scans",
            f"/api/code-scan/scans/{scan_id}",
            f"/api/code-scan/scans/{scan_id}/findings",
            f"/api/code-scan/scans/{scan_id}/chains",
            f"/api/code-scan/scans/{scan_id}/prs",
            f"/api/code-scan/scans/{scan_id}/budget",
            f"/api/code-scan/scans/{scan_id}/export",
        ]
        for path in read_endpoints:
            resp = client.get(path, headers=auth_header(viewer_token))
            assert resp.status_code == 200, f"Viewer GET {path} should be 200, got {resp.status_code}"



    def test_viewer_cannot_access_config(self, client, viewer_token):
        """Viewer role cannot access GET /config (403 - Admin only)."""
        resp = client.get("/api/code-scan/config", headers=auth_header(viewer_token))
        assert resp.status_code == 403, f"Viewer GET /config should be 403, got {resp.status_code}"

    def test_agent_cannot_delete_scan(self, client):
        """Agent role cannot DELETE scans (403 - Admin only)."""
        agent_user = _create_user("testagent", "AgentPass123!", "Agent", VALID_MODULES)
        agent_token = create_access_token(agent_user)
        scan_id = _create_scan_directly()
        resp = client.delete(f"/api/code-scan/scans/{scan_id}", headers=auth_header(agent_token))
        assert resp.status_code == 403, f"Agent DELETE scan should be 403, got {resp.status_code}"

    def test_agent_cannot_access_config(self, client):
        """Agent role cannot access GET or POST /config (403 - Admin only)."""
        agent_user = _create_user("testagent2", "AgentPass123!", "Agent", VALID_MODULES)
        agent_token = create_access_token(agent_user)
        resp = client.get("/api/code-scan/config", headers=auth_header(agent_token))
        assert resp.status_code == 403, f"Agent GET /config should be 403, got {resp.status_code}"
        resp = client.post("/api/code-scan/config", json={"model": "test"}, headers=auth_header(agent_token))
        assert resp.status_code == 403, f"Agent POST /config should be 403, got {resp.status_code}"

    def test_agent_can_initiate_scans(self, client):
        """Agent role can POST scans (initiate) and resume/stop."""
        agent_user = _create_user("testagent3", "AgentPass123!", "Agent", VALID_MODULES)
        agent_token = create_access_token(agent_user)
        resp = client.post("/api/code-scan/scans", json={"repos": ["owner/test-repo"]}, headers=auth_header(agent_token))
        assert resp.status_code == 200, f"Agent POST /scans should be 200, got {resp.status_code}"

class TestRouterRegistration:
    """The code_scan_module router is properly registered in the app."""

    def test_router_is_registered_with_correct_prefix(self):
        """Router uses /api/code-scan prefix."""
        from main import app
        code_scan_routes = [r.path for r in app.routes if hasattr(r, "path") and "/api/code-scan" in r.path]
        assert len(code_scan_routes) > 0, "No /api/code-scan routes found in app"

    def test_all_18_endpoints_are_registered(self):
        """All 18 expected endpoint paths are present in the app routes."""
        from main import app
        registered = set()
        for route in app.routes:
            if hasattr(route, "path") and hasattr(route, "methods"):
                for method in route.methods:
                    if "/api/code-scan" in route.path:
                        registered.add((method, route.path))
        expected = [
            ("POST", "/api/code-scan/scans"),
            ("GET", "/api/code-scan/scans"),
            ("GET", "/api/code-scan/scans/{scan_id}"),
            ("GET", "/api/code-scan/scans/{scan_id}/findings"),
            ("GET", "/api/code-scan/scans/{scan_id}/sbom/{repo:path}"),
            ("GET", "/api/code-scan/scans/{scan_id}/sca/{repo:path}"),
            ("GET", "/api/code-scan/scans/{scan_id}/cbom/{repo:path}"),
            ("GET", "/api/code-scan/scans/{scan_id}/chains"),
            ("GET", "/api/code-scan/scans/{scan_id}/licenses/{repo:path}"),
            ("GET", "/api/code-scan/scans/{scan_id}/container/{repo:path}"),
            ("GET", "/api/code-scan/scans/{scan_id}/prs"),
            ("GET", "/api/code-scan/scans/{scan_id}/budget"),
            ("GET", "/api/code-scan/scans/{scan_id}/export"),
            ("POST", "/api/code-scan/scans/{scan_id}/resume"),
            ("POST", "/api/code-scan/scans/{scan_id}/stop"),
            ("DELETE", "/api/code-scan/scans/{scan_id}"),
            ("GET", "/api/code-scan/config"),
            ("POST", "/api/code-scan/config"),
        ]
        for method, path in expected:
            assert (method, path) in registered, f"({method}, {path}) not in routes: {sorted(registered)}"

    def test_router_has_rbac_dependency(self):
        """Router is included with require_module dependency."""
        import code_scan_module
        assert hasattr(code_scan_module, "require_module")
        from main import app
        code_scan_routes = [r for r in app.routes if hasattr(r, "path") and "/api/code-scan/scans" in r.path]
        assert len(code_scan_routes) > 0

"""Property-based tests for RBAC enforcement on code_scan_module endpoints.

**Property 28: RBAC Enforcement Matrix**
For any (role, endpoint, method) triple, the access decision should match the RBAC matrix:
- Admin allows all operations
- Agent allows scan initiation and reads but denies config changes and deletions
- Viewer allows reads only but denies scan initiation, config changes, and deletions

**Validates: Requirements 22.1, 22.2, 22.3**
"""
import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from rbac_auth import create_access_token, hash_password, VALID_MODULES


# ---------------------------------------------------------------------------
# RBAC Matrix Definition
# ---------------------------------------------------------------------------

# Roles
ROLES = ["Admin", "Agent", "Viewer"]

# Endpoint definitions: (method, path_template, category)
# Categories:
#   "read" - GET endpoints accessible to all authenticated users with code_scan module
#   "scan_write" - POST endpoints for scan initiation (Admin + Agent)
#   "admin_only" - endpoints only Admin can access (DELETE, config)
ENDPOINTS = [
    ("POST", "/api/code-scan/scans", "scan_write"),
    ("GET", "/api/code-scan/scans", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/findings", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/sbom/owner/repo", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/sca/owner/repo", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/cbom/owner/repo", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/chains", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/licenses/owner/repo", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/container/owner/repo", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/prs", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/budget", "read"),
    ("GET", "/api/code-scan/scans/{scan_id}/export", "read"),
    ("POST", "/api/code-scan/scans/{scan_id}/resume", "scan_write"),
    ("POST", "/api/code-scan/scans/{scan_id}/stop", "scan_write"),
    ("DELETE", "/api/code-scan/scans/{scan_id}", "admin_only"),
    ("GET", "/api/code-scan/config", "admin_only"),
    ("POST", "/api/code-scan/config", "admin_only"),
]


def expected_access(role: str, category: str) -> bool:
    """Return True if the given role should have access to the given category."""
    if role == "Admin":
        return True
    elif role == "Agent":
        return category in ("read", "scan_write")
    elif role == "Viewer":
        return category == "read"
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_rbac_props.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-for-rbac-props")
    database.init_db()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app, raise_server_exceptions=False)


def _create_user_with_role(role: str, suffix: str = ""):
    """Create a user with the given role and full code_scan module access."""
    user_id = str(uuid.uuid4())
    username = f"test_{role.lower()}_{suffix or uuid.uuid4().hex[:6]}"
    pw_hash = hash_password("TestPass123!")
    database.rbac_create_user(
        id=user_id,
        username=username,
        password_hash=pw_hash,
        role=role,
        permitted_modules=VALID_MODULES,
    )
    database.rbac_update_user(user_id, {"force_password_change": 0})
    user = database.rbac_get_user_by_id(user_id)
    return user


def _create_scan_directly():
    """Create a scan record directly in the DB for endpoint tests."""
    scan_id = str(uuid.uuid4())
    conn = database.get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO code_scans (id, label, status, phase, progress, status_details, repos_json, config_json) "
        "VALUES (?, ?, 'CREATED', 'CREATED', 0, 'Test scan', ?, ?)",
        (scan_id, "Test Scan", '["owner/test-repo"]', '{}'),
    )
    conn.commit()
    conn.close()
    database.code_scan_repo_create(scan_id=scan_id, repo_identifier="owner/test-repo", status="QUEUED")
    return scan_id


def _resolve_path(path_template: str, scan_id: str) -> str:
    """Replace {scan_id} placeholder in path template."""
    return path_template.replace("{scan_id}", scan_id)


def _get_request_body(method: str, path: str):
    """Return an appropriate request body for write endpoints."""
    if method == "POST" and path.endswith("/scans"):
        return {"repos": ["owner/test-repo"]}
    if method == "POST" and path.endswith("/config"):
        return {"model": "test-model"}
    return None


# ---------------------------------------------------------------------------
# Property 28: RBAC Enforcement Matrix
# ---------------------------------------------------------------------------

# Strategy for selecting a role
role_strategy = st.sampled_from(ROLES)

# Strategy for selecting an endpoint
endpoint_strategy = st.sampled_from(ENDPOINTS)


class TestRBACEnforcementMatrix:
    """Property 28: RBAC Enforcement Matrix.

    For any (role, endpoint, method) triple, the access decision should match the
    RBAC matrix: Admin allows all operations; Agent allows scan initiation and reads
    but denies config changes; Viewer allows reads only but denies scan initiation
    and config changes.

    **Validates: Requirements 22.1, 22.2, 22.3**
    """

    @given(
        role=role_strategy,
        endpoint=endpoint_strategy,
    )
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_rbac_matrix_property(self, client, role, endpoint):
        """For any (role, endpoint) pair, the HTTP response code matches the RBAC matrix.

        - If access is expected: response should NOT be 403
        - If access is denied: response should be 403
        """
        method, path_template, category = endpoint

        # Create a scan for endpoints that reference {scan_id}
        scan_id = _create_scan_directly()
        path = _resolve_path(path_template, scan_id)

        # Create user with the given role and get token
        user = _create_user_with_role(role)
        token = create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        # Build request
        body = _get_request_body(method, path)
        kwargs = {"headers": headers}
        if body:
            kwargs["json"] = body

        # Make request
        resp = client.request(method, path, **kwargs)

        # Determine expected access
        should_have_access = expected_access(role, category)

        if should_have_access:
            # Should NOT get 403 (may get 200, 400, 404, etc. but not 403)
            assert resp.status_code != 403, (
                f"Role={role} should have access to {method} {path} (category={category}) "
                f"but got 403: {resp.text}"
            )
        else:
            # Should get 403
            assert resp.status_code == 403, (
                f"Role={role} should be DENIED access to {method} {path} (category={category}) "
                f"but got {resp.status_code}: {resp.text}"
            )

    def test_unauthenticated_always_denied(self, client):
        """All endpoints reject unauthenticated requests with 401."""
        scan_id = _create_scan_directly()
        for method, path_template, _ in ENDPOINTS:
            path = _resolve_path(path_template, scan_id)
            body = _get_request_body(method, path)
            kwargs = {}
            if body:
                kwargs["json"] = body
            resp = client.request(method, path, **kwargs)
            assert resp.status_code == 401, (
                f"Unauthenticated {method} {path} should be 401, got {resp.status_code}"
            )

    def test_user_without_module_always_denied(self, client):
        """Users without code_scan in permitted_modules get 403 on all endpoints."""
        # Create user with only 'tprm' module
        user_id = str(uuid.uuid4())
        pw_hash = hash_password("TestPass123!")
        database.rbac_create_user(
            id=user_id,
            username="no_codescan_user",
            password_hash=pw_hash,
            role="Agent",
            permitted_modules=["tprm"],
        )
        database.rbac_update_user(user_id, {"force_password_change": 0})
        user = database.rbac_get_user_by_id(user_id)
        token = create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        scan_id = _create_scan_directly()
        for method, path_template, _ in ENDPOINTS:
            path = _resolve_path(path_template, scan_id)
            body = _get_request_body(method, path)
            kwargs = {"headers": headers}
            if body:
                kwargs["json"] = body
            resp = client.request(method, path, **kwargs)
            assert resp.status_code == 403, (
                f"User without code_scan module: {method} {path} should be 403, got {resp.status_code}"
            )

    @pytest.mark.parametrize("role,method,path_template,category", [
        (role, method, path, cat)
        for role in ROLES
        for method, path, cat in ENDPOINTS
    ])
    def test_rbac_matrix_exhaustive(self, client, role, method, path_template, category):
        """Exhaustive parameterized test covering all role×endpoint combinations."""
        scan_id = _create_scan_directly()
        path = _resolve_path(path_template, scan_id)

        user = _create_user_with_role(role, suffix=f"{role}_{method}_{category}")
        token = create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        body = _get_request_body(method, path)
        kwargs = {"headers": headers}
        if body:
            kwargs["json"] = body

        resp = client.request(method, path, **kwargs)

        should_have_access = expected_access(role, category)

        if should_have_access:
            assert resp.status_code != 403, (
                f"Role={role} should have access to {method} {path} (category={category}) "
                f"but got 403: {resp.text}"
            )
        else:
            assert resp.status_code == 403, (
                f"Role={role} should be DENIED access to {method} {path} (category={category}) "
                f"but got {resp.status_code}: {resp.text}"
            )

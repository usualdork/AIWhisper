"""Unit tests for POST /scans/{id}/stop, POST /scans/{id}/resume, and reset_inflight_code_scans.

Tests cover:
- Stop endpoint: sets cancellation flag, marks scan STOPPED, marks SCANNING repos as INTERRUPTED
- Resume endpoint: verifies state check, clears cancellation flag, launches background task
- reset_inflight_code_scans: marks active scans and repos as INTERRUPTED on restart
"""

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from rbac_auth import create_access_token, hash_password, VALID_MODULES

from main import app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Use a fresh SQLite DB for each test."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-stop-resume")
    database.init_db()
    # Clear cancellation flags between tests
    import code_scan_module
    code_scan_module._scan_cancellation_flags.clear()
    yield db_path


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


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _create_scan_with_repos(repos=None, scan_phase="SCANNING"):
    """Helper to create a scan record with per-repo records."""
    if repos is None:
        repos = ["owner/repo1", "owner/repo2", "owner/repo3"]

    scan_id = database.create_code_scan(
        label="Test Scan",
        repos=repos,
        config={},
    )
    database.code_scan_update_phase(scan_id, scan_phase)

    # Create per-repo records
    for repo in repos:
        database.code_scan_repo_create(scan_id=scan_id, repo_identifier=repo, status="QUEUED")

    database.code_scan_update_repo_counts(scan_id, total_repos=len(repos))
    return scan_id


class TestStopScan:
    """Tests for POST /scans/{id}/stop endpoint."""

    def test_stop_scan_marks_stopped(self, fresh_db, admin_token):
        """Stop a running scan and verify it's marked as STOPPED."""
        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "STOPPED"
        assert data["scan_id"] == scan_id

        # Verify DB state
        scan = database.get_code_scan(scan_id)
        assert scan["scan_phase"] == "STOPPED"

    def test_stop_scan_sets_cancellation_flag(self, fresh_db, admin_token):
        """Stop sets the cancellation flag in the module."""
        import code_scan_module

        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 200

        assert code_scan_module._scan_cancellation_flags.get(scan_id) is True

    def test_stop_scan_marks_scanning_repos_as_interrupted(self, fresh_db, admin_token):
        """Stop marks any SCANNING repos as INTERRUPTED."""
        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        # Mark one repo as SCANNING
        repos = database.code_scan_repo_get_by_scan_id(scan_id)
        database.code_scan_repo_update_status(repos[0]["id"], "SCANNING")
        database.code_scan_repo_update_status(repos[1]["id"], "COMPLETED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 200

        # Verify repo statuses
        updated_repos = database.code_scan_repo_get_by_scan_id(scan_id)
        repo_statuses = {r["repo_identifier"]: r["status"] for r in updated_repos}
        assert repo_statuses["owner/repo1"] == "INTERRUPTED"
        assert repo_statuses["owner/repo2"] == "COMPLETED"
        assert repo_statuses["owner/repo3"] == "QUEUED"

    def test_stop_scan_preserves_findings(self, fresh_db, admin_token):
        """Stop preserves all previously persisted findings."""
        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        # Insert some findings
        findings = [
            {
                "id": str(uuid.uuid4()),
                "vuln_class": "SQL_INJECTION",
                "repo": "owner/repo1",
                "file_path": "app.py",
                "line_start": 10,
                "line_end": 10,
                "severity": "HIGH",
                "confidence": 90,
                "title": "SQL Injection",
                "description": "Test finding",
                "finding_type": "sast",
            }
        ]
        database.insert_code_scan_findings(scan_id, findings)

        # Stop the scan
        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 200

        # Verify findings are still accessible
        persisted = database.get_code_scan_findings(scan_id)
        assert len(persisted) == 1
        assert persisted[0]["title"] == "SQL Injection"

    def test_stop_scan_not_found(self, fresh_db, admin_token):
        """Stop returns 404 for non-existent scan."""
        resp = client.post(f"/api/code-scan/scans/{uuid.uuid4()}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 404

    def test_stop_scan_already_in_terminal_state(self, fresh_db, admin_token):
        """Stop returns 400 if scan is already in a terminal state."""
        scan_id = _create_scan_with_repos(scan_phase="COMPLETED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/stop", headers=auth_header(admin_token))
        assert resp.status_code == 400
        assert "terminal state" in resp.json()["detail"]


class TestResumeScan:
    """Tests for POST /scans/{id}/resume endpoint."""

    def test_resume_stopped_scan(self, fresh_db, admin_token):
        """Resume a STOPPED scan transitions to RESUMING."""
        scan_id = _create_scan_with_repos(scan_phase="STOPPED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "RESUMING"
        assert data["scan_id"] == scan_id

    def test_resume_interrupted_scan(self, fresh_db, admin_token):
        """Resume an INTERRUPTED scan transitions to RESUMING."""
        scan_id = _create_scan_with_repos(scan_phase="INTERRUPTED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "RESUMING"

    def test_resume_failed_scan(self, fresh_db, admin_token):
        """Resume a FAILED scan transitions to RESUMING."""
        scan_id = _create_scan_with_repos(scan_phase="FAILED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 200

    def test_resume_clears_cancellation_flag(self, fresh_db, admin_token):
        """Resume clears the cancellation flag so the scan can proceed."""
        import code_scan_module

        scan_id = _create_scan_with_repos(scan_phase="STOPPED")
        code_scan_module._scan_cancellation_flags[scan_id] = True

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 200

        # Flag should be cleared
        assert scan_id not in code_scan_module._scan_cancellation_flags

    def test_resume_rejects_active_scan(self, fresh_db, admin_token):
        """Resume returns 400 if scan is currently active (not in resumable state)."""
        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 400
        assert "Cannot resume scan in state" in resp.json()["detail"]

    def test_resume_rejects_completed_scan(self, fresh_db, admin_token):
        """Resume returns 400 if scan is already completed."""
        scan_id = _create_scan_with_repos(scan_phase="COMPLETED")

        resp = client.post(f"/api/code-scan/scans/{scan_id}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 400

    def test_resume_not_found(self, fresh_db, admin_token):
        """Resume returns 404 for non-existent scan."""
        resp = client.post(f"/api/code-scan/scans/{uuid.uuid4()}/resume", headers=auth_header(admin_token))
        assert resp.status_code == 404


class TestResetInflightCodeScans:
    """Tests for reset_inflight_code_scans() called on startup."""

    def test_marks_active_scans_as_interrupted(self, fresh_db):
        """Active-phase scans are marked INTERRUPTED on reset."""
        # Create scans in various active phases
        scan1 = _create_scan_with_repos(scan_phase="SCANNING")
        scan2 = _create_scan_with_repos(scan_phase="ENRICHING")
        scan3 = _create_scan_with_repos(scan_phase="CHAINING")

        # Also create a completed scan that shouldn't be touched
        scan_done = _create_scan_with_repos(scan_phase="COMPLETED")

        database.reset_inflight_code_scans()

        # Active scans should be INTERRUPTED
        assert database.get_code_scan(scan1)["scan_phase"] == "INTERRUPTED"
        assert database.get_code_scan(scan2)["scan_phase"] == "INTERRUPTED"
        assert database.get_code_scan(scan3)["scan_phase"] == "INTERRUPTED"

        # Completed scan should remain COMPLETED
        assert database.get_code_scan(scan_done)["scan_phase"] == "COMPLETED"

    def test_marks_scanning_repos_as_interrupted(self, fresh_db):
        """Repos with status SCANNING are marked INTERRUPTED on reset."""
        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        # Set some repos to SCANNING
        repos = database.code_scan_repo_get_by_scan_id(scan_id)
        database.code_scan_repo_update_status(repos[0]["id"], "SCANNING")
        database.code_scan_repo_update_status(repos[1]["id"], "COMPLETED")
        database.code_scan_repo_update_status(repos[2]["id"], "SCANNING")

        database.reset_inflight_code_scans()

        # Verify repo statuses
        updated_repos = database.code_scan_repo_get_by_scan_id(scan_id)
        repo_statuses = {r["repo_identifier"]: r["status"] for r in updated_repos}
        assert repo_statuses["owner/repo1"] == "INTERRUPTED"
        assert repo_statuses["owner/repo2"] == "COMPLETED"
        assert repo_statuses["owner/repo3"] == "INTERRUPTED"

    def test_does_not_affect_stopped_or_failed_scans(self, fresh_db):
        """STOPPED and FAILED scans are not touched by reset."""
        scan_stopped = _create_scan_with_repos(scan_phase="STOPPED")
        scan_failed = _create_scan_with_repos(scan_phase="FAILED")

        database.reset_inflight_code_scans()

        assert database.get_code_scan(scan_stopped)["scan_phase"] == "STOPPED"
        assert database.get_code_scan(scan_failed)["scan_phase"] == "FAILED"

    def test_handles_all_active_phases(self, fresh_db):
        """All active phases are properly reset."""
        phases = ["INGESTING", "SCANNING", "ENRICHING", "CHAINING", "PATCHING", "REPORTING"]
        scan_ids = []
        for phase in phases:
            sid = _create_scan_with_repos(scan_phase=phase)
            scan_ids.append(sid)

        database.reset_inflight_code_scans()

        for sid in scan_ids:
            assert database.get_code_scan(sid)["scan_phase"] == "INTERRUPTED"


class TestCancellationFlagInBackground:
    """Tests for cancellation flag behavior in background task."""

    def test_cancellation_flag_prevents_repo_processing(self, fresh_db):
        """When cancellation flag is set, repos should not be processed."""
        import code_scan_module

        scan_id = _create_scan_with_repos(scan_phase="SCANNING")

        # Set the cancellation flag before running background
        code_scan_module._scan_cancellation_flags[scan_id] = True

        # Run the background task
        config = {"concurrency": 5, "diff_aware": False}
        asyncio.run(code_scan_module.run_scan_background(scan_id, config))

        # All repos should still be in their initial state (QUEUED), not COMPLETED
        repos = database.code_scan_repo_get_by_scan_id(scan_id)
        for repo in repos:
            assert repo["status"] == "QUEUED"

    def test_resume_skips_completed_repos(self, fresh_db):
        """run_scan_resume only processes non-terminal repos."""
        import code_scan_module

        scan_id = _create_scan_with_repos(
            repos=["owner/repo1", "owner/repo2", "owner/repo3"],
            scan_phase="STOPPED",
        )

        # Mark one repo as already COMPLETED
        repos = database.code_scan_repo_get_by_scan_id(scan_id)
        database.code_scan_repo_update_status(repos[0]["id"], "COMPLETED")
        # Mark another as INTERRUPTED (should be re-processed)
        database.code_scan_repo_update_status(repos[1]["id"], "INTERRUPTED")

        # Store config in scan record
        conn = database.get_db_connection()
        c = conn.cursor()
        c.execute(
            "UPDATE code_scans SET config_json = ? WHERE id = ?",
            ('{"concurrency": 5, "diff_aware": false}', scan_id),
        )
        conn.commit()
        conn.close()

        # Run the resume task
        config = {"concurrency": 5, "diff_aware": False}
        asyncio.run(code_scan_module.run_scan_resume(scan_id, config))

        # repo1 should still be COMPLETED (not re-processed)
        updated_repos = database.code_scan_repo_get_by_scan_id(scan_id)
        repo_statuses = {r["repo_identifier"]: r["status"] for r in updated_repos}
        assert repo_statuses["owner/repo1"] == "COMPLETED"
        # repo2 and repo3 should now be COMPLETED (re-processed successfully)
        assert repo_statuses["owner/repo2"] == "COMPLETED"
        assert repo_statuses["owner/repo3"] == "COMPLETED"

        # Scan should be COMPLETED
        scan = database.get_code_scan(scan_id)
        assert scan["scan_phase"] == "COMPLETED"

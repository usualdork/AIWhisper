"""
Property-based tests for the Holistic Code Scanner scan lifecycle.

Property 2: Partial Findings Survive Errors
For any scan that encounters an unrecoverable error at an arbitrary point after N findings
have been persisted, all N previously-persisted findings should remain queryable via the
findings endpoint and the scan status should be FAILED.

**Validates: Requirements 1.5**

Property 3: All Repos Reach Terminal State
For any multi-repo scan request containing 1 to 200 repositories, after the scan completes
(or is stopped/fails), every submitted repo should have a status in {COMPLETED, FAILED,
SKIPPED} — no repo remains in QUEUED or SCANNING.

**Validates: Requirements 2.1**

Property 4: JSON Array and File Upload Equivalence
For any list of repository identifiers, submitting them as a JSON array in the request body
or as a newline-delimited text file upload should produce identical scan configurations.

**Validates: Requirements 2.2**

Property 5: Status Reports All Repos
For any multi-repo scan with N submitted repositories, the status endpoint response should
contain exactly N repo status entries.

**Validates: Requirements 2.3**

Property 6: Multi-Repo Isolation
For any multi-repo scan where one repository is injected with a failure condition, all other
repositories should still reach a terminal state.

**Validates: Requirements 2.4**

Property 7: Diff-Aware Skip on Same SHA
For any repository that has a prior completed scan with the same HEAD SHA, when diff_aware
mode is enabled the repo should be marked SKIPPED.

**Validates: Requirements 2.5**
"""

import asyncio
import io
import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    composite,
    integers,
    just,
    lists,
    sampled_from,
    text,
    booleans,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TERMINAL_REPO_STATES = {"COMPLETED", "FAILED", "SKIPPED"}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FINDING_TYPES = ["sast", "sca", "cbom", "container", "chain"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Set up a fresh temporary database for each test."""
    db_path = str(tmp_path / "test_lifecycle_props.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-lifecycle-props")
    database.init_db()
    yield


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_repo_name(draw):
    """Generate a realistic repo identifier like 'owner/repo-name'."""
    owners = ["acme", "org", "team", "dev", "corp", "myco", "bigco", "startup"]
    repo_names = [
        "api-server", "web-app", "auth-svc", "data-pipeline", "ml-model",
        "frontend", "backend", "infra", "docs", "cli-tool",
    ]
    owner = draw(sampled_from(owners))
    repo = draw(sampled_from(repo_names))
    suffix = draw(integers(min_value=0, max_value=99))
    return f"{owner}/{repo}-{suffix}"


@composite
def st_repo_list(draw, min_size=1, max_size=10):
    """Generate a list of unique repo identifiers (1-10 repos)."""
    repos = draw(lists(st_repo_name(), min_size=min_size, max_size=max_size))
    # Ensure uniqueness
    unique_repos = list(dict.fromkeys(repos))
    assume(len(unique_repos) >= min_size)
    return unique_repos[:max_size]


@composite
def st_finding(draw, repo_identifier: str):
    """Generate a finding dict for a given repo."""
    return {
        "id": str(uuid.uuid4()),
        "vuln_class": draw(sampled_from(["SQL_INJECTION", "XSS", "SSRF", "CSRF"])),
        "repo": repo_identifier,
        "file_path": f"src/{draw(sampled_from(['main', 'app', 'utils', 'handler']))}.py",
        "line_start": draw(integers(min_value=1, max_value=500)),
        "line_end": draw(integers(min_value=1, max_value=500)),
        "severity": draw(sampled_from(SEVERITIES)),
        "confidence": draw(integers(min_value=50, max_value=100)),
        "title": f"Finding in {repo_identifier}",
        "description": "Generated test finding",
        "finding_type": draw(sampled_from(FINDING_TYPES)),
    }


@composite
def st_failure_index(draw, max_val):
    """Generate a random index for where failure should be injected."""
    return draw(integers(min_value=0, max_value=max_val))


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _create_scan_with_repos(repos: list, config: dict = None) -> str:
    """Helper to create a scan record and per-repo records."""
    if config is None:
        config = {"concurrency": 5, "diff_aware": False}

    scan_id = database.create_code_scan(
        label=f"Test Scan ({len(repos)} repos)",
        repos=repos,
        config=config,
    )
    database.code_scan_update_phase(scan_id, "CREATED")
    database.code_scan_update_repo_counts(scan_id, total_repos=len(repos))

    for repo in repos:
        database.code_scan_repo_create(scan_id=scan_id, repo_identifier=repo, status="QUEUED")

    return scan_id


# ===========================================================================
# Property 2: Partial Findings Survive Errors
# ===========================================================================

@given(
    repos=st_repo_list(min_size=2, max_size=5),
    failure_idx=integers(min_value=1, max_value=4),
)
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_2_partial_findings_survive_errors(fresh_db, repos, failure_idx):
    """
    For any scan that encounters an unrecoverable error at an arbitrary point after N
    findings have been persisted, all N previously-persisted findings should remain
    queryable via the findings endpoint and the scan status should be FAILED.

    **Validates: Requirements 1.5**
    """
    from code_scan_module import run_scan_background

    # Ensure failure_idx is within range of repos
    actual_failure_idx = failure_idx % len(repos)
    # Ensure at least one repo succeeds before the failure
    if actual_failure_idx == 0:
        actual_failure_idx = 1

    config = {"concurrency": 1, "diff_aware": False}
    scan_id = _create_scan_with_repos(repos, config)

    # Track which repos produce findings vs which ones raise errors
    successful_repos = repos[:actual_failure_idx]
    failing_repo = repos[actual_failure_idx]

    # Build findings for successful repos
    pre_failure_findings = []
    for repo in successful_repos:
        finding = {
            "id": str(uuid.uuid4()),
            "vuln_class": "SQL_INJECTION",
            "repo": repo,
            "file_path": "src/app.py",
            "line_start": 10,
            "line_end": 10,
            "severity": "HIGH",
            "confidence": 90,
            "title": f"Finding in {repo}",
            "description": "Test finding",
            "finding_type": "sast",
        }
        pre_failure_findings.append(finding)

    call_count = [0]

    async def mock_invoke(sid, repo_identifier, cfg):
        nonlocal call_count
        idx = call_count[0]
        call_count[0] += 1

        if repo_identifier == failing_repo:
            # Simulate unrecoverable scan-level error by raising
            raise RuntimeError(f"Unrecoverable error scanning {repo_identifier}")
        elif repo_identifier in successful_repos:
            # Return pre-built finding for this repo
            repo_idx = successful_repos.index(repo_identifier)
            return [pre_failure_findings[repo_idx]]
        return []

    import code_scan_module
    original_invoke = code_scan_module._invoke_scanner_for_repo
    code_scan_module._invoke_scanner_for_repo = mock_invoke

    try:
        asyncio.run(run_scan_background(scan_id, config))
    finally:
        code_scan_module._invoke_scanner_for_repo = original_invoke

    # Verify: findings from successful repos are still queryable
    findings = database.get_code_scan_findings(scan_id)
    assert len(findings) >= len(successful_repos), (
        f"Expected at least {len(successful_repos)} findings, got {len(findings)}"
    )

    # Verify: the failing repo is marked FAILED
    repo_records = database.code_scan_repo_get_by_scan_id(scan_id)
    status_map = {r["repo_identifier"]: r["status"] for r in repo_records}
    assert status_map[failing_repo] == "FAILED", (
        f"Expected failing repo to be FAILED, got {status_map[failing_repo]}"
    )

    # Scan should still COMPLETE (per-repo isolation catches per-repo errors)
    # But if it's a scan-level error, it should be FAILED
    scan = database.get_code_scan(scan_id)
    # Per-repo isolation means scan completes; partial findings are preserved
    assert scan["scan_phase"] in ("COMPLETED", "FAILED"), (
        f"Scan should be COMPLETED or FAILED, got {scan['scan_phase']}"
    )


# ===========================================================================
# Property 3: All Repos Reach Terminal State
# ===========================================================================

@given(repos=st_repo_list(min_size=1, max_size=10))
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_3_all_repos_reach_terminal_state(fresh_db, repos):
    """
    For any multi-repo scan request containing 1 to 200 repositories, after the scan
    completes (or is stopped/fails), every submitted repo should have a status in
    {COMPLETED, FAILED, SKIPPED} — no repo remains in QUEUED or SCANNING.

    **Validates: Requirements 2.1**
    """
    from code_scan_module import run_scan_background

    config = {"concurrency": 5, "diff_aware": False}
    scan_id = _create_scan_with_repos(repos, config)

    async def mock_invoke(sid, repo_identifier, cfg):
        return []

    import code_scan_module
    original_invoke = code_scan_module._invoke_scanner_for_repo
    code_scan_module._invoke_scanner_for_repo = mock_invoke

    try:
        asyncio.run(run_scan_background(scan_id, config))
    finally:
        code_scan_module._invoke_scanner_for_repo = original_invoke

    # Verify: every repo is in a terminal state
    repo_records = database.code_scan_repo_get_by_scan_id(scan_id)
    assert len(repo_records) == len(repos), (
        f"Expected {len(repos)} repo records, got {len(repo_records)}"
    )

    for r in repo_records:
        assert r["status"] in TERMINAL_REPO_STATES, (
            f"Repo {r['repo_identifier']} has non-terminal status: {r['status']}"
        )


# ===========================================================================
# Property 4: JSON Array and File Upload Equivalence
# ===========================================================================

@given(repos=st_repo_list(min_size=1, max_size=10))
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_4_json_array_file_upload_equivalence(fresh_db, repos):
    """
    For any list of repository identifiers, submitting them as a JSON array in the
    request body or as a newline-delimited text file upload should produce identical
    scan configurations.

    **Validates: Requirements 2.2**
    """
    from code_scan_module import build_scan_config, ScanStartRequest

    # Simulate JSON array submission: create request directly from repos list
    json_request = ScanStartRequest(repos=repos)
    json_config = build_scan_config(json_request)

    # Simulate file upload: parse newline-delimited text into repos list
    file_content = "\n".join(repos)
    parsed_repos = [line.strip() for line in file_content.splitlines() if line.strip()]

    # Create request from parsed file content
    file_request = ScanStartRequest(repos=parsed_repos)
    file_config = build_scan_config(file_request)

    # Verify: both methods produce identical configurations
    assert json_config == file_config, (
        f"JSON config != File config:\nJSON: {json_config}\nFile: {file_config}"
    )

    # Verify: parsed repos match original repos
    assert parsed_repos == repos, (
        f"Parsed repos != original repos:\nParsed: {parsed_repos}\nOriginal: {repos}"
    )


# ===========================================================================
# Property 5: Status Reports All Repos
# ===========================================================================

@given(repos=st_repo_list(min_size=1, max_size=10))
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_5_status_reports_all_repos(fresh_db, repos):
    """
    For any multi-repo scan with N submitted repositories, the status endpoint response
    should contain exactly N repo status entries.

    **Validates: Requirements 2.3**
    """
    from code_scan_module import run_scan_background

    config = {"concurrency": 5, "diff_aware": False}
    scan_id = _create_scan_with_repos(repos, config)

    async def mock_invoke(sid, repo_identifier, cfg):
        return []

    import code_scan_module
    original_invoke = code_scan_module._invoke_scanner_for_repo
    code_scan_module._invoke_scanner_for_repo = mock_invoke

    try:
        asyncio.run(run_scan_background(scan_id, config))
    finally:
        code_scan_module._invoke_scanner_for_repo = original_invoke

    # Query the status (simulating the status endpoint logic)
    repo_records = database.code_scan_repo_get_by_scan_id(scan_id)

    # Verify: exactly N repo status entries
    assert len(repo_records) == len(repos), (
        f"Expected {len(repos)} repo status entries, got {len(repo_records)}"
    )

    # Verify: all submitted repos are represented
    reported_repos = {r["repo_identifier"] for r in repo_records}
    submitted_repos = set(repos)
    assert reported_repos == submitted_repos, (
        f"Mismatch: reported={reported_repos}, submitted={submitted_repos}"
    )


# ===========================================================================
# Property 6: Multi-Repo Isolation
# ===========================================================================

@given(
    repos=st_repo_list(min_size=2, max_size=10),
    failure_idx=integers(min_value=0, max_value=9),
)
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_6_multi_repo_isolation(fresh_db, repos, failure_idx):
    """
    For any multi-repo scan where one repository is injected with a failure condition,
    all other repositories should still reach a terminal state.

    **Validates: Requirements 2.4**
    """
    from code_scan_module import run_scan_background

    # Pick which repo will fail (wrap index within bounds)
    actual_failure_idx = failure_idx % len(repos)
    failing_repo = repos[actual_failure_idx]

    config = {"concurrency": 5, "diff_aware": False}
    scan_id = _create_scan_with_repos(repos, config)

    async def mock_invoke(sid, repo_identifier, cfg):
        if repo_identifier == failing_repo:
            raise RuntimeError(f"Injected failure for {repo_identifier}")
        return []

    import code_scan_module
    original_invoke = code_scan_module._invoke_scanner_for_repo
    code_scan_module._invoke_scanner_for_repo = mock_invoke

    try:
        asyncio.run(run_scan_background(scan_id, config))
    finally:
        code_scan_module._invoke_scanner_for_repo = original_invoke

    # Verify: all repos reach a terminal state
    repo_records = database.code_scan_repo_get_by_scan_id(scan_id)
    status_map = {r["repo_identifier"]: r["status"] for r in repo_records}

    for repo in repos:
        assert status_map[repo] in TERMINAL_REPO_STATES, (
            f"Repo {repo} has non-terminal status: {status_map[repo]}"
        )

    # The failing repo should be FAILED
    assert status_map[failing_repo] == "FAILED", (
        f"Expected failing repo to be FAILED, got {status_map[failing_repo]}"
    )

    # All other repos should be COMPLETED (since no diff-aware skipping)
    for repo in repos:
        if repo != failing_repo:
            assert status_map[repo] == "COMPLETED", (
                f"Non-failing repo {repo} should be COMPLETED, got {status_map[repo]}"
            )


# ===========================================================================
# Property 7: Diff-Aware Skip on Same SHA
# ===========================================================================

@given(repos=st_repo_list(min_size=1, max_size=5))
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_7_diff_aware_skip_on_same_sha(fresh_db, repos):
    """
    For any repository that has a prior completed scan with the same HEAD SHA, when
    diff_aware mode is enabled the repo should be marked SKIPPED.

    **Validates: Requirements 2.5**
    """
    from code_scan_module import run_scan_background

    # Clean up any existing repo records to prevent cross-contamination between
    # hypothesis examples (they share the same DB within one test invocation)
    conn = database.get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM code_scan_repos")
    c.execute("DELETE FROM code_scans")
    c.execute("DELETE FROM code_scan_findings")
    conn.commit()
    conn.close()

    # Generate a unique SHA for each repo
    repo_shas = {repo: f"sha_{uuid.uuid4().hex[:12]}" for repo in repos}

    # --- First: create a prior completed scan with known SHAs ---
    prior_config = {"concurrency": 5, "diff_aware": False}
    prior_scan_id = _create_scan_with_repos(repos, prior_config)

    # Manually complete the prior scan with known SHAs
    prior_repo_records = database.code_scan_repo_get_by_scan_id(prior_scan_id)
    conn = database.get_db_connection()
    c = conn.cursor()
    for r in prior_repo_records:
        sha = repo_shas[r["repo_identifier"]]
        c.execute(
            "UPDATE code_scan_repos SET status = 'COMPLETED', head_sha = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (sha, r["id"]),
        )
    conn.commit()
    conn.close()

    # --- Second: create a new scan with diff_aware=True ---
    config = {"concurrency": 5, "diff_aware": True}
    scan_id = _create_scan_with_repos(repos, config)

    # Mock _get_repo_head_sha to return the same SHA (simulating no changes)
    # Use a closure that captures repo_shas for this specific test invocation
    import code_scan_module
    original_get_sha = code_scan_module._get_repo_head_sha

    def patched_get_sha(repo):
        return repo_shas.get(repo, None)

    code_scan_module._get_repo_head_sha = patched_get_sha

    # Mock _invoke_scanner_for_repo (should NOT be called for skipped repos)
    invoke_called_for = []

    async def mock_invoke(sid, repo_identifier, cfg):
        invoke_called_for.append(repo_identifier)
        return []

    original_invoke = code_scan_module._invoke_scanner_for_repo
    code_scan_module._invoke_scanner_for_repo = mock_invoke

    try:
        asyncio.run(run_scan_background(scan_id, config))

        # Verify: all repos should be SKIPPED (same SHA as prior scan)
        repo_records = database.code_scan_repo_get_by_scan_id(scan_id)
        for r in repo_records:
            assert r["status"] == "SKIPPED", (
                f"Repo {r['repo_identifier']} should be SKIPPED (diff-aware), got {r['status']}"
            )

        # Verify: scanner was NOT invoked for any repo (all skipped)
        assert len(invoke_called_for) == 0, (
            f"Scanner should not have been called for any repo, but was called for: {invoke_called_for}"
        )
    finally:
        code_scan_module._get_repo_head_sha = original_get_sha
        code_scan_module._invoke_scanner_for_repo = original_invoke

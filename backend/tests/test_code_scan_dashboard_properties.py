"""
Property-based tests for Code Scanner → Unified Dashboard integration.

Property 24: Unified Dashboard Integration
All findings are pushed with source_module="code_scan" and finding_type correctly set.
For each chain, exactly one unified finding of type "chain" is created.

**Validates: Requirements 19.1, 19.2, 19.4**

Property 25: Dashboard Finding Type Filterable
Filtering by finding_type returns only findings matching that type.

**Validates: Requirements 19.3**
"""

import json
import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    composite,
    integers,
    lists,
    sampled_from,
    text,
    floats,
    just,
    one_of,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from code_scan_module import push_to_unified_dashboard


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FINDING_TYPES = ["sast", "sca", "cbom", "container"]
CHAIN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Set up a fresh temporary database for each test function."""
    original_db_name = database.DB_NAME
    database.DB_NAME = str(tmp_path / "test_dashboard_integration.db")
    database.init_db()
    yield
    database.DB_NAME = original_db_name


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_finding(draw):
    """Generate a valid code scan finding dict for persistence."""
    finding_id = str(uuid.uuid4())
    severity = draw(sampled_from(SEVERITIES))
    finding_type = draw(sampled_from(FINDING_TYPES))
    title = draw(sampled_from([
        "SQL Injection in login handler",
        "XSS in user input",
        "Hardcoded credentials",
        "SSRF via URL parameter",
        "Buffer overflow in parser",
        "Command injection in exec",
    ]))
    description = draw(sampled_from([
        "User input flows into database query without sanitization.",
        "Untrusted data rendered in HTML response.",
        "API key hardcoded in source file.",
        "Server-side request forgery via controllable URL.",
    ]))
    file_path = draw(sampled_from([
        "src/auth/login.py",
        "app/api/handler.js",
        "lib/utils/parser.go",
        "services/user/controller.ts",
    ]))
    return {
        "id": finding_id,
        "severity": severity,
        "finding_type": finding_type,
        "title": title,
        "description": description,
        "file_path": file_path,
        "vuln_class": "SQL_Injection",
        "line_start": 10,
        "line_end": 15,
        "confidence": 85,
        "repo": "owner/repo",
    }


@composite
def st_chain(draw):
    """Generate a valid exploit chain dict."""
    chain_id = str(uuid.uuid4())
    severity = draw(sampled_from(CHAIN_SEVERITIES))
    step_count = draw(integers(min_value=2, max_value=4))
    affected_repos = draw(lists(
        sampled_from(["owner/repo-a", "owner/repo-b", "owner/repo-c"]),
        min_size=1,
        max_size=3,
        unique=True,
    ))
    chain_json = json.dumps({
        "steps": [{"repo": r, "finding": f"finding-{i}"} for i, r in enumerate(affected_repos[:step_count])],
        "description": "Multi-step exploit chain",
    })
    confidence_score = draw(floats(min_value=0.5, max_value=1.0))
    return {
        "severity": severity,
        "chain_json": chain_json,
        "affected_repos": json.dumps(affected_repos),
        "step_count": step_count,
        "confidence_score": confidence_score,
    }


@composite
def st_findings_and_chains(draw):
    """Generate a list of findings and a list of chains for a scan."""
    findings = draw(lists(st_finding(), min_size=1, max_size=8))
    chains = draw(lists(st_chain(), min_size=0, max_size=3))
    return findings, chains


# ---------------------------------------------------------------------------
# Property 24: Unified Dashboard Integration
# ---------------------------------------------------------------------------

@given(data=st_findings_and_chains())
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_property_24_unified_dashboard_integration(setup_test_db, data):
    """
    Property 24: All findings are pushed with source_module="code_scan" and
    finding_type correctly set. For each chain, exactly one unified finding
    of type "chain" is created.

    **Validates: Requirements 19.1, 19.2, 19.4**
    """
    findings, chains = data

    # Create a scan in the DB
    scan_id = database.create_code_scan(
        label="Test Dashboard Integration",
        repos=["owner/repo"],
        config={"budget_limit_usd": 50.0},
    )

    # Persist findings to code_scan_findings table
    database.insert_code_scan_findings(scan_id, findings)

    # Update finding_type on each persisted finding
    persisted_findings = database.get_code_scan_findings(scan_id)
    for i, pf in enumerate(persisted_findings):
        if i < len(findings):
            database.code_scan_finding_update_type(
                finding_id=pf["id"],
                finding_type=findings[i]["finding_type"],
                repo_identifier="owner/repo",
            )

    # Persist chains
    for chain in chains:
        database.code_scan_chain_create(
            scan_id=scan_id,
            chain_json=chain["chain_json"],
            severity=chain["severity"],
            confidence_score=chain["confidence_score"],
            affected_repos=chain["affected_repos"],
            step_count=chain["step_count"],
        )

    # Execute push_to_unified_dashboard
    result = push_to_unified_dashboard(scan_id)

    # Verify findings_pushed count matches number of persisted findings
    assert result["findings_pushed"] == len(persisted_findings)

    # Verify chains_pushed count matches number of chains
    assert result["chains_pushed"] == len(chains)

    # Verify all unified findings pushed have source_module="code_scan" in module_tags
    # We verify by checking evidence sources for this scan_id
    all_unified, total = database.list_unified_findings(
        filters={},
        page=1,
        page_size=10000,
    )

    # Find unified findings that were pushed from this scan (via evidence_sources)
    pushed_unified_ids = set()
    for uf in all_unified:
        evidence = database.get_evidence_sources(uf["id"])
        for ev in evidence:
            if ev.get("source_scan_id") == scan_id:
                pushed_unified_ids.add(uf["id"])
                break

    assert len(pushed_unified_ids) == len(persisted_findings) + len(chains)

    # Verify finding_type is set correctly for non-chain findings
    for uf_id in pushed_unified_ids:
        uf = database.get_unified_finding(uf_id)
        assert uf is not None
        # module_tags should contain "code_scan"
        module_tags = uf.get("module_tags", [])
        if isinstance(module_tags, str):
            module_tags = json.loads(module_tags)
        assert "code_scan" in module_tags
        # finding_type should be set
        assert uf.get("finding_type") in FINDING_TYPES + ["chain"]

    # Verify chains: exactly one unified finding per chain with type "chain"
    chain_unified = [
        uid for uid in pushed_unified_ids
        if database.get_unified_finding(uid).get("finding_type") == "chain"
    ]
    assert len(chain_unified) == len(chains)


# ---------------------------------------------------------------------------
# Property 25: Dashboard Finding Type Filterable
# ---------------------------------------------------------------------------

@given(data=st_findings_and_chains())
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_property_25_dashboard_finding_type_filterable(setup_test_db, data):
    """
    Property 25: Filtering by finding_type returns only findings matching that type.
    No cross-contamination between sast, sca, cbom, container, and chain types.

    **Validates: Requirements 19.3**
    """
    findings, chains = data

    # Create a scan and persist data
    scan_id = database.create_code_scan(
        label="Test Finding Type Filter",
        repos=["owner/repo"],
        config={"budget_limit_usd": 50.0},
    )

    # Persist findings
    database.insert_code_scan_findings(scan_id, findings)

    # Update finding_type on each persisted finding
    persisted_findings = database.get_code_scan_findings(scan_id)
    for i, pf in enumerate(persisted_findings):
        if i < len(findings):
            database.code_scan_finding_update_type(
                finding_id=pf["id"],
                finding_type=findings[i]["finding_type"],
                repo_identifier="owner/repo",
            )

    # Persist chains
    for chain in chains:
        database.code_scan_chain_create(
            scan_id=scan_id,
            chain_json=chain["chain_json"],
            severity=chain["severity"],
            confidence_score=chain["confidence_score"],
            affected_repos=chain["affected_repos"],
            step_count=chain["step_count"],
        )

    # Push to unified dashboard
    push_to_unified_dashboard(scan_id)

    # Test filtering by each finding_type — no cross-contamination
    all_types = FINDING_TYPES + ["chain"]
    for filter_type in all_types:
        filtered_findings, filtered_count = database.list_unified_findings(
            filters={"finding_type": filter_type},
            page=1,
            page_size=10000,
        )
        # Every returned finding must match the filter type
        for f in filtered_findings:
            assert f.get("finding_type") == filter_type, (
                f"Cross-contamination: filtering by '{filter_type}' returned "
                f"finding with type '{f.get('finding_type')}'"
            )

    # Verify that findings from this scan are correctly distributed across types
    # by checking evidence_sources
    all_unified, _ = database.list_unified_findings(
        filters={},
        page=1,
        page_size=10000,
    )

    pushed_from_this_scan = []
    for uf in all_unified:
        evidence = database.get_evidence_sources(uf["id"])
        for ev in evidence:
            if ev.get("source_scan_id") == scan_id:
                pushed_from_this_scan.append(uf)
                break

    # Verify total pushed matches expected
    expected_total = len(persisted_findings) + len(chains)
    assert len(pushed_from_this_scan) == expected_total

    # Verify no finding_type is None for pushed findings
    for uf in pushed_from_this_scan:
        assert uf.get("finding_type") is not None
        assert uf.get("finding_type") in all_types

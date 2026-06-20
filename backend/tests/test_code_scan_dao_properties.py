"""
Property-based tests for the Holistic Code Scanner DAO layer.

Property 1: Finding Persistence Round-Trip
For any set of HolisticFinding objects produced by the scanner, persisting them
to the code_scan_findings table and then querying them back should yield equivalent
finding data (id, severity, title, description, file_path, finding_type all preserved).

**Validates: Requirements 1.3**
"""

import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    text,
    sampled_from,
    integers,
    composite,
    lists,
    one_of,
    just,
    none,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FINDING_TYPES = ["sast", "sca", "cbom", "container", "chain"]
VULN_CLASSES = [
    "SQL_Injection", "XSS", "SSRF", "Command_Injection", "Path_Traversal",
    "Auth_Bypass", "CSRF", "Insecure_Deserialization", "Buffer_Overflow",
    "Broken_Access_Control", "Sensitive_Data_Exposure",
]
OWASP_CATEGORIES = [
    "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
    "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Set up a fresh temporary database for each test function."""
    original_db_name = database.DB_NAME
    database.DB_NAME = str(tmp_path / "test_code_scan.db")
    database.init_db()
    yield
    database.DB_NAME = original_db_name


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_file_path(draw):
    """Generate a realistic file path."""
    prefixes = ["src/", "lib/", "app/", "backend/", "frontend/", "services/", ""]
    prefix = draw(sampled_from(prefixes))
    # Generate path segments
    segments = draw(
        lists(
            text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=2, max_size=15),
            min_size=1,
            max_size=4,
        )
    )
    extensions = [".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php"]
    ext = draw(sampled_from(extensions))
    path = prefix + "/".join(segments) + ext
    assume(len(path) >= 5)
    return path


@composite
def st_finding_title(draw):
    """Generate a realistic vulnerability title."""
    adjectives = ["Potential", "Critical", "Unauthenticated", "Remote", "Local"]
    nouns = [
        "SQL Injection", "XSS Attack", "Buffer Overflow", "SSRF Vulnerability",
        "Command Injection", "Path Traversal", "Auth Bypass", "CSRF",
        "Insecure Deserialization", "Data Leak", "Hardcoded Secret",
    ]
    adj = draw(sampled_from(adjectives))
    noun = draw(sampled_from(nouns))
    suffix = draw(one_of(just(""), just(" in API endpoint"), just(" in handler")))
    return f"{adj} {noun}{suffix}"


@composite
def st_finding_description(draw):
    """Generate a realistic finding description."""
    templates = [
        "User-controlled input flows into {sink} without sanitization.",
        "The function at line {line} accepts untrusted data via {source}.",
        "Hardcoded credentials found in configuration file.",
        "Sensitive data transmitted over unencrypted channel.",
        "Missing authentication check allows unauthorized access to {resource}.",
        "Insecure use of {api} may lead to remote code execution.",
    ]
    template = draw(sampled_from(templates))
    # Fill in placeholders with simple values
    desc = template.format(
        sink="database query",
        line=str(draw(integers(min_value=1, max_value=500))),
        source="HTTP request parameter",
        resource="admin panel",
        api="eval()",
    )
    return desc


@composite
def st_holistic_finding(draw):
    """Generate a valid HolisticFinding-like dict ready for persistence.

    Represents the data structure that the holistic scanner produces.
    """
    finding_id = str(uuid.uuid4())
    severity = draw(sampled_from(SEVERITIES))
    finding_type = draw(sampled_from(FINDING_TYPES))
    title = draw(st_finding_title())
    description = draw(st_finding_description())
    file_path = draw(st_file_path())
    vuln_class = draw(sampled_from(VULN_CLASSES))
    owasp_category = draw(one_of(sampled_from(OWASP_CATEGORIES), just(None)))
    repo_identifier = draw(
        sampled_from(["owner/repo-a", "owner/repo-b", "org/service-x", "team/app-y"])
    )

    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": description,
        "file_path": file_path,
        "finding_type": finding_type,
        "vuln_class": vuln_class,
        "owasp_category": owasp_category,
        "repo_identifier": repo_identifier,
    }


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def create_scan_for_test() -> str:
    """Create a code scan record and return its ID."""
    scan_id = database.create_code_scan(
        label="Property Test Scan",
        repos=["owner/test-repo"],
        config={},
    )
    return scan_id


def persist_finding(scan_id: str, finding: dict) -> str:
    """Persist a holistic finding to the code_scan_findings table.

    Uses insert_code_scan_findings then updates the holistic-scanner columns.
    Returns the finding ID.
    """
    # Insert the base finding
    base_finding = {
        "id": finding["id"],
        "severity": finding["severity"],
        "title": finding["title"],
        "description": finding["description"],
        "file_path": finding["file_path"],
        "vuln_class": finding.get("vuln_class"),
        "owasp_category": finding.get("owasp_category"),
        "repo": finding.get("repo_identifier", ""),
    }
    database.insert_code_scan_findings(scan_id, [base_finding])

    # Update the holistic-scanner-specific columns
    database.code_scan_finding_update_type(
        finding_id=finding["id"],
        finding_type=finding["finding_type"],
        repo_identifier=finding.get("repo_identifier"),
    )

    return finding["id"]


# ===========================================================================
# Property 1: Finding Persistence Round-Trip
# ===========================================================================

@given(finding=st_holistic_finding())
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_1_finding_persistence_round_trip(setup_test_db, finding):
    """
    For any HolisticFinding object produced by the scanner, persisting it to the
    code_scan_findings table and then querying it back should yield equivalent
    finding data (id, severity, title, description, file_path, finding_type all preserved).

    **Validates: Requirements 1.3**
    """
    # Create a scan to hold the finding
    scan_id = create_scan_for_test()

    # Persist the finding
    persist_finding(scan_id, finding)

    # Read it back
    findings_list = database.get_code_scan_findings(scan_id)

    # Should have exactly one finding
    assert len(findings_list) == 1, f"Expected 1 finding, got {len(findings_list)}"

    retrieved = findings_list[0]

    # Verify all key fields are preserved (round-trip identity)
    assert retrieved["id"] == finding["id"], (
        f"ID mismatch: {retrieved['id']} != {finding['id']}"
    )
    assert retrieved["severity"] == finding["severity"], (
        f"Severity mismatch: {retrieved['severity']} != {finding['severity']}"
    )
    assert retrieved["title"] == finding["title"], (
        f"Title mismatch: {retrieved['title']} != {finding['title']}"
    )
    assert retrieved["description"] == finding["description"], (
        f"Description mismatch: {retrieved['description']} != {finding['description']}"
    )
    assert retrieved["file_path"] == finding["file_path"], (
        f"File path mismatch: {retrieved['file_path']} != {finding['file_path']}"
    )
    assert retrieved["finding_type"] == finding["finding_type"], (
        f"Finding type mismatch: {retrieved['finding_type']} != {finding['finding_type']}"
    )


@given(findings=lists(st_holistic_finding(), min_size=1, max_size=10))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_1_batch_finding_persistence_round_trip(setup_test_db, findings):
    """
    For any batch of HolisticFinding objects, persisting them all and querying them back
    should yield the same set of findings with all fields preserved.

    **Validates: Requirements 1.3**
    """
    # Ensure all findings have unique IDs
    seen_ids = set()
    unique_findings = []
    for f in findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique_findings.append(f)

    assume(len(unique_findings) >= 1)

    # Create a scan to hold the findings
    scan_id = create_scan_for_test()

    # Persist all findings
    for finding in unique_findings:
        persist_finding(scan_id, finding)

    # Read them all back
    findings_list = database.get_code_scan_findings(scan_id)

    # Should have the same count
    assert len(findings_list) == len(unique_findings), (
        f"Expected {len(unique_findings)} findings, got {len(findings_list)}"
    )

    # Build a lookup by ID for easy comparison
    retrieved_by_id = {f["id"]: f for f in findings_list}

    for original in unique_findings:
        assert original["id"] in retrieved_by_id, (
            f"Finding {original['id']} not found in retrieved results"
        )
        retrieved = retrieved_by_id[original["id"]]

        # Verify round-trip for all key fields
        assert retrieved["severity"] == original["severity"]
        assert retrieved["title"] == original["title"]
        assert retrieved["description"] == original["description"]
        assert retrieved["file_path"] == original["file_path"]
        assert retrieved["finding_type"] == original["finding_type"]

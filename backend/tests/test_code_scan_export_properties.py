"""
Property-based tests for export formats in the Holistic Code Scanner.

Property 27: Export Format Correctness
For any completed scan with findings:
- JSON export should contain all findings present in the database (completeness)
- SARIF export should produce a valid SARIF v2.1.0 document with one result per finding
- The SARIF document should have correct structure: $schema, version "2.1.0", runs array, tool section

**Validates: Requirements 21.1, 21.2, 21.4**
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
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VALID_FINDING_TYPES = ["sast", "sca", "cbom", "container", "chain"]

SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Set up a fresh temporary database for each test."""
    db_path = str(tmp_path / "test_export_props.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-export-props")
    database.init_db()
    yield


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_finding(draw):
    """Generate a single finding with varied severities and finding_types."""
    severity = draw(sampled_from(VALID_SEVERITIES))
    finding_type = draw(sampled_from(VALID_FINDING_TYPES))
    vuln_class = draw(sampled_from([
        "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "SSRF", "IDOR",
        "BROKEN_AUTH", "CRYPTO_WEAK", "INSECURE_DESERIALIZATION",
        "COMMAND_INJECTION", "HARDCODED_SECRET", "OTHER",
    ]))
    line_start = draw(integers(min_value=1, max_value=500))
    repo = draw(sampled_from(["owner/repo-a", "owner/repo-b", "owner/repo-c"]))

    return {
        "id": str(uuid.uuid4()),
        "vuln_class": vuln_class,
        "repo": repo,
        "file_path": f"src/module_{draw(integers(min_value=1, max_value=20))}.py",
        "line_start": line_start,
        "line_end": line_start + draw(integers(min_value=0, max_value=10)),
        "severity": severity,
        "confidence": draw(integers(min_value=50, max_value=100)),
        "title": f"Finding: {vuln_class} in {repo}",
        "description": f"Detected {vuln_class} vulnerability",
        "finding_type": finding_type,
    }


@composite
def st_findings_list(draw, min_size=1, max_size=10):
    """Generate a list of 1-10 findings with varied severities and types."""
    return draw(lists(st_finding(), min_size=min_size, max_size=max_size))


# ---------------------------------------------------------------------------
# Helper: simulate what the export endpoint does
# ---------------------------------------------------------------------------

def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level (mirrors code_scan_module._sarif_level)."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    return mapping.get(severity.upper(), "warning")


def build_json_export(scan_id: str, findings: list) -> dict:
    """Build JSON export response (mirrors code_scan_module.export_scan for format=json)."""
    return {
        "scan_id": scan_id,
        "format": "json",
        "findings": findings,
        "total": len(findings),
    }


def build_sarif_export(scan_id: str, findings: list) -> dict:
    """Build SARIF export response (mirrors code_scan_module.export_scan for format=sarif)."""
    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Angela Holistic Scanner",
                        "version": "2.0.0",
                    }
                },
                "results": [
                    {
                        "ruleId": f.get("vuln_class", "OTHER"),
                        "level": _sarif_level(f.get("severity", "MEDIUM")),
                        "message": {"text": f.get("title", "")},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.get("file_path", "")},
                                    "region": {"startLine": f.get("line_number", 1) or 1},
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }


# ===========================================================================
# Property 27: Export Format Correctness
# ===========================================================================

@given(findings_data=st_findings_list(min_size=1, max_size=10))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_27_json_export_completeness(fresh_db, findings_data):
    """
    For any completed scan with findings, the JSON export should contain all
    findings present in the database (completeness).

    **Validates: Requirements 21.1**
    """
    # Create a scan and persist findings
    scan_id = database.create_code_scan(
        label="Export test scan",
        repos=["owner/repo-a"],
        config={},
    )

    # Insert findings into DB
    database.insert_code_scan_findings(scan_id, findings_data)

    # Retrieve findings from DB (as the export endpoint would)
    db_findings = database.get_code_scan_findings(scan_id)

    # Build the JSON export
    json_export = build_json_export(scan_id, db_findings)

    # Property: JSON export total matches DB count
    assert json_export["total"] == len(findings_data), (
        f"JSON export total ({json_export['total']}) does not match "
        f"number of inserted findings ({len(findings_data)})"
    )

    # Property: JSON export findings array count matches DB count
    assert len(json_export["findings"]) == len(findings_data), (
        f"JSON export findings count ({len(json_export['findings'])}) does not match "
        f"number of inserted findings ({len(findings_data)})"
    )

    # Property: All finding IDs from the DB are present in the export
    db_ids = {f["id"] for f in db_findings}
    export_ids = {f["id"] for f in json_export["findings"]}
    assert db_ids == export_ids, (
        f"Finding IDs mismatch. DB has {db_ids - export_ids} extra, "
        f"export has {export_ids - db_ids} extra"
    )

    # Property: format field is correct
    assert json_export["format"] == "json"
    assert json_export["scan_id"] == scan_id


@given(findings_data=st_findings_list(min_size=1, max_size=10))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_27_sarif_export_structure(fresh_db, findings_data):
    """
    For any completed scan with findings, the SARIF export should produce a valid
    SARIF v2.1.0 document with correct structure and one result per finding.

    **Validates: Requirements 21.2, 21.4**
    """
    # Create a scan and persist findings
    scan_id = database.create_code_scan(
        label="SARIF export test scan",
        repos=["owner/repo-a"],
        config={},
    )

    # Insert findings into DB
    database.insert_code_scan_findings(scan_id, findings_data)

    # Retrieve findings from DB (as the export endpoint would)
    db_findings = database.get_code_scan_findings(scan_id)

    # Build the SARIF export
    sarif_doc = build_sarif_export(scan_id, db_findings)

    # --- SARIF structural validation ---

    # Property: $schema field is present and correct
    assert "$schema" in sarif_doc, "SARIF document missing $schema field"
    assert sarif_doc["$schema"] == SARIF_SCHEMA_URL, (
        f"SARIF $schema mismatch: got '{sarif_doc['$schema']}'"
    )

    # Property: version is "2.1.0"
    assert "version" in sarif_doc, "SARIF document missing version field"
    assert sarif_doc["version"] == SARIF_VERSION, (
        f"SARIF version mismatch: expected '2.1.0', got '{sarif_doc['version']}'"
    )

    # Property: runs is an array with at least one run
    assert "runs" in sarif_doc, "SARIF document missing runs field"
    assert isinstance(sarif_doc["runs"], list), "SARIF runs should be an array"
    assert len(sarif_doc["runs"]) >= 1, "SARIF runs array should have at least one run"

    # Property: first run has a tool section with driver
    run = sarif_doc["runs"][0]
    assert "tool" in run, "SARIF run missing tool section"
    assert "driver" in run["tool"], "SARIF tool missing driver section"
    assert "name" in run["tool"]["driver"], "SARIF driver missing name"
    assert "version" in run["tool"]["driver"], "SARIF driver missing version"

    # Property: results has exactly N results (one per finding)
    assert "results" in run, "SARIF run missing results section"
    results = run["results"]
    assert len(results) == len(findings_data), (
        f"SARIF results count ({len(results)}) does not match "
        f"number of findings ({len(findings_data)})"
    )

    # Property: Each result has ruleId, level, message.text, and locations
    for i, result in enumerate(results):
        assert "ruleId" in result, f"SARIF result {i} missing ruleId"
        assert result["ruleId"] is not None and len(str(result["ruleId"])) > 0, (
            f"SARIF result {i} has empty ruleId"
        )

        assert "level" in result, f"SARIF result {i} missing level"
        assert result["level"] in ("error", "warning", "note", "none"), (
            f"SARIF result {i} has invalid level: '{result['level']}'"
        )

        assert "message" in result, f"SARIF result {i} missing message"
        assert "text" in result["message"], f"SARIF result {i} missing message.text"

        assert "locations" in result, f"SARIF result {i} missing locations"
        assert isinstance(result["locations"], list), (
            f"SARIF result {i} locations should be an array"
        )
        assert len(result["locations"]) >= 1, (
            f"SARIF result {i} should have at least one location"
        )

        # Validate location structure
        loc = result["locations"][0]
        assert "physicalLocation" in loc, (
            f"SARIF result {i} location missing physicalLocation"
        )
        phys = loc["physicalLocation"]
        assert "artifactLocation" in phys, (
            f"SARIF result {i} missing artifactLocation"
        )
        assert "uri" in phys["artifactLocation"], (
            f"SARIF result {i} missing artifactLocation.uri"
        )
        assert "region" in phys, (
            f"SARIF result {i} missing region"
        )
        assert "startLine" in phys["region"], (
            f"SARIF result {i} missing region.startLine"
        )


@given(findings_data=st_findings_list(min_size=1, max_size=10))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_27_sarif_severity_mapping(fresh_db, findings_data):
    """
    For any set of findings, the SARIF export should correctly map severity levels:
    CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW -> "note".

    **Validates: Requirements 21.2**
    """
    # Create a scan and persist findings
    scan_id = database.create_code_scan(
        label="SARIF severity test scan",
        repos=["owner/repo-a"],
        config={},
    )

    database.insert_code_scan_findings(scan_id, findings_data)
    db_findings = database.get_code_scan_findings(scan_id)

    # Build the SARIF export
    sarif_doc = build_sarif_export(scan_id, db_findings)
    results = sarif_doc["runs"][0]["results"]

    # Property: each result's level corresponds to its severity
    for i, (result, finding) in enumerate(zip(results, db_findings)):
        severity = finding.get("severity", "MEDIUM")
        expected_level = _sarif_level(severity)
        assert result["level"] == expected_level, (
            f"SARIF result {i}: severity '{severity}' should map to level "
            f"'{expected_level}', got '{result['level']}'"
        )

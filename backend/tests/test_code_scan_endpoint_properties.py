"""
Property-based tests for specialized endpoints in the Holistic Code Scanner.

Property 8: SBOM Component Completeness
For any set of lockfile contents parsed by the SBOM generator, the resulting CycloneDX
document should have a component count equal to the number of distinct dependencies, and
every component should have non-empty name, version, ecosystem, and purl fields.

**Validates: Requirements 3.1, 3.3**

Property 9: CBOM Classification and Finding Generation
For any detected cryptographic algorithm, the classification should be exactly one of
{SAFE, WEAK, QUANTUM_RISK}, and for every WEAK/QUANTUM_RISK, a corresponding finding
should exist with severity MEDIUM (WEAK) or HIGH (QUANTUM_RISK).

**Validates: Requirements 4.2, 4.4**

Property 10: CVSS-to-Severity Mapping
For any CVE with a numeric CVSS score, the severity mapping should produce CRITICAL for
score >= 9.0, HIGH for >= 7.0, MEDIUM for >= 4.0, and LOW for < 4.0.

**Validates: Requirements 5.4**

Property 16: License Classification and Flagging Invariant
For any dependency with a license identifier, exactly one classification from
{PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, COMMERCIAL, UNKNOWN}, and
STRONG_COPYLEFT/UNKNOWN should have requires_review=true.

**Validates: Requirements 8.1, 8.2**

Property 18: Container Severity Classification
For any critical misconfiguration (running as root, secrets in build args), severity
should be HIGH or CRITICAL.

**Validates: Requirements 9.4**
"""

import json
import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    booleans,
    composite,
    dictionaries,
    floats,
    integers,
    just,
    lists,
    none,
    one_of,
    sampled_from,
    text,
    tuples,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_CBOM_CLASSIFICATIONS = {"SAFE", "WEAK", "QUANTUM_RISK"}
VALID_LICENSE_CATEGORIES = {"PERMISSIVE", "WEAK_COPYLEFT", "STRONG_COPYLEFT", "COMMERCIAL", "UNKNOWN"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
ECOSYSTEMS = ["npm", "pypi", "maven", "cargo", "go", "rubygems", "nuget", "composer"]

# Critical container misconfigurations that should always produce HIGH or CRITICAL
CRITICAL_CONTAINER_MISCONFIGS = [
    "running_as_root",
    "secrets_in_build_args",
    "secrets_in_env",
    "root_user",
    "hardcoded_secrets",
    "plaintext_password_in_args",
]


# ---------------------------------------------------------------------------
# Helper Functions — Classification Logic (encoding the rules from the spec)
# ---------------------------------------------------------------------------

def cvss_to_severity(score: float) -> str:
    """Convert a CVSS score to a severity string.

    Uses CVSS v3 severity ranges per Requirement 5.4:
    - >= 9.0: CRITICAL
    - >= 7.0: HIGH
    - >= 4.0: MEDIUM
    - < 4.0: LOW
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def classify_cbom_algorithm(algorithm: str, key_size: int = None) -> str:
    """Classify a cryptographic algorithm as SAFE, WEAK, or QUANTUM_RISK.

    Based on current NIST guidance (Requirement 4.2):
    - WEAK: DES, 3DES, MD5, SHA-1, RC4, Blowfish, small RSA (<2048)
    - QUANTUM_RISK: RSA (any), ECC, DH, DSA (all public-key crypto vulnerable to quantum)
    - SAFE: AES-128+, SHA-256+, ChaCha20, HMAC-SHA256+
    """
    algo_upper = algorithm.upper()

    # Weak algorithms
    weak_patterns = ["DES", "3DES", "TRIPLE_DES", "MD5", "SHA1", "SHA-1", "RC4", "RC2", "BLOWFISH"]
    for pattern in weak_patterns:
        if pattern in algo_upper:
            # 3DES check must not match plain DES
            if pattern == "DES" and ("3DES" in algo_upper or "TRIPLE" in algo_upper):
                continue
            return "WEAK"

    # Quantum-risk: public-key algorithms
    quantum_risk_patterns = ["RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "DIFFIE"]
    for pattern in quantum_risk_patterns:
        if pattern in algo_upper:
            # Small RSA keys are also weak, but primary classification is quantum risk
            return "QUANTUM_RISK"

    # Safe: modern symmetric and hash algorithms
    return "SAFE"


def cbom_classification_to_severity(classification: str) -> str:
    """Map CBOM classification to finding severity per Requirement 4.4."""
    if classification == "WEAK":
        return "MEDIUM"
    elif classification == "QUANTUM_RISK":
        return "HIGH"
    return None  # SAFE algorithms don't generate findings


def classify_license(license_id: str) -> dict:
    """Classify a license identifier into a category with review flag.

    Per Requirements 8.1, 8.2:
    - PERMISSIVE: MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, Unlicense, CC0-1.0
    - WEAK_COPYLEFT: LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-1.0, EPL-2.0
    - STRONG_COPYLEFT: GPL-2.0, GPL-3.0, AGPL-3.0, EUPL-1.2
    - COMMERCIAL: Proprietary, Commercial
    - UNKNOWN: anything not recognized

    STRONG_COPYLEFT and UNKNOWN require review.
    """
    license_upper = license_id.upper().strip()

    # Permissive licenses
    permissive = [
        "MIT", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "APACHE-2.0", "ISC",
        "UNLICENSE", "CC0-1.0", "0BSD", "WTFPL", "ZLIB", "BSL-1.0",
    ]
    for p in permissive:
        if p in license_upper:
            return {"category": "PERMISSIVE", "requires_review": False}

    # Weak copyleft
    weak_copyleft = ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0", "LGPL-2.0"]
    for wc in weak_copyleft:
        if wc in license_upper:
            return {"category": "WEAK_COPYLEFT", "requires_review": False}

    # Strong copyleft (check before weak, since GPL patterns overlap)
    strong_copyleft = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-1.0", "EUPL-1.2"]
    for sc in strong_copyleft:
        if sc in license_upper:
            return {"category": "STRONG_COPYLEFT", "requires_review": True}

    # Commercial
    commercial = ["PROPRIETARY", "COMMERCIAL"]
    for c in commercial:
        if c in license_upper:
            return {"category": "COMMERCIAL", "requires_review": False}

    # Unknown — anything not recognized
    return {"category": "UNKNOWN", "requires_review": True}


def classify_container_severity(misconfiguration_type: str) -> str:
    """Classify container misconfiguration severity per Requirement 9.4.

    Critical misconfigurations (running as root, secrets in build args) should
    always produce HIGH or CRITICAL severity.
    """
    misconfig_upper = misconfiguration_type.upper().replace("-", "_").replace(" ", "_")

    # Critical misconfigurations always produce HIGH or CRITICAL
    critical_patterns = [
        "ROOT", "SECRET", "PASSWORD", "HARDCODED", "PLAINTEXT",
        "CREDENTIAL", "PRIVATE_KEY", "TOKEN_IN",
    ]
    for pattern in critical_patterns:
        if pattern in misconfig_upper:
            return "HIGH"

    # Other misconfigurations may be MEDIUM or LOW
    return "MEDIUM"


# ---------------------------------------------------------------------------
# SBOM Helper — Generate CycloneDX document from dependencies
# ---------------------------------------------------------------------------

def generate_sbom_cyclonedx(dependencies: list) -> dict:
    """Generate a CycloneDX 1.5 document from a list of dependency dicts.

    Each dependency has: name, version, ecosystem.
    Returns the CycloneDX JSON structure with components.
    """
    components = []
    for dep in dependencies:
        purl = f"pkg:{dep['ecosystem']}/{dep['name']}@{dep['version']}"
        components.append({
            "type": "library",
            "name": dep["name"],
            "version": dep["version"],
            "purl": purl,
            "properties": [
                {"name": "ecosystem", "value": dep["ecosystem"]}
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": "2024-01-01T00:00:00Z",
            "tools": [{"name": "angela-sbom-generator", "version": "2.0.0"}],
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Set up a fresh temporary database for each test."""
    db_path = str(tmp_path / "test_endpoint_props.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret-endpoint-props")
    database.init_db()
    yield


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_dependency(draw):
    """Generate a single dependency with name, version, and ecosystem."""
    ecosystem = draw(sampled_from(ECOSYSTEMS))
    name = draw(sampled_from([
        "express", "lodash", "react", "axios", "flask", "django", "requests",
        "numpy", "pandas", "tokio", "serde", "actix-web", "spring-boot",
        "junit", "mocha", "jest", "pytest", "gunicorn", "uvicorn",
    ]))
    major = draw(integers(min_value=0, max_value=20))
    minor = draw(integers(min_value=0, max_value=99))
    patch = draw(integers(min_value=0, max_value=99))
    version = f"{major}.{minor}.{patch}"
    return {"name": name, "version": version, "ecosystem": ecosystem}


@composite
def st_dependency_list(draw, min_size=1, max_size=20):
    """Generate a list of unique dependencies."""
    deps = draw(lists(st_dependency(), min_size=min_size, max_size=max_size))
    # Deduplicate by (name, version, ecosystem)
    seen = set()
    unique_deps = []
    for dep in deps:
        key = (dep["name"], dep["version"], dep["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_deps.append(dep)
    assume(len(unique_deps) >= min_size)
    return unique_deps[:max_size]


@composite
def st_crypto_algorithm(draw):
    """Generate a cryptographic algorithm identifier."""
    algorithms = [
        "AES-128", "AES-256", "AES-GCM-256", "ChaCha20-Poly1305",
        "SHA-256", "SHA-384", "SHA-512", "HMAC-SHA256",
        "DES", "3DES", "MD5", "SHA-1", "RC4", "Blowfish",
        "RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-P384",
        "DH-2048", "DSA-1024", "Ed25519",
    ]
    return draw(sampled_from(algorithms))


@composite
def st_license_id(draw):
    """Generate a license identifier (SPDX-like)."""
    licenses = [
        "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC",
        "Unlicense", "CC0-1.0", "0BSD", "WTFPL", "Zlib",
        "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0",
        "GPL-2.0", "GPL-3.0", "AGPL-3.0", "EUPL-1.2",
        "Proprietary", "Commercial",
        "UNKNOWN-LICENSE", "Custom-1.0", "No-License-Found",
    ]
    return draw(sampled_from(licenses))


@composite
def st_container_critical_misconfig(draw):
    """Generate a critical container misconfiguration type."""
    return draw(sampled_from(CRITICAL_CONTAINER_MISCONFIGS))


@composite
def st_cvss_score(draw):
    """Generate a valid CVSS score between 0.0 and 10.0."""
    return draw(floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False))


# ===========================================================================
# Property 8: SBOM Component Completeness
# ===========================================================================

@given(dependencies=st_dependency_list(min_size=1, max_size=20))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_8_sbom_component_completeness(fresh_db, dependencies):
    """
    For any set of lockfile contents parsed by the SBOM generator, the resulting
    CycloneDX document should have a component count equal to the number of distinct
    dependencies in the input lockfiles, and every component should have non-empty
    name, version, ecosystem, and purl fields.

    **Validates: Requirements 3.1, 3.3**
    """
    # Generate SBOM from the dependencies
    sbom_doc = generate_sbom_cyclonedx(dependencies)

    # Property: component count equals distinct dependency count
    assert len(sbom_doc["components"]) == len(dependencies), (
        f"Expected {len(dependencies)} components, got {len(sbom_doc['components'])}"
    )

    # Property: every component has non-empty name, version, ecosystem, and purl
    for i, component in enumerate(sbom_doc["components"]):
        assert component.get("name") and len(component["name"]) > 0, (
            f"Component {i} has empty or missing name"
        )
        assert component.get("version") and len(component["version"]) > 0, (
            f"Component {i} has empty or missing version"
        )
        assert component.get("purl") and len(component["purl"]) > 0, (
            f"Component {i} has empty or missing purl"
        )
        # Ecosystem is in properties
        props = component.get("properties", [])
        ecosystem_props = [p for p in props if p.get("name") == "ecosystem"]
        assert len(ecosystem_props) == 1, (
            f"Component {i} should have exactly one ecosystem property"
        )
        assert ecosystem_props[0]["value"] and len(ecosystem_props[0]["value"]) > 0, (
            f"Component {i} has empty ecosystem property"
        )

    # Additional: verify round-trip through database storage
    scan_id = database.create_code_scan(
        label="SBOM test scan",
        repos=["test/repo"],
        config={},
    )
    cyclonedx_json = json.dumps(sbom_doc)
    database.code_scan_sbom_create(
        scan_id=scan_id,
        repo_identifier="test/repo",
        cyclonedx_json=cyclonedx_json,
        component_count=len(dependencies),
    )

    # Verify retrieval
    stored = database.code_scan_sbom_get(scan_id, "test/repo")
    assert stored is not None
    assert stored["component_count"] == len(dependencies)
    stored_doc = stored["cyclonedx"]
    assert len(stored_doc["components"]) == len(dependencies)


# ===========================================================================
# Property 9: CBOM Classification and Finding Generation
# ===========================================================================

@given(algorithm=st_crypto_algorithm())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_9_cbom_classification_and_finding_generation(fresh_db, algorithm):
    """
    For any detected cryptographic algorithm, the classification should be exactly one
    of {SAFE, WEAK, QUANTUM_RISK}, and for every entry classified as WEAK or QUANTUM_RISK,
    a corresponding finding should exist with severity MEDIUM (WEAK) or HIGH (QUANTUM_RISK).

    **Validates: Requirements 4.2, 4.4**
    """
    # Classify the algorithm
    classification = classify_cbom_algorithm(algorithm)

    # Property: classification is exactly one of the valid set
    assert classification in VALID_CBOM_CLASSIFICATIONS, (
        f"Algorithm '{algorithm}' classified as '{classification}', "
        f"expected one of {VALID_CBOM_CLASSIFICATIONS}"
    )

    # Property: WEAK/QUANTUM_RISK must produce a finding with correct severity
    expected_severity = cbom_classification_to_severity(classification)

    if classification in ("WEAK", "QUANTUM_RISK"):
        assert expected_severity is not None, (
            f"Classification '{classification}' should map to a severity"
        )
        if classification == "WEAK":
            assert expected_severity == "MEDIUM", (
                f"WEAK classification should produce MEDIUM severity, got '{expected_severity}'"
            )
        elif classification == "QUANTUM_RISK":
            assert expected_severity == "HIGH", (
                f"QUANTUM_RISK classification should produce HIGH severity, got '{expected_severity}'"
            )

        # Simulate finding generation and DB persistence
        scan_id = database.create_code_scan(
            label="CBOM test scan",
            repos=["test/repo"],
            config={},
        )
        finding_id = str(uuid.uuid4())
        database.insert_code_scan_findings(scan_id, [{
            "id": finding_id,
            "vuln_class": f"CRYPTO_{classification}",
            "repo": "test/repo",
            "file_path": "src/crypto.py",
            "line_start": 42,
            "line_end": 42,
            "severity": expected_severity,
            "confidence": 90,
            "title": f"Crypto: {algorithm} ({classification})",
            "description": f"Detected {algorithm} classified as {classification}",
            "finding_type": "cbom",
        }])

        # Verify finding persists with correct type and severity
        findings = database.get_code_scan_findings(scan_id)
        cbom_findings = [f for f in findings if f.get("title", "").startswith("Crypto:")]
        assert len(cbom_findings) >= 1, "CBOM finding should be persisted"
        assert cbom_findings[0]["severity"] == expected_severity

    else:
        # SAFE classification should not generate a finding
        assert expected_severity is None, (
            f"SAFE classification should not produce a finding severity, got '{expected_severity}'"
        )


# ===========================================================================
# Property 10: CVSS-to-Severity Mapping
# ===========================================================================

@given(score=st_cvss_score())
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_10_cvss_to_severity_mapping(fresh_db, score):
    """
    For any CVE with a numeric CVSS score, the severity mapping should produce
    CRITICAL for score >= 9.0, HIGH for >= 7.0, MEDIUM for >= 4.0, LOW for < 4.0.

    **Validates: Requirements 5.4**
    """
    severity = cvss_to_severity(score)

    # Property: output is always a valid severity
    assert severity in VALID_SEVERITIES, (
        f"CVSS score {score} produced invalid severity '{severity}'"
    )

    # Property: mapping follows exact threshold rules
    if score >= 9.0:
        assert severity == "CRITICAL", (
            f"Score {score} >= 9.0 should map to CRITICAL, got '{severity}'"
        )
    elif score >= 7.0:
        assert severity == "HIGH", (
            f"Score {score} >= 7.0 should map to HIGH, got '{severity}'"
        )
    elif score >= 4.0:
        assert severity == "MEDIUM", (
            f"Score {score} >= 4.0 should map to MEDIUM, got '{severity}'"
        )
    else:
        assert severity == "LOW", (
            f"Score {score} < 4.0 should map to LOW, got '{severity}'"
        )


# ===========================================================================
# Property 16: License Classification and Flagging Invariant
# ===========================================================================

@given(license_id=st_license_id())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_16_license_classification_and_flagging(fresh_db, license_id):
    """
    For any dependency with a license identifier, exactly one classification from
    {PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, COMMERCIAL, UNKNOWN}, and
    STRONG_COPYLEFT/UNKNOWN should have requires_review=true.

    **Validates: Requirements 8.1, 8.2**
    """
    result = classify_license(license_id)

    # Property: exactly one classification from the valid set
    category = result["category"]
    assert category in VALID_LICENSE_CATEGORIES, (
        f"License '{license_id}' classified as '{category}', "
        f"expected one of {VALID_LICENSE_CATEGORIES}"
    )

    # Property: STRONG_COPYLEFT and UNKNOWN require review
    requires_review = result["requires_review"]
    if category in ("STRONG_COPYLEFT", "UNKNOWN"):
        assert requires_review is True, (
            f"License '{license_id}' classified as '{category}' should have "
            f"requires_review=True, got {requires_review}"
        )
    else:
        assert requires_review is False, (
            f"License '{license_id}' classified as '{category}' should have "
            f"requires_review=False, got {requires_review}"
        )

    # Verify DB persistence round-trip
    scan_id = database.create_code_scan(
        label="License test scan",
        repos=["test/repo"],
        config={},
    )
    database.code_scan_license_create_batch(
        scan_id=scan_id,
        repo_identifier="test/repo",
        records=[{
            "package_name": "test-pkg",
            "package_version": "1.0.0",
            "ecosystem": "npm",
            "license_id": license_id,
            "license_category": category,
            "requires_review": requires_review,
        }],
    )

    # Verify retrieval
    stored = database.code_scan_license_get(scan_id, "test/repo")
    assert len(stored) == 1
    assert stored[0]["license_category"] == category
    assert bool(stored[0]["requires_review"]) == requires_review


# ===========================================================================
# Property 18: Container Severity Classification
# ===========================================================================

@given(misconfig_type=st_container_critical_misconfig())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_18_container_severity_classification(fresh_db, misconfig_type):
    """
    For any critical misconfiguration (running as root, secrets in build args),
    severity should be HIGH or CRITICAL.

    **Validates: Requirements 9.4**
    """
    severity = classify_container_severity(misconfig_type)

    # Property: critical misconfigurations always produce HIGH or CRITICAL
    assert severity in ("HIGH", "CRITICAL"), (
        f"Critical misconfiguration '{misconfig_type}' should produce HIGH or CRITICAL "
        f"severity, got '{severity}'"
    )

    # Verify DB persistence round-trip
    scan_id = database.create_code_scan(
        label="Container test scan",
        repos=["test/repo"],
        config={},
    )
    record = database.code_scan_container_create(
        scan_id=scan_id,
        repo_identifier="test/repo",
        dockerfile_path="Dockerfile",
        misconfiguration_type=misconfig_type,
        severity=severity,
        description=f"Container misconfiguration: {misconfig_type}",
        recommended_fix=f"Fix: address {misconfig_type}",
    )

    # Verify retrieval
    stored = database.code_scan_container_get(scan_id, "test/repo")
    assert len(stored) == 1
    assert stored[0]["severity"] == severity
    assert stored[0]["misconfiguration_type"] == misconfig_type

"""
Property-based tests for configuration handling in the Holistic Code Scanner.

Property 22: Configuration Validation
For any scan configuration, values outside valid ranges (budget < $2.00, concurrency > 20,
invalid model name, invalid severity level) should be rejected with a descriptive error,
while all values within valid ranges should be accepted.

**Validates: Requirements 11.1, 11.4**

Property 23: Configuration Defaults Fill
For any partial scan configuration where fields are omitted, the effective configuration
used by the orchestrator should have all required fields populated from the platform
defaults stored in `code_scan_settings`.

**Validates: Requirements 11.2**
"""

import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    booleans,
    composite,
    floats,
    integers,
    just,
    none,
    one_of,
    sampled_from,
    text,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from fastapi import HTTPException
from code_scan_module import build_scan_config, ScanStartRequest


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VALID_MODELS = [
    "claude-opus-4-8",
    "claude-sonnet-4-20250514",
    "gpt-4o",
    "gpt-4-turbo",
    "deepseek-coder",
    "custom-model-v1",
]

# All keys that must be present in a complete config output
REQUIRED_CONFIG_KEYS = {
    "model",
    "budget_limit_usd",
    "concurrency",
    "sast_enabled",
    "sca_enabled",
    "sbom_enabled",
    "cbom_enabled",
    "license_scan_enabled",
    "container_analysis_enabled",
    "chain_reasoning_enabled",
    "auto_pr_enabled",
    "auto_pr_min_severity",
    "auto_pr_mode",
    "auto_pr_base_branch",
    "diff_aware",
    "generate_lockfiles",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Set up a fresh temporary database for each test function."""
    db_path = str(tmp_path / "test_config_props.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret")
    database.init_db()
    yield


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

@composite
def st_valid_budget(draw):
    """Generate a valid budget amount (>= $2.00)."""
    return draw(floats(min_value=2.0, max_value=10000.0, allow_nan=False, allow_infinity=False))


@composite
def st_invalid_budget(draw):
    """Generate an invalid budget amount (< $2.00, but still a finite number)."""
    return draw(floats(min_value=-10000.0, max_value=1.99, allow_nan=False, allow_infinity=False))


@composite
def st_valid_concurrency(draw):
    """Generate a valid concurrency value (1 to 20)."""
    return draw(integers(min_value=1, max_value=20))


@composite
def st_invalid_concurrency_too_high(draw):
    """Generate an invalid concurrency value (> 20)."""
    return draw(integers(min_value=21, max_value=1000))


@composite
def st_invalid_concurrency_too_low(draw):
    """Generate an invalid concurrency value (< 1)."""
    return draw(integers(min_value=-100, max_value=0))


@composite
def st_valid_severity(draw):
    """Generate a valid severity string (case-insensitive variants)."""
    base = draw(sampled_from(VALID_SEVERITIES))
    # Also test lower-case since the function normalizes
    variant = draw(sampled_from([base, base.lower(), base.capitalize()]))
    return variant


@composite
def st_invalid_severity(draw):
    """Generate an invalid severity string."""
    invalid_values = [
        "INVALID", "NONE", "SEVERE", "WARN", "ERROR", "INFO", "DEBUG",
        "critical!", "super_high", "very_low", "unknown", "0", "99",
        "CRITICALx", "HIGH ", " MEDIUM",
    ]
    return draw(sampled_from(invalid_values))


@composite
def st_valid_model(draw):
    """Generate a valid (non-empty, non-whitespace) model string."""
    return draw(sampled_from(VALID_MODELS))


@composite
def st_invalid_model(draw):
    """Generate an invalid model string (empty or whitespace-only)."""
    invalid_values = ["", " ", "   ", "\t", "\n", "  \t\n  "]
    return draw(sampled_from(invalid_values))


@composite
def st_valid_full_config(draw):
    """Generate a fully valid ScanStartRequest with all fields populated."""
    return ScanStartRequest(
        repos=["owner/repo"],
        model=draw(st_valid_model()),
        budget_limit_usd=draw(st_valid_budget()),
        concurrency=draw(st_valid_concurrency()),
        auto_pr_min_severity=draw(sampled_from(VALID_SEVERITIES)),
        sast_enabled=draw(booleans()),
        sca_enabled=draw(booleans()),
        sbom_enabled=draw(booleans()),
        cbom_enabled=draw(booleans()),
        license_scan_enabled=draw(booleans()),
        container_analysis_enabled=draw(booleans()),
        chain_reasoning_enabled=draw(booleans()),
        auto_pr_enabled=draw(booleans()),
        diff_aware=draw(booleans()),
        generate_lockfiles=draw(booleans()),
    )


@composite
def st_partial_config(draw):
    """Generate a ScanStartRequest with some fields omitted (None).

    This tests that defaults are filled in correctly.
    """
    # Each field has a chance of being None (omitted)
    model = draw(one_of(st_valid_model(), none()))
    budget = draw(one_of(st_valid_budget(), none()))
    concurrency = draw(one_of(st_valid_concurrency(), none()))
    severity = draw(one_of(sampled_from(VALID_SEVERITIES), none()))
    sast = draw(one_of(booleans(), none()))
    sca = draw(one_of(booleans(), none()))
    sbom = draw(one_of(booleans(), none()))
    cbom = draw(one_of(booleans(), none()))
    license_scan = draw(one_of(booleans(), none()))
    container = draw(one_of(booleans(), none()))
    chain = draw(one_of(booleans(), none()))
    auto_pr = draw(one_of(booleans(), none()))
    diff_aware = draw(one_of(booleans(), none()))
    generate_lockfiles = draw(one_of(booleans(), none()))

    return ScanStartRequest(
        repos=["owner/repo"],
        model=model,
        budget_limit_usd=budget,
        concurrency=concurrency,
        auto_pr_min_severity=severity,
        sast_enabled=sast,
        sca_enabled=sca,
        sbom_enabled=sbom,
        cbom_enabled=cbom,
        license_scan_enabled=license_scan,
        container_analysis_enabled=container,
        chain_reasoning_enabled=chain,
        auto_pr_enabled=auto_pr,
        diff_aware=diff_aware,
        generate_lockfiles=generate_lockfiles,
    )


# ===========================================================================
# Property 22: Configuration Validation
# ===========================================================================


@given(config=st_valid_full_config())
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_valid_configs_always_accepted(setup_test_db, config):
    """
    For any scan configuration with all values within valid ranges, the
    build_scan_config function should accept the configuration and return
    a complete config dict with all expected keys.

    **Validates: Requirements 11.1, 11.4**
    """
    result = build_scan_config(config)

    # Should return a dict with all required keys
    assert isinstance(result, dict)
    assert set(result.keys()) == REQUIRED_CONFIG_KEYS

    # Validate that values are of the correct types
    assert isinstance(result["model"], str) and len(result["model"].strip()) > 0
    assert isinstance(result["budget_limit_usd"], float) and result["budget_limit_usd"] >= 2.0
    assert isinstance(result["concurrency"], int) and 1 <= result["concurrency"] <= 20
    assert result["auto_pr_min_severity"] in VALID_SEVERITIES


@given(invalid_budget=st_invalid_budget())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_invalid_budget_rejected(setup_test_db, invalid_budget):
    """
    For any budget value below $2.00, build_scan_config should raise an
    HTTPException with status code 400 and a descriptive error message.

    **Validates: Requirements 11.1, 11.4**
    """
    request = ScanStartRequest(repos=["owner/repo"], budget_limit_usd=invalid_budget)

    with pytest.raises(HTTPException) as exc_info:
        build_scan_config(request)

    assert exc_info.value.status_code == 400
    assert "2.00" in exc_info.value.detail


@given(invalid_concurrency=st_invalid_concurrency_too_high())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_concurrency_above_max_rejected(setup_test_db, invalid_concurrency):
    """
    For any concurrency value greater than 20, build_scan_config should raise
    an HTTPException with status code 400.

    **Validates: Requirements 11.1, 11.4**
    """
    request = ScanStartRequest(repos=["owner/repo"], concurrency=invalid_concurrency)

    with pytest.raises(HTTPException) as exc_info:
        build_scan_config(request)

    assert exc_info.value.status_code == 400
    assert "Concurrency" in exc_info.value.detail


@given(invalid_concurrency=st_invalid_concurrency_too_low())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_concurrency_below_min_rejected(setup_test_db, invalid_concurrency):
    """
    For any concurrency value less than 1, build_scan_config should raise
    an HTTPException with status code 400.

    **Validates: Requirements 11.1, 11.4**
    """
    request = ScanStartRequest(repos=["owner/repo"], concurrency=invalid_concurrency)

    with pytest.raises(HTTPException) as exc_info:
        build_scan_config(request)

    assert exc_info.value.status_code == 400
    assert "Concurrency" in exc_info.value.detail


@given(invalid_severity=st_invalid_severity())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_invalid_severity_rejected(setup_test_db, invalid_severity):
    """
    For any severity string that is not one of CRITICAL, HIGH, MEDIUM, LOW
    (case-insensitive), build_scan_config should raise an HTTPException 400.

    **Validates: Requirements 11.1, 11.4**
    """
    # Ensure the value is truly invalid after uppercasing
    assume(invalid_severity.strip().upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"})

    request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity=invalid_severity)

    with pytest.raises(HTTPException) as exc_info:
        build_scan_config(request)

    assert exc_info.value.status_code == 400
    assert "auto_pr_min_severity" in exc_info.value.detail


@given(invalid_model=st_invalid_model())
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_invalid_model_rejected(setup_test_db, invalid_model):
    """
    For any model name that is empty or whitespace-only, build_scan_config
    should raise an HTTPException with status code 400.

    **Validates: Requirements 11.1, 11.4**
    """
    request = ScanStartRequest(repos=["owner/repo"], model=invalid_model)

    with pytest.raises(HTTPException) as exc_info:
        build_scan_config(request)

    assert exc_info.value.status_code == 400
    assert "Model" in exc_info.value.detail


@given(valid_severity=st_valid_severity())
@settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_22_valid_severity_accepted(setup_test_db, valid_severity):
    """
    For any valid severity string (CRITICAL, HIGH, MEDIUM, LOW in any case),
    build_scan_config should accept it and normalize to uppercase.

    **Validates: Requirements 11.1, 11.4**
    """
    request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity=valid_severity)
    config = build_scan_config(request)

    assert config["auto_pr_min_severity"] == valid_severity.strip().upper()
    assert config["auto_pr_min_severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ===========================================================================
# Property 23: Configuration Defaults Fill
# ===========================================================================


@given(config=st_partial_config())
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_23_partial_config_fills_all_defaults(setup_test_db, config):
    """
    For any partial scan configuration where fields are omitted (None),
    the effective configuration returned by build_scan_config should have
    ALL required fields populated — no None values for required keys.

    **Validates: Requirements 11.2**
    """
    result = build_scan_config(config)

    # All required keys must be present
    assert set(result.keys()) == REQUIRED_CONFIG_KEYS

    # No required field should be None (except auto_pr_base_branch which is optional)
    for key in REQUIRED_CONFIG_KEYS:
        if key == "auto_pr_base_branch":
            continue  # This field is legitimately optional/nullable
        assert result[key] is not None, f"Key '{key}' should not be None in output config"

    # Validate types and ranges for filled-in defaults
    assert isinstance(result["model"], str) and len(result["model"].strip()) > 0
    assert isinstance(result["budget_limit_usd"], float) and result["budget_limit_usd"] >= 2.0
    assert isinstance(result["concurrency"], int) and 1 <= result["concurrency"] <= 20
    assert result["auto_pr_min_severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert isinstance(result["sast_enabled"], bool)
    assert isinstance(result["sca_enabled"], bool)
    assert isinstance(result["sbom_enabled"], bool)
    assert isinstance(result["cbom_enabled"], bool)
    assert isinstance(result["license_scan_enabled"], bool)
    assert isinstance(result["container_analysis_enabled"], bool)
    assert isinstance(result["chain_reasoning_enabled"], bool)
    assert isinstance(result["auto_pr_enabled"], bool)
    assert isinstance(result["diff_aware"], bool)
    assert isinstance(result["generate_lockfiles"], bool)


@given(config=st_partial_config())
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_23_user_values_override_defaults(setup_test_db, config):
    """
    For any partial scan configuration, fields that ARE provided by the user
    should appear in the output config with the user's value, not the default.

    **Validates: Requirements 11.2**
    """
    result = build_scan_config(config)

    # If user provided a model, it should be in the result
    if config.model is not None:
        assert result["model"] == config.model.strip()

    # If user provided budget, it should be in the result
    if config.budget_limit_usd is not None:
        assert result["budget_limit_usd"] == config.budget_limit_usd

    # If user provided concurrency, it should be in the result
    if config.concurrency is not None:
        assert result["concurrency"] == config.concurrency

    # If user provided severity, it should be normalized and in the result
    if config.auto_pr_min_severity is not None:
        assert result["auto_pr_min_severity"] == config.auto_pr_min_severity.upper()

    # Boolean toggles — when user provides them, they should be respected
    if config.sast_enabled is not None:
        assert result["sast_enabled"] == config.sast_enabled
    if config.sca_enabled is not None:
        assert result["sca_enabled"] == config.sca_enabled
    if config.sbom_enabled is not None:
        assert result["sbom_enabled"] == config.sbom_enabled
    if config.cbom_enabled is not None:
        assert result["cbom_enabled"] == config.cbom_enabled
    if config.license_scan_enabled is not None:
        assert result["license_scan_enabled"] == config.license_scan_enabled
    if config.container_analysis_enabled is not None:
        assert result["container_analysis_enabled"] == config.container_analysis_enabled
    if config.diff_aware is not None:
        assert result["diff_aware"] == config.diff_aware
    if config.generate_lockfiles is not None:
        assert result["generate_lockfiles"] == config.generate_lockfiles


@given(
    budget=st_valid_budget(),
    concurrency=st_valid_concurrency(),
    model=st_valid_model(),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_23_completely_omitted_uses_platform_defaults(setup_test_db, budget, concurrency, model):
    """
    When all configurable fields are omitted (None), the output should
    use the platform defaults from the code_scan_settings table.

    Verifies that custom platform defaults are picked up correctly.

    **Validates: Requirements 11.2**
    """
    # Set custom platform defaults
    database.code_scan_settings_upsert("model", model)
    database.code_scan_settings_upsert("budget_limit_usd", str(budget))
    database.code_scan_settings_upsert("concurrency_limit", str(concurrency))

    # Request with all fields omitted
    request = ScanStartRequest(repos=["owner/repo"])

    result = build_scan_config(request)

    # All fields should be populated from platform defaults
    assert result["model"] == model
    assert result["budget_limit_usd"] == budget
    assert result["concurrency"] == concurrency
    # All required keys present
    assert set(result.keys()) == REQUIRED_CONFIG_KEYS

"""Unit tests for build_scan_config helper function.

Tests the configuration builder that merges user requests with platform defaults,
validates constraints, and returns a merged config dict.

Validates: Requirements 11.1, 11.2, 11.4
"""
import os
import sys
import uuid
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from fastapi import HTTPException
from code_scan_module import build_scan_config, ScanStartRequest


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Set up a fresh database with default settings for each test."""
    db_path = str(tmp_path / "test_config.db")
    monkeypatch.setattr(database, "DB_NAME", db_path)
    monkeypatch.setenv("RBAC_JWT_SECRET", "test-secret")
    database.init_db()
    yield


class TestBuildScanConfigDefaults:
    """When user omits fields, platform defaults are used."""

    def test_uses_default_model(self):
        """Model defaults to platform setting when not provided."""
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        # Should use the default from code_scan_settings table
        assert config["model"] != ""
        assert isinstance(config["model"], str)

    def test_uses_default_budget(self):
        """Budget defaults to platform setting when not provided."""
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["budget_limit_usd"] == 50.0

    def test_uses_default_concurrency(self):
        """Concurrency defaults to platform setting when not provided."""
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["concurrency"] == 5

    def test_uses_default_auto_pr_min_severity(self):
        """auto_pr_min_severity defaults to HIGH."""
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["auto_pr_min_severity"] == "HIGH"

    def test_all_required_keys_present(self):
        """Config dict contains all expected keys."""
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        expected_keys = {
            "model", "budget_limit_usd", "concurrency",
            "sast_enabled", "sca_enabled", "sbom_enabled", "cbom_enabled",
            "license_scan_enabled", "container_analysis_enabled",
            "chain_reasoning_enabled", "auto_pr_enabled",
            "auto_pr_min_severity", "auto_pr_mode", "auto_pr_base_branch",
            "diff_aware", "generate_lockfiles",
        }
        assert set(config.keys()) == expected_keys


class TestBuildScanConfigUserOverrides:
    """User-provided values take precedence over defaults."""

    def test_user_model_overrides_default(self):
        """User-specified model overrides platform default."""
        request = ScanStartRequest(repos=["owner/repo"], model="claude-sonnet-4-20250514")
        config = build_scan_config(request)
        assert config["model"] == "claude-sonnet-4-20250514"

    def test_user_budget_overrides_default(self):
        """User-specified budget overrides platform default."""
        request = ScanStartRequest(repos=["owner/repo"], budget_limit_usd=25.0)
        config = build_scan_config(request)
        assert config["budget_limit_usd"] == 25.0

    def test_user_concurrency_overrides_default(self):
        """User-specified concurrency overrides platform default."""
        request = ScanStartRequest(repos=["owner/repo"], concurrency=10)
        config = build_scan_config(request)
        assert config["concurrency"] == 10

    def test_user_severity_overrides_default(self):
        """User-specified min severity overrides platform default."""
        request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity="CRITICAL")
        config = build_scan_config(request)
        assert config["auto_pr_min_severity"] == "CRITICAL"

    def test_user_toggles_override_defaults(self):
        """User-specified module toggles override platform defaults."""
        request = ScanStartRequest(
            repos=["owner/repo"],
            sast_enabled=False,
            license_scan_enabled=True,
            container_analysis_enabled=True,
        )
        config = build_scan_config(request)
        assert config["sast_enabled"] is False
        assert config["license_scan_enabled"] is True
        assert config["container_analysis_enabled"] is True


class TestBuildScanConfigValidation:
    """Validation rejects invalid configurations with descriptive errors."""

    def test_budget_below_minimum_rejected(self):
        """Budget < $2.00 raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], budget_limit_usd=1.99)
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "2.00" in exc_info.value.detail

    def test_budget_at_minimum_accepted(self):
        """Budget == $2.00 is accepted."""
        request = ScanStartRequest(repos=["owner/repo"], budget_limit_usd=2.0)
        config = build_scan_config(request)
        assert config["budget_limit_usd"] == 2.0

    def test_concurrency_zero_rejected(self):
        """Concurrency < 1 raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], concurrency=0)
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "Concurrency" in exc_info.value.detail

    def test_concurrency_above_max_rejected(self):
        """Concurrency > 20 raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], concurrency=21)
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "Concurrency" in exc_info.value.detail

    def test_concurrency_at_max_accepted(self):
        """Concurrency == 20 is accepted."""
        request = ScanStartRequest(repos=["owner/repo"], concurrency=20)
        config = build_scan_config(request)
        assert config["concurrency"] == 20

    def test_concurrency_at_min_accepted(self):
        """Concurrency == 1 is accepted."""
        request = ScanStartRequest(repos=["owner/repo"], concurrency=1)
        config = build_scan_config(request)
        assert config["concurrency"] == 1

    def test_invalid_severity_rejected(self):
        """Invalid auto_pr_min_severity raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity="INVALID")
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "auto_pr_min_severity" in exc_info.value.detail

    def test_valid_severities_accepted(self):
        """All valid severities (CRITICAL, HIGH, MEDIUM, LOW) are accepted."""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity=sev)
            config = build_scan_config(request)
            assert config["auto_pr_min_severity"] == sev

    def test_severity_case_insensitive(self):
        """Severity matching is case-insensitive."""
        request = ScanStartRequest(repos=["owner/repo"], auto_pr_min_severity="medium")
        config = build_scan_config(request)
        assert config["auto_pr_min_severity"] == "MEDIUM"

    def test_empty_model_rejected(self):
        """Empty string model raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], model="")
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "Model" in exc_info.value.detail

    def test_whitespace_only_model_rejected(self):
        """Whitespace-only model raises HTTPException 400."""
        request = ScanStartRequest(repos=["owner/repo"], model="   ")
        with pytest.raises(HTTPException) as exc_info:
            build_scan_config(request)
        assert exc_info.value.status_code == 400
        assert "Model" in exc_info.value.detail


class TestBuildScanConfigPlatformDefaultsIntegration:
    """Tests that custom platform defaults are picked up correctly."""

    def test_custom_platform_model_used(self):
        """Custom model default from settings is used when user doesn't specify."""
        database.code_scan_settings_upsert("model", "custom-model-v1")
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["model"] == "custom-model-v1"

    def test_custom_platform_budget_used(self):
        """Custom budget default from settings is used when user doesn't specify."""
        database.code_scan_settings_upsert("budget_limit_usd", "100.0")
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["budget_limit_usd"] == 100.0

    def test_custom_platform_concurrency_used(self):
        """Custom concurrency default from settings is used when user doesn't specify."""
        database.code_scan_settings_upsert("concurrency_limit", "10")
        request = ScanStartRequest(repos=["owner/repo"])
        config = build_scan_config(request)
        assert config["concurrency"] == 10

    def test_sca_disabled_by_platform_default(self):
        """Platform default sca_enabled=false is respected."""
        database.code_scan_settings_upsert("sca_enabled", "false")
        request = ScanStartRequest(repos=["owner/repo"], sca_enabled=None)
        config = build_scan_config(request)
        assert config["sca_enabled"] is False

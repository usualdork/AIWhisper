"""
Property-based tests for the Auto-PR integration.

Property 14: Auto-PR Generates Diffs for Qualifying Findings
For any scan with auto_pr enabled and findings at or above the configured minimum
severity, the Auto_PR_Publisher should produce at least one patch diff for each repo
containing qualifying findings.

**Validates: Requirements 7.1**

Property 15: Patch Syntax Validation
For any generated patch, the syntax validator should correctly accept valid patches
and reject invalid ones (ast.parse for Python, json.loads for JSON, yaml.safe_load
for YAML, bracket-balance for JS/TS/Go).

**Validates: Requirements 7.2**
"""

import json
import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    composite,
    dictionaries,
    from_regex,
    integers,
    just,
    lists,
    one_of,
    sampled_from,
    text,
    booleans,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from code_scan_module import validate_patch_syntax, auto_pr_phase


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

@composite
def valid_python_code(draw):
    """Generate syntactically valid Python code snippets."""
    templates = [
        "x = {val}",
        "def f():\n    return {val}",
        "class C:\n    pass",
        "import os",
        "a = [{val}, {val2}]",
        "if True:\n    x = {val}",
        "for i in range({val}):\n    pass",
        "print({val})",
    ]
    template = draw(sampled_from(templates))
    val = draw(integers(min_value=0, max_value=1000))
    val2 = draw(integers(min_value=0, max_value=1000))
    return template.format(val=val, val2=val2)


@composite
def invalid_python_code(draw):
    """Generate syntactically invalid Python code snippets."""
    snippets = [
        "def f(\n    x = ",
        "class :",
        "if True\n    pass",
        "for in range(10):",
        "def (x):",
        "import ",
        "return return return",
        "def f():\n  return\n x",
        "( [ { ) ] }",
        "def f(x,,y):",
    ]
    return draw(sampled_from(snippets))


@composite
def valid_json_code(draw):
    """Generate syntactically valid JSON strings."""
    templates = [
        '{{"key": {val}}}',
        '[{val}, {val2}]',
        '{{"name": "test", "value": {val}}}',
        '"{text}"',
        'null',
        'true',
        'false',
        '{val}',
    ]
    template = draw(sampled_from(templates))
    val = draw(integers(min_value=0, max_value=1000))
    val2 = draw(integers(min_value=0, max_value=1000))
    t = draw(sampled_from(["hello", "world", "test", "data"]))
    return template.format(val=val, val2=val2, text=t)


@composite
def invalid_json_code(draw):
    """Generate syntactically invalid JSON strings."""
    snippets = [
        "{key: value}",
        "{'key': 'value'}",
        "{\"key\": }",
        "[1, 2, ]",
        "{\"unclosed: true",
        "undefined",
        "{\"a\": 1,}",
    ]
    return draw(sampled_from(snippets))


@composite
def valid_yaml_code(draw):
    """Generate syntactically valid YAML strings."""
    templates = [
        "key: {val}",
        "items:\n  - {val}\n  - {val2}",
        "name: test\nvalue: {val}",
        "---\nkey: value",
        "a: true\nb: false",
    ]
    template = draw(sampled_from(templates))
    val = draw(integers(min_value=0, max_value=1000))
    val2 = draw(integers(min_value=0, max_value=1000))
    return template.format(val=val, val2=val2)


@composite
def invalid_yaml_code(draw):
    """Generate syntactically invalid YAML strings."""
    snippets = [
        "key: [unclosed",
        ":\n  - :\n  -: :\n:: :",
        "{{invalid}}",
        "a: *undefined_anchor",
    ]
    return draw(sampled_from(snippets))


@composite
def valid_js_code(draw):
    """Generate bracket-balanced JS/TS/Go code."""
    templates = [
        "function f() {{ return {val}; }}",
        "const x = [{val}, {val2}];",
        "if (true) {{ console.log({val}); }}",
        "(function() {{ return {val}; }})()",
        "const obj = {{ a: {val}, b: {val2} }};",
    ]
    template = draw(sampled_from(templates))
    val = draw(integers(min_value=0, max_value=1000))
    val2 = draw(integers(min_value=0, max_value=1000))
    return template.format(val=val, val2=val2)


@composite
def invalid_js_code(draw):
    """Generate bracket-unbalanced code."""
    snippets = [
        "function f() { return 1; ",
        "const x = [1, 2;",
        "if (true { }",
        "(((",
        "}}}}",
        "[[[",
        "function() { if (x) { }",
        "const x = {a: [1, 2}];",
    ]
    return draw(sampled_from(snippets))


@composite
def repo_identifier_strategy(draw):
    """Generate repository identifiers like owner/repo."""
    owner = draw(sampled_from(["acme", "corp", "myorg", "testco", "devops"]))
    repo = draw(sampled_from(["api", "web", "service", "lib", "infra", "app"]))
    suffix = draw(integers(min_value=1, max_value=99))
    return f"{owner}/{repo}-{suffix}"


@composite
def finding_strategy(draw, severity=None, repo_identifier=None):
    """Generate a scan finding dict."""
    sev = severity or draw(sampled_from(SEVERITIES))
    repo = repo_identifier or draw(repo_identifier_strategy())
    finding_id = str(uuid.uuid4())
    file_ext = draw(sampled_from([".py", ".js", ".json", ".yaml", ".go", ".ts"]))
    return {
        "id": finding_id,
        "scan_id": "",  # filled at insert time
        "severity": sev,
        "title": f"Finding {finding_id[:8]}",
        "description": "Test finding for auto-PR",
        "file_path": f"src/main{file_ext}",
        "line_number": draw(integers(min_value=1, max_value=500)),
        "vuln_class": "INJECTION",
        "owasp_category": "A03",
        "finding_type": "sast",
        "repo_identifier": repo,
        "repo": repo,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_database():
    """Initialize a fresh test database for each test."""
    database.DB_PATH = ":memory:"
    database._connection_cache = {}
    database.init_db()
    yield
    database._connection_cache = {}


# ---------------------------------------------------------------------------
# Property 14: Auto-PR Generates Diffs for Qualifying Findings
# ---------------------------------------------------------------------------

class TestProperty14AutoPRGeneratesDiffs:
    """
    **Validates: Requirements 7.1**

    For any scan with auto_pr enabled and findings at or above the configured
    minimum severity, the Auto_PR_Publisher should produce at least one patch
    diff (PR record) for each repo containing qualifying findings.
    """

    @given(
        min_severity=sampled_from(SEVERITIES),
        repo_count=integers(min_value=1, max_value=5),
        findings_per_repo=integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_auto_pr_generates_pr_records_for_qualifying_repos(
        self, min_severity, repo_count, findings_per_repo, setup_database
    ):
        """
        Property: When auto_pr is enabled and findings exist at/above min severity,
        at least one PR record is created for each repo with qualifying findings.
        """
        # Create a scan
        scan_id = database.create_code_scan(
            label="Auto-PR test scan",
            repos=[f"org/repo-{i}" for i in range(repo_count)],
            config={"auto_pr_enabled": True, "auto_pr_min_severity": min_severity},
        )

        min_rank = SEVERITY_RANK[min_severity]

        # Insert findings that qualify (at or above min severity)
        repos_with_qualifying = set()
        for i in range(repo_count):
            repo = f"org/repo-{i}"
            for j in range(findings_per_repo):
                # Use a severity that qualifies
                sev = min_severity  # exactly at threshold
                finding_id = str(uuid.uuid4())
                database.insert_code_scan_findings(scan_id, [{
                    "id": finding_id,
                    "vuln_class": "INJECTION",
                    "repo": repo,
                    "file_path": "src/app.py",
                    "line_start": 10 + j,
                    "line_end": 10 + j,
                    "severity": sev,
                    "confidence": 90,
                    "title": f"Finding {j}",
                    "description": "Test",
                    "finding_type": "sast",
                }])
                # Update finding with repo_identifier
                database.code_scan_finding_update_type(
                    finding_id=finding_id,
                    finding_type="sast",
                    repo_identifier=repo,
                )
                repos_with_qualifying.add(repo)

        # Run auto_pr_phase
        config = {
            "auto_pr_enabled": True,
            "auto_pr_min_severity": min_severity,
        }
        auto_pr_phase(scan_id, config)

        # Verify: at least one PR record per repo with qualifying findings
        prs = database.code_scan_pr_get_by_scan_id(scan_id)
        repos_with_prs = {pr["repo_identifier"] for pr in prs}

        for repo in repos_with_qualifying:
            assert repo in repos_with_prs, (
                f"Expected PR record for {repo} but found none. "
                f"PRs created for: {repos_with_prs}"
            )

    @given(
        min_severity=sampled_from(["CRITICAL", "HIGH"]),
        repo_count=integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_auto_pr_skips_when_disabled(self, min_severity, repo_count, setup_database):
        """
        Property: When auto_pr_enabled is False, no PR records are created.
        """
        scan_id = database.create_code_scan(
            label="Auto-PR disabled test",
            repos=[f"org/repo-{i}" for i in range(repo_count)],
            config={"auto_pr_enabled": False},
        )

        # Insert qualifying findings
        for i in range(repo_count):
            repo = f"org/repo-{i}"
            finding_id = str(uuid.uuid4())
            database.insert_code_scan_findings(scan_id, [{
                "id": finding_id,
                "vuln_class": "XSS",
                "repo": repo,
                "file_path": "src/index.js",
                "line_start": 5,
                "line_end": 5,
                "severity": "CRITICAL",
                "confidence": 95,
                "title": "Critical XSS",
                "description": "Test",
                "finding_type": "sast",
            }])
            database.code_scan_finding_update_type(
                finding_id=finding_id,
                finding_type="sast",
                repo_identifier=repo,
            )

        # Run auto_pr_phase with disabled
        config = {
            "auto_pr_enabled": False,
            "auto_pr_min_severity": min_severity,
        }
        auto_pr_phase(scan_id, config)

        # Verify: no PR records created
        prs = database.code_scan_pr_get_by_scan_id(scan_id)
        assert len(prs) == 0, "No PRs should be created when auto_pr is disabled"

    @given(
        min_severity=sampled_from(["CRITICAL", "HIGH"]),
    )
    @settings(
        max_examples=20,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_auto_pr_skips_findings_below_min_severity(self, min_severity, setup_database):
        """
        Property: Findings below minimum severity do not trigger PR creation.
        """
        scan_id = database.create_code_scan(
            label="Auto-PR severity filter test",
            repos=["org/low-sev-repo"],
            config={"auto_pr_enabled": True, "auto_pr_min_severity": min_severity},
        )

        # Insert only LOW severity findings (below any configured min)
        finding_id = str(uuid.uuid4())
        database.insert_code_scan_findings(scan_id, [{
            "id": finding_id,
            "vuln_class": "INFO",
            "repo": "org/low-sev-repo",
            "file_path": "src/util.py",
            "line_start": 1,
            "line_end": 1,
            "severity": "LOW",
            "confidence": 50,
            "title": "Low finding",
            "description": "Test",
            "finding_type": "sast",
        }])
        database.code_scan_finding_update_type(
            finding_id=finding_id,
            finding_type="sast",
            repo_identifier="org/low-sev-repo",
        )

        config = {
            "auto_pr_enabled": True,
            "auto_pr_min_severity": min_severity,
        }
        auto_pr_phase(scan_id, config)

        prs = database.code_scan_pr_get_by_scan_id(scan_id)
        assert len(prs) == 0, (
            f"No PRs should be created when findings are below {min_severity}"
        )


# ---------------------------------------------------------------------------
# Property 15: Patch Syntax Validation
# ---------------------------------------------------------------------------

class TestProperty15PatchSyntaxValidation:
    """
    **Validates: Requirements 7.2**

    For any generated patch, the syntax validator should correctly accept valid
    patches and reject invalid ones (ast.parse for Python, json.loads for JSON,
    yaml.safe_load for YAML, bracket-balance for JS/TS/Go).
    """

    @given(code=valid_python_code())
    @settings(max_examples=50, deadline=None)
    def test_valid_python_accepted(self, code):
        """Valid Python code should pass syntax validation."""
        assert validate_patch_syntax(code, "python") is True

    @given(code=invalid_python_code())
    @settings(max_examples=50, deadline=None)
    def test_invalid_python_rejected(self, code):
        """Invalid Python code should fail syntax validation."""
        assert validate_patch_syntax(code, "python") is False

    @given(code=valid_json_code())
    @settings(max_examples=50, deadline=None)
    def test_valid_json_accepted(self, code):
        """Valid JSON code should pass syntax validation."""
        assert validate_patch_syntax(code, "json") is True

    @given(code=invalid_json_code())
    @settings(max_examples=50, deadline=None)
    def test_invalid_json_rejected(self, code):
        """Invalid JSON code should fail syntax validation."""
        assert validate_patch_syntax(code, "json") is False

    @given(code=valid_yaml_code())
    @settings(max_examples=50, deadline=None)
    def test_valid_yaml_accepted(self, code):
        """Valid YAML code should pass syntax validation."""
        assert validate_patch_syntax(code, "yaml") is True

    @given(code=invalid_yaml_code())
    @settings(max_examples=50, deadline=None)
    def test_invalid_yaml_rejected(self, code):
        """Invalid YAML code should fail syntax validation."""
        assert validate_patch_syntax(code, "yaml") is False

    @given(code=valid_js_code())
    @settings(max_examples=50, deadline=None)
    def test_valid_js_accepted(self, code):
        """Bracket-balanced JS code should pass syntax validation."""
        assert validate_patch_syntax(code, "javascript") is True

    @given(code=invalid_js_code())
    @settings(max_examples=50, deadline=None)
    def test_invalid_js_rejected(self, code):
        """Bracket-unbalanced code should fail syntax validation."""
        assert validate_patch_syntax(code, "javascript") is False

    @given(code=valid_js_code())
    @settings(max_examples=30, deadline=None)
    def test_valid_typescript_accepted(self, code):
        """Bracket-balanced TS code should pass syntax validation."""
        assert validate_patch_syntax(code, "typescript") is True

    @given(code=valid_js_code())
    @settings(max_examples=30, deadline=None)
    def test_valid_go_accepted(self, code):
        """Bracket-balanced Go code should pass syntax validation."""
        assert validate_patch_syntax(code, "go") is True

    def test_empty_code_rejected(self):
        """Empty or whitespace-only code should fail validation."""
        assert validate_patch_syntax("", "python") is False
        assert validate_patch_syntax("   ", "python") is False
        assert validate_patch_syntax("", "json") is False
        assert validate_patch_syntax("", "yaml") is False
        assert validate_patch_syntax("", "javascript") is False

    def test_unknown_language_accepted(self):
        """Unknown languages should pass validation (no validator available)."""
        assert validate_patch_syntax("anything here", "cobol") is True
        assert validate_patch_syntax("{}", "unknown") is True

"""
Property-based tests for Budget Tracking.

Property 19: Budget Accounting Invariant
For any sequence of LLM calls with known input/output token counts, the accumulated
cost should equal sum of (input_tokens × 15.0 / 1_000_000) + (output_tokens × 75.0 / 1_000_000).

**Validates: Requirements 10.1, 10.5**

Property 20: Budget Warning at 80% Threshold
When accumulated cost first crosses 80% of the limit, budget_warning_emitted should
transition to true.

**Validates: Requirements 10.2**

Property 21: Budget Halt Preserves Findings
When cost crosses budget limit, scan halts (BUDGET_EXCEEDED) but all prior findings
remain queryable.

**Validates: Requirements 10.3**
"""

import os
import sys
import uuid

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    integers,
    floats,
    lists,
    tuples,
    composite,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from code_scan_module import budget_tracking_hook, BudgetExceededError_


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Set up a fresh temporary database for each test function."""
    original_db_name = database.DB_NAME
    database.DB_NAME = str(tmp_path / "test_budget.db")
    database.init_db()
    yield
    database.DB_NAME = original_db_name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_scan_for_test(budget_limit_usd: float = 50.0) -> str:
    """Create a code scan record and return its ID."""
    scan_id = database.create_code_scan(
        label="Budget Test Scan",
        repos=["owner/test-repo"],
        config={"budget_limit_usd": budget_limit_usd},
    )
    database.code_scan_update_phase(scan_id, "SCANNING")
    return scan_id


def insert_finding_for_test(scan_id: str, repo_identifier: str = "owner/test-repo") -> str:
    """Insert a finding and return its ID."""
    finding_id = str(uuid.uuid4())
    base_finding = {
        "id": finding_id,
        "vuln_class": "SQL_Injection",
        "repo": repo_identifier,
        "file_path": "src/main.py",
        "line_start": 10,
        "line_end": 10,
        "severity": "HIGH",
        "confidence": 85,
        "title": "SQL Injection in query",
        "description": "User input flows into SQL query without sanitization.",
    }
    database.insert_code_scan_findings(scan_id, [base_finding])
    database.code_scan_finding_update_type(
        finding_id=finding_id,
        finding_type="sast",
        repo_identifier=repo_identifier,
    )
    return finding_id


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for a single LLM call's token counts
st_token_pair = tuples(
    integers(min_value=0, max_value=500_000),   # input_tokens
    integers(min_value=0, max_value=100_000),   # output_tokens
)

# Strategy for a sequence of LLM calls
st_token_sequence = lists(st_token_pair, min_size=1, max_size=20)


# ---------------------------------------------------------------------------
# Property 19: Budget Accounting Invariant
# ---------------------------------------------------------------------------

@given(token_calls=st_token_sequence)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_19_budget_accounting_invariant(setup_test_db, token_calls):
    """
    **Property 19: Budget Accounting Invariant**

    For any sequence of LLM calls with known input/output token counts, the
    Budget_Tracker's accumulated cost should equal the sum of
    (input_tokens × 15.0 / 1_000_000) + (output_tokens × 75.0 / 1_000_000)
    for all calls, at per-scan and per-repo granularity.

    **Validates: Requirements 10.1, 10.5**
    """
    # Use a large budget limit so we don't trigger budget exceeded
    budget_limit = 999999.0
    scan_id = create_scan_for_test(budget_limit_usd=budget_limit)
    repo = "owner/test-repo"
    config = {"budget_limit_usd": budget_limit}

    expected_total_cost = 0.0
    expected_input_tokens = 0
    expected_output_tokens = 0

    for input_tokens, output_tokens in token_calls:
        input_cost = input_tokens * 15.0 / 1_000_000
        output_cost = output_tokens * 75.0 / 1_000_000
        expected_total_cost += input_cost + output_cost
        expected_input_tokens += input_tokens
        expected_output_tokens += output_tokens

        budget_tracking_hook(
            scan_id=scan_id,
            repo_identifier=repo,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            config=config,
        )

    # Verify scan-level accounting
    budget_records = database.code_scan_budget_get_by_scan_id(scan_id)
    scan_level = [r for r in budget_records if r.get("repo_identifier") is None]
    repo_level = [r for r in budget_records if r.get("repo_identifier") == repo]

    assert len(scan_level) == 1, "Should have exactly one scan-level budget record"
    assert len(repo_level) == 1, "Should have exactly one per-repo budget record"

    scan_rec = scan_level[0]
    repo_rec = repo_level[0]

    # Verify accumulated cost matches expected (with floating point tolerance)
    assert abs(scan_rec["cost_usd"] - expected_total_cost) < 1e-9, (
        f"Scan-level cost {scan_rec['cost_usd']} != expected {expected_total_cost}"
    )
    assert abs(repo_rec["cost_usd"] - expected_total_cost) < 1e-9, (
        f"Repo-level cost {repo_rec['cost_usd']} != expected {expected_total_cost}"
    )

    # Verify token counts
    assert scan_rec["input_tokens"] == expected_input_tokens
    assert scan_rec["output_tokens"] == expected_output_tokens
    assert repo_rec["input_tokens"] == expected_input_tokens
    assert repo_rec["output_tokens"] == expected_output_tokens

    # Verify the scan's cost_usd column was updated
    scan = database.get_code_scan(scan_id)
    assert abs((scan.get("cost_usd") or 0.0) - expected_total_cost) < 1e-9


# ---------------------------------------------------------------------------
# Property 20: Budget Warning at 80% Threshold
# ---------------------------------------------------------------------------

@given(token_calls=st_token_sequence)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_20_budget_warning_at_80_percent(setup_test_db, token_calls):
    """
    **Property 20: Budget Warning at 80% Threshold**

    When accumulated cost first crosses 80% of the limit, budget_warning_emitted
    should transition from false to true and be reflected in the budget records.

    **Validates: Requirements 10.2**
    """
    # Calculate total cost that would be generated
    total_cost = sum(
        (inp * 15.0 / 1_000_000) + (out * 75.0 / 1_000_000)
        for inp, out in token_calls
    )

    # Set budget limit such that total cost is between 80% and 100% of limit
    # (to test warning without exceeding)
    # We want: total_cost >= 0.8 * budget_limit AND total_cost < budget_limit
    # So: budget_limit > total_cost AND budget_limit <= total_cost / 0.8
    assume(total_cost > 0)  # Need non-zero cost to cross any threshold

    # Set limit so total cost is exactly 90% of the limit
    budget_limit = total_cost / 0.9

    scan_id = create_scan_for_test(budget_limit_usd=budget_limit)
    repo = "owner/test-repo"
    config = {"budget_limit_usd": budget_limit}

    # Execute all LLM calls
    for input_tokens, output_tokens in token_calls:
        budget_tracking_hook(
            scan_id=scan_id,
            repo_identifier=repo,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            config=config,
        )

    # After all calls, the accumulated cost = total_cost = 0.9 * budget_limit
    # which is >= 0.8 * budget_limit, so warning should be emitted
    budget_records = database.code_scan_budget_get_by_scan_id(scan_id)
    scan_level = [r for r in budget_records if r.get("repo_identifier") is None]

    assert len(scan_level) == 1
    assert scan_level[0]["budget_warning_emitted"] == 1, (
        f"Warning should be emitted when cost ({total_cost:.6f}) >= "
        f"80% of limit ({budget_limit * 0.8:.6f})"
    )


@given(token_calls=st_token_sequence)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_20_no_warning_below_80_percent(setup_test_db, token_calls):
    """
    **Property 20: Budget Warning at 80% Threshold (negative case)**

    When accumulated cost stays below 80% of the limit, budget_warning_emitted
    should remain false.

    **Validates: Requirements 10.2**
    """
    total_cost = sum(
        (inp * 15.0 / 1_000_000) + (out * 75.0 / 1_000_000)
        for inp, out in token_calls
    )
    assume(total_cost > 0)

    # Set limit so total cost is only 50% of the limit (well below 80%)
    budget_limit = total_cost / 0.5

    scan_id = create_scan_for_test(budget_limit_usd=budget_limit)
    repo = "owner/test-repo"
    config = {"budget_limit_usd": budget_limit}

    for input_tokens, output_tokens in token_calls:
        budget_tracking_hook(
            scan_id=scan_id,
            repo_identifier=repo,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            config=config,
        )

    budget_records = database.code_scan_budget_get_by_scan_id(scan_id)
    scan_level = [r for r in budget_records if r.get("repo_identifier") is None]

    assert len(scan_level) == 1
    assert scan_level[0]["budget_warning_emitted"] == 0, (
        f"Warning should NOT be emitted when cost ({total_cost:.6f}) < "
        f"80% of limit ({budget_limit * 0.8:.6f})"
    )


# ---------------------------------------------------------------------------
# Property 21: Budget Halt Preserves Findings
# ---------------------------------------------------------------------------

@given(
    pre_halt_calls=lists(st_token_pair, min_size=1, max_size=5),
    finding_count=integers(min_value=1, max_value=5),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_21_budget_halt_preserves_findings(setup_test_db, pre_halt_calls, finding_count):
    """
    **Property 21: Budget Halt Preserves Findings**

    When cost crosses budget limit, scan halts (BUDGET_EXCEEDED) but all prior
    findings remain queryable.

    **Validates: Requirements 10.3**
    """
    # Calculate total cost from pre_halt_calls
    pre_cost = sum(
        (inp * 15.0 / 1_000_000) + (out * 75.0 / 1_000_000)
        for inp, out in pre_halt_calls
    )
    assume(pre_cost > 0)

    # Set budget limit slightly above pre_cost so pre-halt calls succeed
    # Then one additional call will push cost over the limit
    budget_limit = pre_cost * 1.1  # 10% headroom for pre-halt calls

    scan_id = create_scan_for_test(budget_limit_usd=budget_limit)
    repo = "owner/test-repo"
    config = {"budget_limit_usd": budget_limit}

    # Insert findings before any budget tracking (simulating findings persisted
    # during scanning, before the budget is exceeded)
    inserted_finding_ids = []
    for _ in range(finding_count):
        fid = insert_finding_for_test(scan_id, repo)
        inserted_finding_ids.append(fid)

    # Execute pre-halt calls (these should succeed since we have headroom)
    for input_tokens, output_tokens in pre_halt_calls:
        budget_tracking_hook(
            scan_id=scan_id,
            repo_identifier=repo,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            config=config,
        )

    # Now make a large call that pushes cost over budget_limit
    # We need enough tokens to exceed the remaining budget
    remaining = budget_limit - pre_cost
    # One call that costs more than the remaining budget
    exceeding_input = int((remaining * 1_000_000 / 15.0) + 100_000)

    budget_exceeded = False
    try:
        budget_tracking_hook(
            scan_id=scan_id,
            repo_identifier=repo,
            input_tokens=exceeding_input,
            output_tokens=1000,
            config=config,
        )
    except BudgetExceededError_:
        budget_exceeded = True

    assert budget_exceeded, "BudgetExceededError_ should be raised when cost exceeds limit"

    # Mark scan as BUDGET_EXCEEDED (simulating what run_scan_background does)
    database.code_scan_update_phase(scan_id, "BUDGET_EXCEEDED")

    # Verify scan is in BUDGET_EXCEEDED state
    scan = database.get_code_scan(scan_id)
    assert scan.get("scan_phase") == "BUDGET_EXCEEDED"

    # Verify ALL prior findings are still queryable
    findings = database.get_code_scan_findings(scan_id)
    assert len(findings) == finding_count, (
        f"Expected {finding_count} findings to be preserved, got {len(findings)}"
    )

    # Verify each inserted finding is present
    found_ids = {f["id"] for f in findings}
    for fid in inserted_finding_ids:
        assert fid in found_ids, f"Finding {fid} should be preserved after budget halt"

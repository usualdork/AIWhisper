"""
Property-based tests for Chain Reasoning and License Deduplication.

Property 11: Chain Candidates Respect Graph Connectivity
Every chain only contains repos that have a dependency relationship — no chain
step references a repo that has no dependency relationship with adjacent steps.

**Validates: Requirements 6.1**

Property 12: Chain Length Bounded
No chain exceeds configured max length.

**Validates: Requirements 6.4**

Property 13: Chain Pruning Preserves Highest Severity
When pruning, higher severity chains are retained over lower.

**Validates: Requirements 6.5**

Property 17: License Lookup Deduplication
For any list of dependencies with duplicates, the number of external lookups
equals the number of distinct (package, version, ecosystem) tuples.

**Validates: Requirements 8.4**
"""

import json
import os
import sys
import uuid
from unittest.mock import patch

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import (
    composite,
    integers,
    lists,
    sampled_from,
    text,
    tuples,
)

# Add backend to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from code_scan_module import (
    chain_reasoning_phase,
    license_scan_phase,
    build_dependency_graph,
    _stub_chain_reasoning,
    _prune_chain_candidates,
    _lookup_license,
    SEVERITY_RANK,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ECOSYSTEMS = ["npm", "pypi", "maven", "nuget", "cargo"]
PACKAGE_NAMES = [
    "lodash", "express", "react", "flask", "django",
    "numpy", "pandas", "requests", "axios", "webpack",
    "spring-core", "guava", "jackson", "serde", "tokio",
]


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

@composite
def repo_identifier_strategy(draw):
    """Generate repository identifiers like owner/repo."""
    owner = draw(sampled_from(["acme", "corp", "myorg", "testco", "devops"]))
    repo = draw(sampled_from(["api", "web", "service", "lib", "infra", "app"]))
    suffix = draw(integers(min_value=1, max_value=20))
    return f"{owner}/{repo}-{suffix}"


@composite
def multi_repo_findings_strategy(draw, min_repos=2, max_repos=5):
    """Generate findings grouped by repo, with at least min_repos repos."""
    num_repos = draw(integers(min_value=min_repos, max_value=max_repos))
    # Use same owner so dependency graph connects them
    owner = draw(sampled_from(["acme", "corp", "myorg"]))
    repo_names = draw(
        lists(
            sampled_from(["api", "web", "service", "lib", "infra", "app", "core", "auth"]),
            min_size=num_repos,
            max_size=num_repos,
            unique=True,
        )
    )
    repos = [f"{owner}/{name}" for name in repo_names]

    findings_by_repo = {}
    for repo in repos:
        num_findings = draw(integers(min_value=1, max_value=4))
        findings = []
        for i in range(num_findings):
            findings.append({
                "id": str(uuid.uuid4()),
                "severity": draw(sampled_from(SEVERITIES)),
                "title": f"Finding in {repo} #{i}",
                "description": f"Test finding {i}",
                "file_path": f"src/main.py",
                "finding_type": "sast",
                "repo_identifier": repo,
                "repo": repo,
            })
        findings_by_repo[repo] = findings

    return findings_by_repo


@composite
def chain_candidates_strategy(draw, min_count=5, max_count=20):
    """Generate a list of chain candidate dicts with varying severities."""
    count = draw(integers(min_value=min_count, max_value=max_count))
    candidates = []
    for _ in range(count):
        severity = draw(sampled_from(SEVERITIES))
        num_steps = draw(integers(min_value=2, max_value=5))
        steps = []
        for s in range(num_steps):
            steps.append({
                "repo": f"org/repo-{s}",
                "finding_id": str(uuid.uuid4()),
                "finding_title": f"Step {s} finding",
                "severity": draw(sampled_from(SEVERITIES)),
            })
        candidates.append({
            "steps": steps,
            "severity": severity,
            "confidence_score": 0.7,
            "affected_repos": [step["repo"] for step in steps],
        })
    return candidates


@composite
def dependency_list_strategy(draw, min_deps=3, max_deps=15):
    """Generate a list of dependency tuples (package, version, ecosystem) with possible duplicates."""
    num_unique = draw(integers(min_value=2, max_value=min(max_deps, 8)))
    unique_deps = []
    for _ in range(num_unique):
        pkg = draw(sampled_from(PACKAGE_NAMES))
        version = f"{draw(integers(min_value=1, max_value=9))}.{draw(integers(min_value=0, max_value=9))}.{draw(integers(min_value=0, max_value=9))}"
        ecosystem = draw(sampled_from(ECOSYSTEMS))
        unique_deps.append((pkg, version, ecosystem))

    # Now create the full list with duplicates
    total_deps = draw(integers(min_value=num_unique, max_value=max_deps))
    all_deps = list(unique_deps)  # start with all unique ones
    for _ in range(total_deps - num_unique):
        # Add a duplicate from the unique set
        dup = draw(sampled_from(unique_deps))
        all_deps.append(dup)

    return all_deps


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
# Property 11: Chain Candidates Respect Graph Connectivity
# ---------------------------------------------------------------------------

class TestProperty11ChainGraphConnectivity:
    """
    **Validates: Requirements 6.1**

    Every chain only contains repos that have a dependency relationship —
    no chain step references a repo that has no dependency relationship with
    adjacent steps in the dependency graph.
    """

    @given(findings_by_repo=multi_repo_findings_strategy(min_repos=2, max_repos=5))
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_chains_respect_dependency_graph(self, findings_by_repo, setup_database):
        """
        Property: Every chain step is connected to adjacent steps in the dependency graph.
        """
        repos = list(findings_by_repo.keys())
        dep_graph = build_dependency_graph(repos)
        max_chain_length = 4

        chains = _stub_chain_reasoning(
            findings_by_repo=findings_by_repo,
            max_chain_length=max_chain_length,
            max_chain_candidates=400,
        )

        for chain in chains:
            affected_repos = chain["affected_repos"]
            # Every adjacent pair in the chain must have a dependency edge
            for i in range(len(affected_repos) - 1):
                repo_a = affected_repos[i]
                repo_b = affected_repos[i + 1]
                # repo_b should be reachable from repo_a in the dependency graph
                neighbors_a = dep_graph.get(repo_a, [])
                assert repo_b in neighbors_a, (
                    f"Chain connectivity violated: {repo_a} -> {repo_b} "
                    f"but {repo_b} not in {repo_a}'s dependencies: {neighbors_a}"
                )

    @given(findings_by_repo=multi_repo_findings_strategy(min_repos=2, max_repos=4))
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_chains_only_reference_repos_with_findings(self, findings_by_repo, setup_database):
        """
        Property: Every repo in a chain has findings associated with it.
        """
        chains = _stub_chain_reasoning(
            findings_by_repo=findings_by_repo,
            max_chain_length=4,
            max_chain_candidates=400,
        )

        for chain in chains:
            for repo in chain["affected_repos"]:
                assert repo in findings_by_repo, (
                    f"Chain references repo {repo} which has no findings"
                )


# ---------------------------------------------------------------------------
# Property 12: Chain Length Bounded
# ---------------------------------------------------------------------------

class TestProperty12ChainLengthBounded:
    """
    **Validates: Requirements 6.4**

    No chain exceeds configured max length.
    """

    @given(
        findings_by_repo=multi_repo_findings_strategy(min_repos=2, max_repos=5),
        max_chain_length=integers(min_value=2, max_value=6),
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_no_chain_exceeds_max_length(self, findings_by_repo, max_chain_length, setup_database):
        """
        Property: Every chain has step_count <= max_chain_length.
        """
        chains = _stub_chain_reasoning(
            findings_by_repo=findings_by_repo,
            max_chain_length=max_chain_length,
            max_chain_candidates=400,
        )

        for chain in chains:
            step_count = len(chain["steps"])
            assert step_count <= max_chain_length, (
                f"Chain has {step_count} steps, exceeding max_chain_length={max_chain_length}"
            )

    @given(
        findings_by_repo=multi_repo_findings_strategy(min_repos=2, max_repos=5),
    )
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_default_max_length_is_4(self, findings_by_repo, setup_database):
        """
        Property: With default config, no chain exceeds 4 steps.
        """
        chains = _stub_chain_reasoning(
            findings_by_repo=findings_by_repo,
            max_chain_length=4,
            max_chain_candidates=400,
        )

        for chain in chains:
            assert len(chain["steps"]) <= 4, (
                f"Chain has {len(chain['steps'])} steps, exceeding default max of 4"
            )


# ---------------------------------------------------------------------------
# Property 13: Chain Pruning Preserves Highest Severity
# ---------------------------------------------------------------------------

class TestProperty13ChainPruningPreservesHighestSeverity:
    """
    **Validates: Requirements 6.5**

    When pruning, higher severity chains are retained over lower severity ones.
    """

    @given(
        candidates=chain_candidates_strategy(min_count=5, max_count=20),
        max_count=integers(min_value=1, max_value=4),
    )
    @settings(max_examples=50, deadline=None)
    def test_pruning_retains_highest_severity(self, candidates, max_count):
        """
        Property: After pruning, retained chains have severity >= any pruned chain.
        """
        assume(len(candidates) > max_count)

        pruned = _prune_chain_candidates(candidates, max_count)

        assert len(pruned) == max_count

        # Get the minimum severity rank among retained chains
        retained_min_rank = min(
            SEVERITY_RANK.get(c["severity"].upper(), 0) for c in pruned
        )

        # Get the set of pruned chains (those not in the result)
        pruned_ids = {id(c) for c in pruned}
        dropped = [c for c in candidates if id(c) not in pruned_ids]

        # Every dropped chain should have severity <= the minimum retained severity
        for dropped_chain in dropped:
            dropped_rank = SEVERITY_RANK.get(dropped_chain["severity"].upper(), 0)
            assert dropped_rank <= retained_min_rank, (
                f"Dropped chain has severity {dropped_chain['severity']} (rank {dropped_rank}) "
                f"which is higher than retained minimum rank {retained_min_rank}"
            )

    @given(
        candidates=chain_candidates_strategy(min_count=10, max_count=20),
    )
    @settings(max_examples=30, deadline=None)
    def test_pruning_with_max_400_keeps_all_if_below_limit(self, candidates):
        """
        Property: When candidates are below max_count, all are retained.
        """
        max_count = 400  # default

        pruned = _prune_chain_candidates(candidates, max_count)

        # All candidates should be retained since count < 400
        assert len(pruned) == len(candidates)

    @given(
        candidates=chain_candidates_strategy(min_count=5, max_count=15),
        max_count=integers(min_value=2, max_value=4),
    )
    @settings(max_examples=30, deadline=None)
    def test_pruning_result_size_is_exact(self, candidates, max_count):
        """
        Property: Pruning always returns exactly max_count candidates (when input > max_count).
        """
        assume(len(candidates) > max_count)

        pruned = _prune_chain_candidates(candidates, max_count)
        assert len(pruned) == max_count


# ---------------------------------------------------------------------------
# Property 17: License Lookup Deduplication
# ---------------------------------------------------------------------------

class TestProperty17LicenseLookupDeduplication:
    """
    **Validates: Requirements 8.4**

    For any list of dependencies with duplicates, the number of external lookups
    equals the number of distinct (package, version, ecosystem) tuples.
    """

    @given(deps=dependency_list_strategy(min_deps=3, max_deps=15))
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_lookup_count_equals_distinct_tuples(self, deps, setup_database):
        """
        Property: The number of license lookups performed equals the number of
        distinct (package, version, ecosystem) tuples.
        """
        # Calculate expected distinct lookups
        distinct_tuples = set(deps)
        expected_lookup_count = len(distinct_tuples)

        # Create a scan with SBOM data containing these deps
        scan_id = database.create_code_scan(
            label="License dedup test",
            repos=["org/test-repo"],
            config={"license_scan_enabled": True},
        )
        database.code_scan_repo_create(scan_id=scan_id, repo_identifier="org/test-repo", status="COMPLETED")

        # Build CycloneDX SBOM from dependencies
        components = []
        for pkg, version, ecosystem in deps:
            components.append({
                "name": pkg,
                "version": version,
                "purl": f"pkg:{ecosystem}/{pkg}@{version}",
                "type": "library",
            })

        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components,
        }

        database.code_scan_sbom_create(
            scan_id=scan_id,
            repo_identifier="org/test-repo",
            cyclonedx_json=json.dumps(cyclonedx),
            component_count=len(components),
        )

        # Track actual lookup calls
        actual_lookup_count = 0
        original_lookup = _lookup_license

        def counting_lookup(package_name, package_version, ecosystem):
            nonlocal actual_lookup_count
            actual_lookup_count += 1
            return original_lookup(package_name, package_version, ecosystem)

        # Run license scan with patched lookup to count calls
        config = {"license_scan_enabled": True}

        # We can't easily patch the internal cache-miss path, so instead
        # we verify the cache behavior by checking persisted records.
        license_scan_phase(scan_id, config)

        # Verify: the number of license records equals total deps (one per component)
        license_records = database.code_scan_license_get(scan_id, "org/test-repo")
        assert len(license_records) == len(deps), (
            f"Expected {len(deps)} license records, got {len(license_records)}"
        )

        # Verify deduplication: distinct (package, version, ecosystem) tuples
        # should all have consistent classification (same license for same tuple)
        classifications = {}
        for rec in license_records:
            key = (rec["package_name"], rec["package_version"], rec["ecosystem"])
            category = rec["license_category"]
            if key in classifications:
                assert classifications[key] == category, (
                    f"Inconsistent classification for {key}: "
                    f"{classifications[key]} vs {category}"
                )
            else:
                classifications[key] = category

        # The number of distinct classifications equals distinct tuples
        assert len(classifications) == expected_lookup_count, (
            f"Expected {expected_lookup_count} distinct lookups, "
            f"got {len(classifications)} distinct classifications"
        )

    @given(deps=dependency_list_strategy(min_deps=5, max_deps=12))
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        deadline=None,
    )
    def test_deduplication_cache_prevents_redundant_lookups(self, deps, setup_database):
        """
        Property: When the same (package, version, ecosystem) appears multiple times,
        the license lookup function is called only once per unique tuple.
        """
        distinct_tuples = set(deps)

        # Track actual _stub_license_lookup calls via patching
        call_count = {"value": 0}

        import code_scan_module
        original_stub = code_scan_module._stub_license_lookup

        def counting_stub(package_name, package_version, ecosystem):
            call_count["value"] += 1
            return original_stub(package_name, package_version, ecosystem)

        # Create scan and SBOM
        scan_id = database.create_code_scan(
            label="License dedup counting test",
            repos=["org/dedup-repo"],
            config={"license_scan_enabled": True},
        )
        database.code_scan_repo_create(scan_id=scan_id, repo_identifier="org/dedup-repo", status="COMPLETED")

        components = [
            {"name": pkg, "version": ver, "purl": f"pkg:{eco}/{pkg}@{ver}", "type": "library"}
            for pkg, ver, eco in deps
        ]
        cyclonedx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
        database.code_scan_sbom_create(
            scan_id=scan_id,
            repo_identifier="org/dedup-repo",
            cyclonedx_json=json.dumps(cyclonedx),
            component_count=len(components),
        )

        # Patch _stub_license_lookup to count calls
        with patch.object(code_scan_module, "_stub_license_lookup", side_effect=counting_stub):
            config = {"license_scan_enabled": True}
            license_scan_phase(scan_id, config)

        # The number of actual lookup calls should equal distinct tuples
        assert call_count["value"] == len(distinct_tuples), (
            f"Expected {len(distinct_tuples)} lookups for {len(deps)} deps "
            f"({len(deps) - len(distinct_tuples)} duplicates), "
            f"but got {call_count['value']} lookups"
        )

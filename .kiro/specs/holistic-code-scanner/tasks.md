# Implementation Plan: Holistic Code Scanner Integration

## Overview

Incremental implementation of the Holistic Scanner V2 integration into the Angela platform. Tasks build sequentially: database schema first, then the FastAPI router skeleton, scanner package wiring, scan lifecycle, specialized endpoints, and finally the frontend update. Each phase is independently testable.

## Tasks

- [x] 1. Database schema and DAO layer
  - [x] 1.1 Create migration to extend existing tables and add new tables
    - Add new columns to `code_scans` table (scan_phase, total_repos, repos_completed, repos_failed, repos_skipped, config_json, cost_usd, budget_limit_usd, diff_aware, resumed_from_scan_id)
    - Add new columns to `code_scan_findings` table (finding_type, sbom_ref, chain_id, sca_cve_id, container_finding_id, repo_identifier)
    - Create `code_scan_repos` table
    - Create `code_scan_sbom` table
    - Create `code_scan_sca` table
    - Create `code_scan_chains` table
    - Create `code_scan_licenses` table
    - Create `code_scan_container` table
    - Create `code_scan_prs` table
    - Create `code_scan_budget` table
    - Create `code_scan_settings` table with default rows
    - _Requirements: 1.3, 2.1, 3.1, 4.1, 5.1, 6.1, 7.3, 8.1, 9.1, 10.1, 11.2, 20.1_

  - [x] 1.2 Implement DAO functions for all new tables
    - CRUD functions for `code_scan_repos` (create, get by scan_id, update status, get by repo_identifier)
    - CRUD functions for `code_scan_sbom` (create, get by scan_id+repo)
    - CRUD functions for `code_scan_sca` (create batch, get by scan_id+repo, filter by reachability/severity)
    - CRUD functions for `code_scan_chains` (create, get by scan_id, filter by severity)
    - CRUD functions for `code_scan_licenses` (create batch, get by scan_id+repo, filter by category)
    - CRUD functions for `code_scan_container` (create, get by scan_id+repo)
    - CRUD functions for `code_scan_prs` (create, get by scan_id, update status)
    - CRUD functions for `code_scan_budget` (create, update, get by scan_id, get 30-day rolling)
    - CRUD functions for `code_scan_settings` (get all, get by key, upsert)
    - Functions to update `code_scans` new columns (scan_phase, cost, repo counts)
    - Functions to update `code_scan_findings` new columns
    - _Requirements: 1.3, 2.3, 10.1, 11.2, 20.1_

  - [x] 1.3 Write property tests for DAO layer
    - **Property 1: Finding Persistence Round-Trip**
    - **Validates: Requirements 1.3**

- [x] 2. Rewrite code_scan_module.py — API router with holistic engine
  - [x] 2.1 Rewrite `backend/code_scan_module.py` to use holistic scanner
    - Remove ALL old chunk-based scanning logic
    - Keep the same router prefix `/api/code-scan` and same variable name `router`
    - Import holistic_scanner package via sys.path
    - Import RBAC middleware using `require_module("code_scan")`
    - Define all Pydantic request/response models (ScanStartRequest, ScanStatusResponse, RepoStatus, FindingResponse, BudgetResponse)
    - Implement all 18 endpoint stubs from the design (POST /scans, GET /scans, GET /scans/{id}, GET /scans/{id}/findings, etc.)
    - Keep backward-compatible response structure for existing frontend (scan_id, status, repos, findings)
    - _Requirements: 1.1, 1.2, 22.4_

  - [x] 2.2 Update `backend/main.py` router registration
    - The existing `app.include_router(code_scan_module.router)` remains unchanged (same module, same router)
    - No new imports needed — the rewritten `code_scan_module.py` exports the same `router` variable
    - Remove any old code_scan_module-specific inline routes in main.py if they exist
    - _Requirements: 1.2_

  - [x] 2.3 Write unit tests for router registration and endpoint accessibility
    - Test all 18 endpoints return valid HTTP responses (even if stubs)
    - Test RBAC decorator is applied to all endpoints
    - _Requirements: 1.2, 22.4_

- [x] 3. Scanner package integration
  - [x] 3.1 Wire holistic_scanner package import in code_scan_module.py
    - Add `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CodeScanning", "New project"))` at module top
    - Import Orchestrator, ScanConfig, BudgetTracker, BudgetExceededError
    - Import model classes: HolisticFinding, CVERecord, ExploitChain
    - Add fallback try/except with clear error message if import fails
    - _Requirements: 1.1_

  - [x] 3.2 Create ScanConfig builder from request + platform defaults
    - Function `build_scan_config(request: ScanStartRequest) -> ScanConfig` that merges user request with `code_scan_settings` defaults
    - Apply validation rules: budget ≥ $2.00, concurrency ≤ 20
    - Return descriptive errors for invalid config
    - _Requirements: 11.1, 11.2, 11.4_

  - [x] 3.3 Write property tests for configuration handling
    - **Property 22: Configuration Validation**
    - **Validates: Requirements 11.1, 11.4**
    - **Property 23: Configuration Defaults Fill**
    - **Validates: Requirements 11.2**

- [x] 4. Scan lifecycle management
  - [x] 4.1 Implement POST /scans endpoint (start scan)
    - Accept JSON body with repos array or multipart form with .txt file upload
    - Parse both input formats into identical repo list
    - Create scan record in DB with status CREATED
    - Create per-repo records in `code_scan_repos` with status QUEUED
    - Validate config and reject invalid combinations
    - Launch background scan task
    - Return scan ID and initial status
    - _Requirements: 1.1, 2.1, 2.2, 11.1_

  - [x] 4.2 Implement background scan orchestration task
    - Async background task that invokes Orchestrator with ScanConfig
    - Process repos with configurable concurrency (asyncio.Semaphore)
    - Update scan_phase as scan progresses through states (INGESTING → SCANNING → ENRICHING → CHAINING → PATCHING → REPORTING → COMPLETED)
    - Update per-repo status as each repo completes
    - Implement diff-aware skipping: compare HEAD SHA against last completed scan
    - Handle per-repo isolation: one repo failure doesn't crash others
    - Persist findings to DB after each repo completes
    - _Requirements: 1.1, 2.1, 2.4, 2.5, 20.1_

  - [x] 4.3 Implement POST /scans/{id}/stop and POST /scans/{id}/resume
    - Stop: set cancellation flag, mark scan as STOPPED, preserve all persisted data
    - Resume: load scan state, skip COMPLETED repos, restart from first non-completed
    - On backend restart: `reset_inflight_code_scans()` marks IN_PROGRESS as INTERRUPTED
    - _Requirements: 20.2, 20.3_

  - [x] 4.4 Implement GET /scans/{id} status endpoint
    - Return full ScanStatusResponse with per-repo status list
    - Include budget metrics (cost_usd, budget warning flag)
    - _Requirements: 2.3_

  - [x] 4.5 Implement error handling and graceful degradation
    - Catch unrecoverable errors → mark scan FAILED, preserve partial findings
    - Exponential backoff for transient failures (GitHub rate limit, LLM timeout)
    - Log all errors with scan_id and repo_identifier context
    - _Requirements: 1.5, 2.4_

  - [x] 4.6 Write property tests for scan lifecycle
    - **Property 2: Partial Findings Survive Errors**
    - **Validates: Requirements 1.5**
    - **Property 3: All Repos Reach Terminal State**
    - **Validates: Requirements 2.1**
    - **Property 4: JSON Array and File Upload Equivalence**
    - **Validates: Requirements 2.2**
    - **Property 5: Status Reports All Repos**
    - **Validates: Requirements 2.3**
    - **Property 6: Multi-Repo Isolation**
    - **Validates: Requirements 2.4**
    - **Property 7: Diff-Aware Skip on Same SHA**
    - **Validates: Requirements 2.5**

- [x] 5. Checkpoint — Ensure core scan lifecycle works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. SBOM, SCA, CBOM, License, and Container endpoints
  - [x] 6.1 Implement GET /scans/{id}/sbom/{repo} endpoint
    - Query `code_scan_sbom` table, return CycloneDX JSON document
    - Handle empty SBOM (no lockfiles found) with metadata note
    - _Requirements: 3.1, 3.2, 3.4_

  - [x] 6.2 Implement GET /scans/{id}/sca/{repo} endpoint
    - Query `code_scan_sca` table, return CVE records with reachability verdicts
    - Support filtering by severity and reachability status
    - _Requirements: 5.1, 5.3_

  - [x] 6.3 Implement GET /scans/{id}/cbom/{repo} endpoint
    - Query crypto BOM data, return JSON array of crypto usage records
    - Include algorithm, key_size, protocol_version, classification (SAFE/WEAK/QUANTUM_RISK)
    - _Requirements: 4.1, 4.3_

  - [x] 6.4 Implement GET /scans/{id}/licenses/{repo} endpoint
    - Query `code_scan_licenses` table, return per-dependency license classification
    - Include requires_review flag for STRONG_COPYLEFT and UNKNOWN
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 6.5 Implement GET /scans/{id}/container/{repo} endpoint
    - Query `code_scan_container` table, return Dockerfile findings
    - Include misconfiguration_type, severity, description, recommended_fix
    - _Requirements: 9.1, 9.3_

  - [x] 6.6 Implement GET /scans/{id}/chains endpoint
    - Query `code_scan_chains` table, return exploit chain objects
    - Include ordered steps, affected repos, severity, confidence score
    - _Requirements: 6.1, 6.3_

  - [x] 6.7 Write property tests for specialized endpoints
    - **Property 8: SBOM Component Completeness**
    - **Validates: Requirements 3.1, 3.3**
    - **Property 9: CBOM Classification and Finding Generation**
    - **Validates: Requirements 4.2, 4.4**
    - **Property 10: CVSS-to-Severity Mapping**
    - **Validates: Requirements 5.4**
    - **Property 16: License Classification and Flagging Invariant**
    - **Validates: Requirements 8.1, 8.2**
    - **Property 18: Container Severity Classification**
    - **Validates: Requirements 9.4**

- [ ] 7. Auto-PR integration
  - [x] 7.1 Implement Auto-PR orchestration within scan lifecycle
    - After enrichment phase, invoke PRPublisher for findings at/above min severity
    - Validate patches syntactically (ast.parse for Python, json.loads for JSON, yaml.safe_load for YAML, bracket-balance for JS/TS/Go)
    - Discard invalid patches with warning log
    - Consolidate valid patches into single branch per repo
    - Open draft PRs via GitHub API (or skip if token missing/insufficient scopes)
    - Persist PR records to `code_scan_prs` table
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.6_

  - [x] 7.2 Implement GET /scans/{id}/prs endpoint
    - Return PR URLs, status (DRAFT/OPEN/MERGED/CLOSED/FAILED), findings addressed
    - _Requirements: 7.5_

  - [x] 7.3 Write property tests for Auto-PR
    - **Property 14: Auto-PR Generates Diffs for Qualifying Findings**
    - **Validates: Requirements 7.1**
    - **Property 15: Patch Syntax Validation**
    - **Validates: Requirements 7.2**

- [x] 8. Budget tracking
  - [x] 8.1 Implement budget tracking within scan orchestration
    - Hook into each LLM call to record input/output tokens and cost
    - Update `code_scan_budget` table after each LLM call
    - Emit warning when cost reaches 80% of budget limit
    - Halt scan gracefully when budget limit is reached (mark BUDGET_EXCEEDED)
    - Preserve all findings generated before halt
    - _Requirements: 10.1, 10.2, 10.3, 10.5_

  - [x] 8.2 Implement GET /scans/{id}/budget endpoint
    - Return current spend, remaining budget, per-repo cost breakdowns
    - Include warning_emitted flag
    - _Requirements: 10.4_

  - [x] 8.3 Write property tests for budget tracking
    - **Property 19: Budget Accounting Invariant**
    - **Validates: Requirements 10.1, 10.5**
    - **Property 20: Budget Warning at 80% Threshold**
    - **Validates: Requirements 10.2**
    - **Property 21: Budget Halt Preserves Findings**
    - **Validates: Requirements 10.3**

- [x] 9. Export formats (JSON, SARIF, Markdown, HTML)
  - [x] 9.1 Implement GET /scans/{id}/export endpoint with format parameter
    - JSON: return complete structured findings document with all metadata
    - SARIF: produce SARIF v2.1.0 document compatible with GitHub Code Scanning
    - Markdown: generate Markdown report with severity breakdowns and finding summaries
    - HTML: generate self-contained interactive HTML dashboard with panels for findings, SBOM, SCA, chains
    - _Requirements: 21.1, 21.2, 21.3, 21.4_

  - [x] 9.2 Write property tests for export formats
    - **Property 27: Export Format Correctness**
    - **Validates: Requirements 21.1, 21.2, 21.4**

- [x] 10. Checkpoint — Ensure all backend endpoints work
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Unified Dashboard integration
  - [x] 11.1 Implement push_to_unified_dashboard function
    - After scan completion, push all findings to unified dashboard
    - Set source_module="code_scan" for all pushed findings
    - Map finding_type correctly (sast, sca, cbom, container, chain)
    - For exploit chains: create one unified finding per chain with chain severity
    - _Requirements: 19.1, 19.2, 19.4_

  - [x] 11.2 Integrate finding_type as filterable attribute in unified dashboard
    - Update unified dashboard query to support finding_type filter
    - Ensure no cross-contamination between finding types in filter results
    - _Requirements: 19.3_

  - [x] 11.3 Write property tests for dashboard integration
    - **Property 24: Unified Dashboard Integration**
    - **Validates: Requirements 19.1, 19.2, 19.4**
    - **Property 25: Dashboard Finding Type Filterable**
    - **Validates: Requirements 19.3**

- [x] 12. RBAC enforcement for scanner endpoints
  - [x] 12.1 Apply RBAC rules to all scanner endpoints
    - Admin: all operations (config changes, scan initiation, deletion)
    - Agent: scan initiation + read access, deny config changes
    - Viewer: read-only access, deny scan initiation and config changes
    - Use `require_module("code_scan")` guard with role differentiation
    - Implement GET/POST /config endpoints (Admin only)
    - Implement DELETE /scans/{id} endpoint (Admin only)
    - _Requirements: 22.1, 22.2, 22.3, 22.4_

  - [x] 12.2 Write property tests for RBAC enforcement
    - **Property 28: RBAC Enforcement Matrix**
    - **Validates: Requirements 22.1, 22.2, 22.3**

- [x] 13. Checkpoint — Ensure backend is complete with all integrations
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Frontend — CodeScanBoard update
  - [x] 14.1 Update CodeScanBoard.jsx with multi-repo input and pre-scan config panel
    - Add multi-line textarea for repo input (one repo per line, supports `owner/repo` and `https://github.com/owner/repo`)
    - Add file upload button accepting .txt files with newline-delimited repos
    - Add paste-from-clipboard button
    - Add "Scan Modules" section with individually togglable checkboxes:
      - SAST (default ON), SCA (default ON), SBOM (default ON), CBOM (default ON)
      - License Compliance (default OFF), Container Analysis (default OFF)
      - Cross-Repo Chain Reasoning (default OFF), Auto-PR (default OFF)
    - When Auto-PR enabled, show sub-options: min severity dropdown, PR mode (draft/open/dry-run), target branch override
    - Add "Advanced Options" collapsible section: budget limit, model dropdown, concurrency, diff-aware toggle, generate lockfiles toggle
    - Show tooltip on hover for each toggle explaining what it does and cost impact
    - Show estimated cost range based on repo count × enabled modules
    - Hide scan form entirely for Viewer role (read-only mode)
    - Persist last-used config in localStorage
    - Add "Save as Template" button + template dropdown for named configs (e.g., "Quick SAST Only", "Full Compliance Scan")
    - Send full config to POST /api/code-scan/scans on submit
    - Display per-repo progress badges during active scan
    - _Requirements: 11.1, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9, 12.10_

  - [x] 14.2 Implement tabbed results view
    - Add tab navigation: Findings, SBOM, SCA, Chains, PRs, Licenses, Container
    - Findings tab: paginated table with finding_type filter (extend existing)
    - Add export buttons (JSON, SARIF, Markdown, HTML) calling /export endpoint
    - _Requirements: 12.3, 21.1_

  - [x] 14.3 Implement SBOM tab
    - Component list with columns: Name, Version, Ecosystem, License, CVE Count
    - Filter by ecosystem, sort by any column
    - Expandable rows showing associated CVEs and license details
    - _Requirements: 13.1, 13.2, 13.3_

  - [x] 14.4 Implement SCA tab
    - CVE records table: CVE ID, Package, Severity, CVSS Score, Reachability, Fix Version
    - Highlight REACHABLE CVEs visually
    - Filter by severity, reachability status, ecosystem
    - _Requirements: 15.1, 15.2, 15.3_

  - [x] 14.5 Implement Chains tab
    - Ordered chain steps with repo, finding reference, connecting arrows
    - Color-code by severity (CRITICAL: red, HIGH: orange, MEDIUM: yellow, LOW: green)
    - Clickable steps navigate to finding detail
    - _Requirements: 14.1, 14.2, 14.3_

  - [x] 14.6 Implement PRs tab
    - PR list: repo name, PR URL (clickable), status badge, findings count
    - Auto-refresh PR status on tab focus via /prs endpoint
    - _Requirements: 16.1, 16.2_

  - [x] 14.7 Implement Licenses tab
    - Category summary (PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, COMMERCIAL, UNKNOWN) with counts
    - Warning indicator on STRONG_COPYLEFT and UNKNOWN
    - Expandable categories showing individual components
    - _Requirements: 17.1, 17.2, 17.3_

  - [x] 14.8 Implement Container tab
    - Dockerfile findings: file path, misconfiguration type, severity, recommended fix
    - Group findings by repository for multi-repo scans
    - _Requirements: 18.1, 18.2_

- [x] 15. Checkpoint — Ensure frontend displays all scan result types
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Chain reasoning integration
  - [x] 16.1 Wire Chain_Reasoner into scan orchestration
    - After enrichment, invoke ChainReasoner across all scanned repos
    - Respect max chain length config (default 4 hops)
    - Prune candidates when exceeding max count (default 400), prioritize by severity
    - Persist chains to `code_scan_chains` table
    - _Requirements: 6.1, 6.2, 6.4, 6.5_

  - [x] 16.2 Write property tests for chain reasoning
    - **Property 11: Chain Candidates Respect Graph Connectivity**
    - **Validates: Requirements 6.1**
    - **Property 12: Chain Length Bounded**
    - **Validates: Requirements 6.4**
    - **Property 13: Chain Pruning Preserves Highest Severity**
    - **Validates: Requirements 6.5**

- [x] 17. License deduplication integration
  - [x] 17.1 Wire License_Scanner with deduplication logic
    - Deduplicate lookups by (package, version, ecosystem) tuple
    - Cache results for duration of scan
    - Persist to `code_scan_licenses` table
    - _Requirements: 8.4_

  - [x] 17.2 Write property test for license deduplication
    - **Property 17: License Lookup Deduplication**
    - **Validates: Requirements 8.4**

- [x] 18. Final checkpoint — Full integration verification
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The holistic_scanner package is imported via sys.path from `backend/CodeScanning/New project/holistic_scanner/` — no code copying
- Each task references specific requirements for traceability
- Property tests use Hypothesis framework (already configured in project)
- Checkpoints ensure incremental validation between major phases
- **IN-PLACE REPLACEMENT**: `code_scan_module.py` is REWRITTEN (not a new file). Same router variable name `router`, same prefix `/api/code-scan/`, same `main.py` registration. `CodeScanBoard.jsx` is UPDATED (same file, same component name, new tabs added).
- No backward-compatible "deprecated" module exists — the old chunk-based scanner code is removed entirely

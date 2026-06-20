# Requirements Document

## Introduction

Integration of the Holistic Scanner V2 into the Angela platform, replacing the legacy chunk-based code scanning module (`backend/code_scan_module.py`). The new scanner provides full-repository single-call analysis with 100% recall, SBOM generation, cryptographic BOM, software composition analysis, cross-repo exploit chain detection, auto-PR fix generation, license compliance, container analysis, and multi-repo parallel scanning. The integration must preserve backward compatibility with the existing API surface while exposing new capabilities through additional endpoints and an updated React frontend.

## Glossary

- **Holistic_Scanner**: The V2 code scanning engine that performs single-call full-context repository analysis via the AngelOne LiteLLM proxy, replacing the chunk-based approach.
- **Scan_Orchestrator**: The backend component that coordinates multi-repo scanning, budget enforcement, resumability, and diff-aware skipping.
- **SBOM_Generator**: The subsystem that produces CycloneDX 1.5 Software Bill of Materials from lockfile parsing.
- **CBOM_Scanner**: The subsystem that detects cryptographic algorithms, weak crypto usage, and quantum-risk patterns across repositories.
- **SCA_Engine**: The Software Composition Analysis engine that queries OSV.dev for CVEs and performs LLM-based reachability analysis.
- **Chain_Reasoner**: The component that constructs dependency graphs and uses LLM reasoning to detect cross-repo exploit chains.
- **Auto_PR_Publisher**: The component that generates unified diffs from findings and opens GitHub Pull Requests with fix patches.
- **License_Scanner**: The subsystem that classifies dependency licenses by risk level (copyleft, permissive, unknown).
- **Container_Analyzer**: The subsystem that analyzes Dockerfiles for base image risks and misconfigurations.
- **Budget_Tracker**: The component that enforces per-scan, per-repo, and rolling 30-day cost limits.
- **Scan_API**: The FastAPI APIRouter that exposes all code scanning endpoints under the `/api/code-scan` prefix.
- **Unified_Dashboard**: The existing Angela module that consolidates findings from all security modules.
- **Scan_State_DB**: The SQLite tables that persist scan status, findings, SBOM data, chains, CVEs, license cache, and PR results.
- **CodeScan_Frontend**: The React component (`CodeScanBoard.jsx`) that displays scan controls, findings, and new scanner capabilities.

## Requirements

### Requirement 1: Backend Scanner Replacement

**User Story:** As a platform operator, I want the legacy chunk-based scanner replaced with the Holistic Scanner V2 engine, so that scans achieve full-context analysis with higher recall.

#### Acceptance Criteria

1. WHEN a scan is initiated via the existing `/api/code-scan/start` endpoint, THE Scan_Orchestrator SHALL invoke the Holistic_Scanner pipeline (Ingest → Select → Neutralize → Scan → Enrich → Chain → Report) instead of the legacy chunk-based pipeline.
2. THE Scan_API SHALL preserve all existing endpoint paths and response schemas for backward compatibility with the CodeScan_Frontend and Unified_Dashboard integrations.
3. WHEN a scan completes, THE Holistic_Scanner SHALL persist findings to the Scan_State_DB using the same `code_scan_findings` table schema with additional columns for new finding metadata (sbom_ref, chain_id, sca_cve_id, container_finding_id).
4. THE Scan_Orchestrator SHALL use the AngelOne LiteLLM proxy (OpenAI-compatible endpoint) for all LLM calls, configured via the existing `ANGELONE_LLM_BASE_URL` and `ANGELONE_LLM_KEY` environment variables.
5. IF the Holistic_Scanner encounters an unrecoverable error during a scan, THEN THE Scan_Orchestrator SHALL mark the scan as FAILED, log the error, and ensure partial findings already persisted remain accessible.

### Requirement 2: Multi-Repository Scan Support

**User Story:** As a security analyst, I want to scan multiple repositories in a single operation, so that I can assess the security posture of an entire service fleet.

#### Acceptance Criteria

1. WHEN a user submits a scan request with multiple repository identifiers (1 to 200 repos), THE Scan_Orchestrator SHALL process them with configurable concurrency (default 5 parallel repos).
2. THE Scan_API SHALL accept repository lists via a JSON array in the request body or via a newline-delimited text file upload at `/api/code-scan/start`.
3. WHILE a multi-repo scan is in progress, THE Scan_API SHALL report per-repo status (QUEUED, SCANNING, COMPLETED, FAILED, SKIPPED) at the existing `/api/code-scan/status/{scan_id}` endpoint.
4. IF one repository fails during a multi-repo scan, THEN THE Scan_Orchestrator SHALL isolate the failure, log it, and continue scanning remaining repositories.
5. WHEN the `diff_aware` option is enabled, THE Scan_Orchestrator SHALL skip repositories whose default-branch HEAD SHA matches the SHA from the most recent completed scan of that repository.

### Requirement 3: SBOM Generation

**User Story:** As a security analyst, I want an SBOM generated for each scanned repository, so that I have a complete inventory of software components.

#### Acceptance Criteria

1. WHEN a scan completes for a repository, THE SBOM_Generator SHALL produce a CycloneDX 1.5 formatted bill of materials by parsing all detected lockfiles (package-lock.json, yarn.lock, Pipfile.lock, poetry.lock, go.sum, Cargo.lock, pom.xml, Gemfile.lock, composer.lock).
2. THE Scan_API SHALL expose the SBOM at `/api/code-scan/sbom/{scan_id}/{repo_id}` returning the CycloneDX JSON document.
3. THE SBOM_Generator SHALL include component name, version, ecosystem, and purl (Package URL) for each identified dependency.
4. IF no lockfiles are found in a repository, THEN THE SBOM_Generator SHALL produce an empty CycloneDX document with zero components and a metadata note indicating no lockfiles were detected.

### Requirement 4: Cryptographic Bill of Materials (CBOM)

**User Story:** As a security analyst, I want cryptographic algorithm detection across repositories, so that I can identify weak crypto and quantum-risk patterns.

#### Acceptance Criteria

1. WHEN a scan completes, THE CBOM_Scanner SHALL identify all cryptographic algorithms, key sizes, and protocol versions used in the scanned codebase.
2. THE CBOM_Scanner SHALL classify each detected algorithm as SAFE, WEAK, or QUANTUM_RISK based on current NIST guidance.
3. THE Scan_API SHALL expose CBOM results at `/api/code-scan/cbom/{scan_id}/{repo_id}` returning a JSON array of crypto usage records.
4. WHEN a WEAK or QUANTUM_RISK algorithm is detected, THE CBOM_Scanner SHALL generate a finding record with severity MEDIUM (WEAK) or HIGH (QUANTUM_RISK) and persist it alongside standard findings.

### Requirement 5: Software Composition Analysis (SCA)

**User Story:** As a security analyst, I want CVE lookup with reachability analysis for all dependencies, so that I can prioritize vulnerabilities that are actually exploitable.

#### Acceptance Criteria

1. WHEN the SCA option is enabled (default: enabled), THE SCA_Engine SHALL query the OSV.dev batch API for known CVEs matching each dependency identified in the SBOM.
2. THE SCA_Engine SHALL perform LLM-based reachability analysis to determine whether vulnerable code paths are actually invoked by the scanned repository.
3. THE Scan_API SHALL expose SCA results at `/api/code-scan/sca/{scan_id}/{repo_id}` returning CVE records with reachability verdicts (REACHABLE, UNREACHABLE, UNKNOWN).
4. WHEN a CVE is classified as REACHABLE, THE SCA_Engine SHALL create a finding with severity mapped from the CVE CVSS score (CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW < 4.0).
5. IF the OSV.dev API is unreachable, THEN THE SCA_Engine SHALL log a warning, mark SCA results as INCOMPLETE, and continue the scan without SCA enrichment.

### Requirement 6: Cross-Repository Exploit Chain Detection

**User Story:** As a security analyst, I want to see how vulnerabilities across multiple repositories can be chained together, so that I can identify systemic risks.

#### Acceptance Criteria

1. WHEN a multi-repo scan includes two or more repositories, THE Chain_Reasoner SHALL construct a dependency graph across all scanned repositories and identify candidate exploit chains.
2. THE Chain_Reasoner SHALL score each candidate chain using an LLM call that evaluates exploitability, impact, and chain feasibility.
3. THE Scan_API SHALL expose exploit chains at `/api/code-scan/chains/{scan_id}` returning an array of chain objects each containing ordered steps, affected repos, severity, and a confidence score.
4. THE Chain_Reasoner SHALL limit chain length to a configurable maximum (default 4 hops) to bound computational cost.
5. WHEN the number of candidate chains exceeds the configured maximum (default 400), THE Chain_Reasoner SHALL prioritize candidates by constituent finding severity and prune lower-priority candidates.

### Requirement 7: Auto-PR Fix Generation

**User Story:** As a DevOps engineer, I want the scanner to generate fix patches and open PRs automatically, so that remediation is accelerated.

#### Acceptance Criteria

1. WHEN the auto_pr option is enabled and a scan produces findings at or above the configured minimum severity (default HIGH), THE Auto_PR_Publisher SHALL generate unified diffs for each fixable finding using a dedicated LLM repair call.
2. THE Auto_PR_Publisher SHALL validate generated patches syntactically (ast.parse for Python, json.loads for JSON, yaml.safe_load for YAML, bracket-balance for JS/TS/Go) and discard patches that fail validation.
3. WHEN patches are validated, THE Auto_PR_Publisher SHALL open one Pull Request per repository on GitHub using the configured write token, with all accepted patches consolidated into a single branch.
4. THE Auto_PR_Publisher SHALL mark all generated PRs as draft by default.
5. THE Scan_API SHALL expose PR status at `/api/code-scan/prs/{scan_id}` returning PR URLs, status (DRAFT, OPEN, MERGED, CLOSED), and the list of findings addressed by each PR.
6. IF the GitHub write token is not configured or lacks required scopes, THEN THE Auto_PR_Publisher SHALL skip PR creation, log a warning, and still persist generated patches for manual download.

### Requirement 8: License Compliance Scanning

**User Story:** As a CISO, I want license risk classification for all dependencies, so that I can ensure compliance with organizational policies.

#### Acceptance Criteria

1. WHEN a scan completes, THE License_Scanner SHALL classify each dependency's license into risk categories: PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, COMMERCIAL, UNKNOWN.
2. THE License_Scanner SHALL flag dependencies with STRONG_COPYLEFT or UNKNOWN licenses as requiring review.
3. THE Scan_API SHALL expose license results at `/api/code-scan/licenses/{scan_id}/{repo_id}` returning a per-dependency license classification.
4. THE License_Scanner SHALL deduplicate license lookups by (package, version, ecosystem) tuple and cache results for the duration of the scan process.

### Requirement 9: Container and Dockerfile Analysis

**User Story:** As a DevOps engineer, I want Dockerfile misconfigurations and base image risks identified during scanning, so that container security is assessed alongside code security.

#### Acceptance Criteria

1. WHEN a repository contains Dockerfile(s), THE Container_Analyzer SHALL analyze them for misconfigurations (running as root, missing health checks, pinned vs unpinned base images, exposed secrets in build args).
2. THE Container_Analyzer SHALL classify base images by known vulnerability status using the same OSV.dev lookup mechanism as SCA.
3. THE Scan_API SHALL expose container findings at `/api/code-scan/container/{scan_id}/{repo_id}` returning an array of container-specific finding records.
4. WHEN a critical misconfiguration is detected (e.g., running as root in production, secrets in build args), THE Container_Analyzer SHALL generate a finding with severity HIGH or CRITICAL.

### Requirement 10: Budget Tracking and Enforcement

**User Story:** As a platform admin, I want per-scan and rolling cost enforcement, so that LLM spending remains within approved limits.

#### Acceptance Criteria

1. THE Budget_Tracker SHALL track token usage and compute cost for every LLM call at per-scan, per-repo, and rolling 30-day granularity.
2. WHEN accumulated cost reaches 80% of the configured budget limit, THE Budget_Tracker SHALL emit a warning event accessible via the scan status endpoint.
3. IF accumulated cost reaches the configured budget limit, THEN THE Budget_Tracker SHALL halt the current scan gracefully, persist all findings generated so far, and mark the scan status as BUDGET_EXCEEDED.
4. THE Scan_API SHALL expose budget metrics at `/api/code-scan/budget` returning current spend, remaining budget, and per-scan cost breakdowns.
5. WHILE a scan is in progress, THE Budget_Tracker SHALL update cost metrics after each LLM call so that the status endpoint reflects near-real-time spend.

### Requirement 11: Scan Configuration

**User Story:** As a platform admin, I want to configure scan parameters (model, budget, feature toggles), so that scans can be tailored to organizational needs.

#### Acceptance Criteria

1. THE Scan_API SHALL accept a configuration object in scan start requests specifying: model name, budget limit (USD), and individual feature toggles for each scan module (SAST, SCA, SBOM, CBOM, license scan, container analysis, chain reasoning, auto-PR), plus auto-PR minimum severity, diff-aware enabled/disabled, and concurrency limit.
2. WHEN configuration parameters are omitted from a request, THE Scan_Orchestrator SHALL use the platform defaults stored in the code_scan_settings database table.
3. THE Scan_API SHALL expose a `/api/code-scan/config` endpoint for Admin-role users to read and update platform-wide default configuration.
4. THE Scan_Orchestrator SHALL validate all configuration values and reject invalid combinations (e.g., budget below $2.00, concurrency above 20) with descriptive error messages.
5. THE Scan_Orchestrator SHALL skip disabled modules entirely (no LLM calls, no API lookups) to save time and cost when a user deselects them.

### Requirement 12: Frontend — Pre-Scan Configuration Panel

**User Story:** As a security analyst, I want full control over what gets scanned and what reports are generated BEFORE starting a scan, so that I can tailor the output to my specific needs and avoid unnecessary cost.

#### Acceptance Criteria

1. WHEN a user opens the CodeScan_Frontend scan form, THE CodeScan_Frontend SHALL display a repository input area supporting: (a) a multi-line text field (one repo per line, supports `owner/repo` and `https://github.com/owner/repo` formats), (b) a file upload button accepting .txt files with newline-delimited repository identifiers, and (c) a paste-from-clipboard button.
2. THE CodeScan_Frontend SHALL display a "Scan Modules" section with individually togglable checkboxes for each analysis module:
   - ☑ SAST (Vulnerability Scanning) — always on by default, core finding engine
   - ☑ SCA (Software Composition Analysis) — CVE lookup via OSV.dev
   - ☑ SBOM Generation — CycloneDX component inventory
   - ☑ CBOM (Cryptographic BOM) — Crypto algorithm detection
   - ☐ License Compliance — Dependency license risk classification
   - ☐ Container Analysis — Dockerfile security checks
   - ☐ Cross-Repo Chain Reasoning — Exploit chain detection (multi-repo only)
   - ☐ Auto-PR (Fix Generation) — Generate patches and open PRs
3. WHEN the "Auto-PR" toggle is enabled, THE CodeScan_Frontend SHALL display additional options:
   - Minimum severity for fix generation (dropdown: CRITICAL, HIGH, MEDIUM, LOW)
   - PR mode (radio: Draft PR / Open PR / Dry-run only — patches saved but no PR opened)
   - Target branch override (optional text input, defaults to repo default branch)
4. THE CodeScan_Frontend SHALL display an "Advanced Options" expandable section with:
   - Budget limit (USD input, default from platform settings)
   - LLM Model selection (dropdown from available models)
   - Concurrency limit (number input, 1-20)
   - Diff-aware mode toggle (skip unchanged repos since last scan)
   - Generate lockfiles toggle (run package managers when no lockfile found)
5. WHEN a user hovers over any toggle, THE CodeScan_Frontend SHALL show a tooltip explaining what the module does and its approximate cost impact.
6. THE CodeScan_Frontend SHALL display an estimated cost range based on the number of repos and enabled modules (rough heuristic: ~$1.17/repo for full scan, less with modules disabled).
7. WHEN an Admin or Agent user clicks "Start Scan", THE CodeScan_Frontend SHALL send the full configuration (repos + all toggles + advanced options) to the POST `/api/code-scan/scans` endpoint.
8. WHILE a Viewer-role user accesses the CodeScan_Frontend, THE CodeScan_Frontend SHALL hide the scan form entirely and show only past scan results in read-only mode.
9. THE CodeScan_Frontend SHALL persist the user's last-used configuration in localStorage so that toggles are remembered between sessions.
10. THE CodeScan_Frontend SHALL provide a "Save as Template" button allowing users to save named scan configurations (e.g., "Quick SAST Only", "Full Compliance Scan") and a dropdown to load saved templates.

### Requirement 13: Frontend — SBOM Viewer

**User Story:** As a security analyst, I want to view the SBOM for each scanned repository in the UI, so that I can inspect the software component inventory.

#### Acceptance Criteria

1. WHEN a scan has completed, THE CodeScan_Frontend SHALL display an "SBOM" tab showing the component list with columns: Component Name, Version, Ecosystem, License, and Known CVE Count.
2. THE CodeScan_Frontend SHALL support filtering SBOM components by ecosystem and sorting by any column.
3. WHEN a user clicks a component row, THE CodeScan_Frontend SHALL expand the row to show associated CVEs (from SCA) and license details.

### Requirement 14: Frontend — Exploit Chain Visualization

**User Story:** As a security analyst, I want a visual representation of exploit chains, so that I can understand cross-repo attack paths.

#### Acceptance Criteria

1. WHEN exploit chains are detected, THE CodeScan_Frontend SHALL display a "Chains" tab showing each chain as an ordered list of steps with source repository, finding reference, and connecting arrows.
2. THE CodeScan_Frontend SHALL color-code chain steps by severity (CRITICAL: red, HIGH: orange, MEDIUM: yellow, LOW: green).
3. WHEN a user clicks a chain step, THE CodeScan_Frontend SHALL navigate to the corresponding finding detail view.

### Requirement 15: Frontend — SCA and CVE Findings

**User Story:** As a security analyst, I want to view CVE findings with reachability verdicts, so that I can prioritize remediation of exploitable vulnerabilities.

#### Acceptance Criteria

1. WHEN SCA results are available, THE CodeScan_Frontend SHALL display an "SCA" tab showing CVE records with columns: CVE ID, Package, Severity, CVSS Score, Reachability Verdict, and Fix Version (if available).
2. THE CodeScan_Frontend SHALL visually distinguish REACHABLE CVEs (highlighted) from UNREACHABLE and UNKNOWN CVEs.
3. THE CodeScan_Frontend SHALL support filtering SCA results by severity, reachability status, and ecosystem.

### Requirement 16: Frontend — Auto-PR Status Tracking

**User Story:** As a DevOps engineer, I want to see the status of auto-generated PRs, so that I can track remediation progress.

#### Acceptance Criteria

1. WHEN auto-PR is enabled and PRs have been generated, THE CodeScan_Frontend SHALL display a "PRs" tab showing each PR with: repository name, PR URL (clickable), status (DRAFT, OPEN, MERGED, CLOSED), and count of findings addressed.
2. THE CodeScan_Frontend SHALL refresh PR status on tab focus by querying `/api/code-scan/prs/{scan_id}`.

### Requirement 17: Frontend — License Compliance View

**User Story:** As a CISO, I want a license compliance summary in the UI, so that I can quickly identify licensing risks.

#### Acceptance Criteria

1. WHEN license scan results are available, THE CodeScan_Frontend SHALL display a "Licenses" tab showing a summary of license categories (PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, COMMERCIAL, UNKNOWN) with component counts.
2. THE CodeScan_Frontend SHALL highlight STRONG_COPYLEFT and UNKNOWN licensed components with a warning indicator.
3. THE CodeScan_Frontend SHALL support expanding each category to view individual component details.

### Requirement 18: Frontend — Container Security Findings

**User Story:** As a DevOps engineer, I want container security findings displayed in the UI, so that I can remediate Dockerfile issues.

#### Acceptance Criteria

1. WHEN container analysis results are available, THE CodeScan_Frontend SHALL display a "Container" tab showing Dockerfile findings with: file path, misconfiguration type, severity, and recommended fix.
2. THE CodeScan_Frontend SHALL group container findings by repository when displaying multi-repo scan results.

### Requirement 19: Unified Dashboard Integration

**User Story:** As a CISO, I want all new finding types (SBOM-based, SCA, chain, container, crypto) integrated into the Unified Vulnerability Dashboard, so that I have a single pane of glass for all security findings.

#### Acceptance Criteria

1. WHEN a scan completes, THE Scan_Orchestrator SHALL push all findings (holistic, SCA, CBOM, container) to the Unified_Dashboard using the existing finding ingestion interface with source_module set to "code_scan".
2. THE Scan_Orchestrator SHALL map new finding types to the Unified_Dashboard schema: finding_type field SHALL distinguish "sast", "sca", "cbom", "container", and "chain" findings.
3. THE Unified_Dashboard SHALL display the finding_type as a filterable attribute in the findings table.
4. WHEN an exploit chain is detected, THE Scan_Orchestrator SHALL create a single Unified_Dashboard finding of type "chain" with severity equal to the chain's overall severity and a description summarizing the chain path.

### Requirement 20: Resumable Scan State

**User Story:** As a platform admin, I want scans to be resumable after interruption, so that work is not lost due to transient failures or restarts.

#### Acceptance Criteria

1. THE Scan_Orchestrator SHALL persist scan state (per-repo status, findings, SBOM data, SCA results, chain data) to the Scan_State_DB after each repository completes.
2. WHEN a scan is resumed via `/api/code-scan/resume/{scan_id}`, THE Scan_Orchestrator SHALL skip repositories already marked COMPLETED and continue from the first non-completed repository.
3. IF the Angela backend process restarts while a scan is in progress, THEN THE Scan_Orchestrator SHALL mark any IN_PROGRESS repositories as INTERRUPTED and allow the scan to be resumed.

### Requirement 21: Output Format Support

**User Story:** As a security analyst, I want scan results in multiple formats (JSON, SARIF, Markdown, HTML), so that I can integrate with different tools and reporting workflows.

#### Acceptance Criteria

1. THE Scan_API SHALL expose a `/api/code-scan/export/{scan_id}` endpoint accepting a `format` query parameter with values: json, sarif, markdown, html.
2. WHEN format is "sarif", THE Scan_API SHALL return a SARIF v2.1.0 document compatible with GitHub Code Scanning upload.
3. WHEN format is "html", THE Scan_API SHALL return a self-contained interactive HTML dashboard with severity breakdowns, finding cards, and SBOM/SCA/Chain panels.
4. WHEN format is "json", THE Scan_API SHALL return the complete structured findings document including all metadata, SCA results, and chain data.

### Requirement 22: RBAC Enforcement for Scanner Endpoints

**User Story:** As a platform operator, I want scanner endpoints to respect the existing RBAC system, so that access is controlled by role.

#### Acceptance Criteria

1. WHILE a user has the Admin role, THE Scan_API SHALL allow all operations including configuration changes, scan initiation, and scan deletion.
2. WHILE a user has the Agent role, THE Scan_API SHALL allow scan initiation and read access to all results, but deny configuration changes.
3. WHILE a user has the Viewer role, THE Scan_API SHALL allow read access to scan results and exports, but deny scan initiation and configuration changes.
4. THE Scan_API SHALL integrate with the existing API_Guard middleware using the module identifier "code_scan" for all endpoints under `/api/code-scan`.

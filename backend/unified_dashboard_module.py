"""Angela Unified Vulnerability Dashboard Module.

Consolidates findings from all 7 Angela security modules into a unified
view with deduplication, lifecycle management, build comparison, and
executive metrics. Follows the existing FastAPI + SQLite WAL pattern.
"""

from __future__ import annotations

import asyncio
import csv
import datetime
import io
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/unified-dashboard")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']

VALID_TRANSITIONS = {
    'Open': ['Acknowledged', 'Wont_Fix', 'False_Positive'],
    'Acknowledged': ['In_Progress', 'Open'],
    'In_Progress': ['Fixed', 'Open'],
    'Fixed': ['Verified', 'Open'],
    'Verified': ['Closed', 'Open'],
    'Closed': ['Open'],
    'Wont_Fix': ['Open'],
    'False_Positive': ['Open'],
}

REQUIRES_COMMENT = {'Wont_Fix', 'False_Positive'}

SLA_THRESHOLDS = {'Critical': 7, 'High': 30, 'Medium': 90}

SEVERITY_WEIGHTS = {'Critical': 10, 'High': 5, 'Medium': 2, 'Low': 1, 'Informational': 0}

CWE_BY_VULN_CLASS = {
    'sql_injection': 'CWE-89', 'xss': 'CWE-79', 'csrf': 'CWE-352',
    'path_traversal': 'CWE-22', 'command_injection': 'CWE-78',
    'insecure_deserialization': 'CWE-502', 'xxe': 'CWE-611',
    'ssrf': 'CWE-918', 'open_redirect': 'CWE-601', 'idor': 'CWE-639',
    'broken_authentication': 'CWE-287', 'sensitive_data_exposure': 'CWE-200',
    'security_misconfiguration': 'CWE-16', 'insufficient_logging': 'CWE-778',
    'hardcoded_credentials': 'CWE-798', 'weak_crypto': 'CWE-327',
    'buffer_overflow': 'CWE-120', 'race_condition': 'CWE-362',
    'privilege_escalation': 'CWE-269', 'dos': 'CWE-400',
    'information_disclosure': 'CWE-200', 'spoofing': 'CWE-290',
    'tampering': 'CWE-345', 'repudiation': 'CWE-778',
    'elevation_of_privilege': 'CWE-269',
}

SUPPORTED_MODULES = [
    'mobile_sast', 'mobile_dast', 'code_scan', 'easm', 'bas',
    'threat_model', 'vuln_management',
]

STOP_WORDS = {'', 'the', 'a', 'an', 'in', 'of', 'on', 'for', 'to', 'and', 'is', 'it', 'by', 'at', 'or'}


# ---------------------------------------------------------------------------
# Pydantic Request/Response Models
# ---------------------------------------------------------------------------

class StatusTransitionRequest(BaseModel):
    status: str
    comment: Optional[str] = None
    user_id: Optional[str] = None
    user_display_name: Optional[str] = None


class AssignRequest(BaseModel):
    assignee_id: str
    user_id: Optional[str] = None
    user_display_name: Optional[str] = None


class BulkStatusRequest(BaseModel):
    finding_ids: List[str]
    status: str
    comment: Optional[str] = None
    user_id: Optional[str] = None


class UserRequest(BaseModel):
    email: str
    display_name: str
    role_id: Optional[str] = None


class FindingResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    cwe_id: Optional[str] = None
    affected_component: Optional[str] = None
    status: str
    assignee_id: Optional[str] = None
    correlation_key: str
    module_tags: Optional[Any] = None
    evidence_count: int = 1
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    resolved_at: Optional[str] = None
    sla_breach: int = 0
    review_flag: int = 0


class FindingListResponse(BaseModel):
    findings: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int


class MetricsResponse(BaseModel):
    risk_posture_score: float
    severity_distribution: Dict[str, int]
    mttr_by_severity: Dict[str, float]
    sla_compliance: Dict[str, Any]
    open_count: int
    closed_count: int


class BuildComparisonResponse(BaseModel):
    new: List[str]
    persisted: List[str]
    fixed: List[str]
    new_count: int
    persisted_count: int
    fixed_count: int


# ---------------------------------------------------------------------------
# Deduplication Engine (Task 3.2)
# ---------------------------------------------------------------------------

def normalize_component_path(path: str) -> str:
    """Normalize file paths: strip leading slashes, resolve common prefixes, lowercase."""
    if not path:
        return ''
    path = path.replace("\\", "/").strip("/")
    # Remove common prefixes like src/, app/, lib/, main/
    for prefix in ("src/", "app/", "lib/", "main/"):
        if path.lower().startswith(prefix):
            path = path[len(prefix):]
            break
    # Strip any remaining leading slashes after prefix removal
    path = path.strip("/")
    return path.lower()


def compute_correlation_key(cwe_id: Optional[str], affected_component: Optional[str]) -> str:
    """Primary match: exact CWE + normalized component path."""
    norm_component = normalize_component_path(affected_component or '')
    cwe_part = (cwe_id or 'NONE').upper()
    return f"{cwe_part}:{norm_component}"


def tokenize_title(title: str) -> set:
    """Split title into lowercase word tokens for Jaccard comparison, minus stop words."""
    if not title:
        return set()
    return set(re.split(r'\W+', title.lower())) - STOP_WORDS


def jaccard_similarity(tokens_a: set, tokens_b: set) -> float:
    """Compute Jaccard similarity between two token sets."""
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def deduplicate_finding(new_finding: dict) -> Tuple[Optional[str], str]:
    """
    Returns (matched_unified_id, action) where action is:
    - 'merge': exact correlation key match → auto-merge
    - 'fuzzy_merge': Jaccard > 0.7 same component → auto-merge
    - 'review': Jaccard 0.4-0.7 same component → flag for manual review
    - 'new': no match → create new unified finding
    """
    correlation_key = compute_correlation_key(
        new_finding.get('cwe_id'), new_finding.get('affected_component')
    )

    # Step 1: Exact correlation key match
    existing = database.find_by_correlation_key(correlation_key)
    if existing:
        return (existing['id'], 'merge')

    # Step 2: Token-based title similarity (same component only)
    new_tokens = tokenize_title(new_finding.get('title', ''))
    norm_component = normalize_component_path(new_finding.get('affected_component', ''))

    candidates = database.find_by_component(new_finding.get('affected_component', ''))

    best_score = 0.0
    best_candidate = None
    for candidate in candidates:
        candidate_tokens_str = candidate.get('title_tokens', '')
        if candidate_tokens_str:
            candidate_tokens = set(candidate_tokens_str.split())
        else:
            candidate_tokens = tokenize_title(candidate.get('title', ''))
        score = jaccard_similarity(new_tokens, candidate_tokens)
        if score > best_score:
            best_score = score
            best_candidate = candidate

    if best_score > 0.7 and best_candidate:
        return (best_candidate['id'], 'fuzzy_merge')
    elif best_score >= 0.4 and best_candidate:
        return (best_candidate['id'], 'review')

    return (None, 'new')


# ---------------------------------------------------------------------------
# Source Module Normalizers (Task 3.3)
# ---------------------------------------------------------------------------

def _severity_from_risk_rating(risk_rating: str) -> str:
    """Map mobile DAST risk_rating to standard severity."""
    mapping = {
        'critical': 'Critical', 'high': 'High', 'medium': 'Medium',
        'low': 'Low', 'informational': 'Informational', 'info': 'Informational',
    }
    return mapping.get((risk_rating or '').lower(), 'Medium')


def _severity_from_cvss(cvss_score) -> str:
    """Map CVSS score to severity."""
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return 'Medium'
    if score >= 9.0:
        return 'Critical'
    elif score >= 7.0:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    elif score > 0:
        return 'Low'
    return 'Informational'


def _severity_from_risk_level(risk_level: str) -> str:
    """Map threat model risk_level to severity."""
    mapping = {
        'critical': 'Critical', 'high': 'High', 'medium': 'Medium',
        'low': 'Low', 'very high': 'Critical', 'very low': 'Informational',
    }
    return mapping.get((risk_level or '').lower(), 'Medium')


def _map_category_to_cwe(category: str) -> Optional[str]:
    """Attempt to map a vulnerability category to a CWE using CWE_BY_VULN_CLASS."""
    if not category:
        return None
    key = category.lower().replace(' ', '_').replace('-', '_')
    return CWE_BY_VULN_CLASS.get(key)


def _validate_severity(severity: str) -> str:
    """Ensure severity is a valid enum value."""
    if severity in SEVERITY_ORDER:
        return severity
    # Try case-insensitive match
    for s in SEVERITY_ORDER:
        if s.lower() == (severity or '').lower():
            return s
    return 'Medium'


def normalize_mobile_sast_finding(raw: dict) -> dict:
    """Normalize mobile_sast_findings schema to unified format."""
    return {
        'title': raw.get('title') or raw.get('finding_title', 'Untitled Finding'),
        'description': raw.get('description') or raw.get('finding_description', ''),
        'severity': _validate_severity(raw.get('severity', 'Medium')),
        'cwe_id': raw.get('cwe_id') or _map_category_to_cwe(raw.get('category', '')),
        'affected_component': raw.get('file_path') or raw.get('affected_component', ''),
        'source_module': 'mobile_sast',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('scan_id', ''),
        'source_evidence': raw.get('evidence') or raw.get('code_snippet', ''),
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


def normalize_mobile_dast_finding(raw: dict) -> dict:
    """Normalize mobile_dast_findings schema to unified format."""
    # Extract component from tags or URL
    component = ''
    tags = raw.get('tags')
    if tags:
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, TypeError):
                tags = [tags]
        if isinstance(tags, list) and tags:
            component = tags[0]
    if not component:
        component = raw.get('url') or raw.get('endpoint') or raw.get('affected_component', '')

    return {
        'title': raw.get('title') or raw.get('finding_title', 'Untitled Finding'),
        'description': raw.get('description') or raw.get('technical_details', ''),
        'severity': _severity_from_risk_rating(raw.get('risk_rating') or raw.get('severity', 'Medium')),
        'cwe_id': raw.get('cwe_id') or _map_category_to_cwe(raw.get('category', '')),
        'affected_component': component,
        'source_module': 'mobile_dast',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('scan_id', ''),
        'source_evidence': raw.get('technical_details') or raw.get('evidence', ''),
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


def normalize_code_scan_finding(raw: dict) -> dict:
    """Normalize code_scan_findings schema to unified format."""
    evidence = raw.get('description', '')
    poc = raw.get('poc') or raw.get('proof_of_concept', '')
    if poc:
        evidence = f"{evidence}\n\nPoC: {poc}" if evidence else poc

    return {
        'title': raw.get('title') or raw.get('finding_title', 'Untitled Finding'),
        'description': raw.get('description', ''),
        'severity': _validate_severity(raw.get('severity', 'Medium')),
        'cwe_id': raw.get('cwe_id') or _map_category_to_cwe(raw.get('category', '')),
        'affected_component': raw.get('file_path') or raw.get('affected_component', ''),
        'source_module': 'code_scan',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('scan_id', ''),
        'source_evidence': evidence,
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


def normalize_easm_finding(raw: dict) -> dict:
    """Normalize easm_findings schema to unified format."""
    # Build component from hostname:port
    hostname = raw.get('hostname') or raw.get('host', '')
    port = raw.get('port', '')
    component = f"{hostname}:{port}" if port else hostname

    # Map CVE to CWE (simplified lookup)
    cwe_id = raw.get('cwe_id')
    if not cwe_id:
        cve_id = raw.get('cve_id', '')
        # Use category mapping as fallback
        cwe_id = _map_category_to_cwe(raw.get('category', ''))

    return {
        'title': raw.get('title') or raw.get('finding_title', 'Untitled Finding'),
        'description': raw.get('description', ''),
        'severity': _validate_severity(raw.get('severity', 'Medium')),
        'cwe_id': cwe_id,
        'affected_component': component or raw.get('affected_component', ''),
        'source_module': 'easm',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('scan_id', ''),
        'source_evidence': raw.get('evidence') or raw.get('details', ''),
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


def normalize_bas_result(raw: dict) -> dict:
    """Normalize bas_results schema to unified format."""
    # Build component from target + asset
    target = raw.get('target') or raw.get('target_system', '')
    asset = raw.get('asset') or raw.get('asset_name', '')
    component = f"{target}/{asset}" if asset else target

    # Map MITRE technique to CWE (use category)
    cwe_id = raw.get('cwe_id')
    if not cwe_id:
        cwe_id = _map_category_to_cwe(raw.get('category', '') or raw.get('attack_type', ''))

    return {
        'title': raw.get('scenario_name') or raw.get('title', 'Untitled Finding'),
        'description': raw.get('description') or raw.get('scenario_description', ''),
        'severity': _validate_severity(raw.get('severity', 'Medium')),
        'cwe_id': cwe_id,
        'affected_component': component or raw.get('affected_component', ''),
        'source_module': 'bas',
        'source_finding_id': raw.get('id') or raw.get('result_id', ''),
        'source_scan_id': raw.get('run_id') or raw.get('scan_id', ''),
        'source_evidence': raw.get('evidence') or raw.get('execution_log', ''),
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


def normalize_threat_model_finding(raw: dict) -> dict:
    """Normalize threat_model_findings schema to unified format."""
    # Map STRIDE category to CWE
    cwe_id = raw.get('cwe_id')
    if not cwe_id:
        stride_category = raw.get('stride_category') or raw.get('category', '')
        cwe_id = _map_category_to_cwe(stride_category.lower().replace(' ', '_') if stride_category else '')

    return {
        'title': raw.get('title') or raw.get('threat_title', 'Untitled Finding'),
        'description': raw.get('description') or raw.get('attack_scenario', ''),
        'severity': _severity_from_risk_level(raw.get('risk_level') or raw.get('severity', 'Medium')),
        'cwe_id': cwe_id,
        'affected_component': raw.get('affected_component') or raw.get('target_component', ''),
        'source_module': 'threat_model',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('session_id') or raw.get('scan_id', ''),
        'source_evidence': raw.get('attack_scenario') or raw.get('evidence', ''),
        'source_remediation': raw.get('remediation') or raw.get('mitigation', ''),
    }


def normalize_vuln_finding(raw: dict) -> dict:
    """Normalize vuln_findings (vulnerability management) schema to unified format."""
    # Map CVSS to severity
    severity = raw.get('severity')
    if not severity:
        severity = _severity_from_cvss(raw.get('cvss_score') or raw.get('cvss', 0))
    else:
        severity = _validate_severity(severity)

    # Map CVE to CWE
    cwe_id = raw.get('cwe_id')
    if not cwe_id:
        cwe_id = _map_category_to_cwe(raw.get('category', ''))

    return {
        'title': raw.get('title') or raw.get('vuln_title', 'Untitled Finding'),
        'description': raw.get('description', ''),
        'severity': severity,
        'cwe_id': cwe_id,
        'affected_component': raw.get('asset') or raw.get('affected_component', ''),
        'source_module': 'vuln_management',
        'source_finding_id': raw.get('id') or raw.get('finding_id', ''),
        'source_scan_id': raw.get('report_id') or raw.get('scan_id', ''),
        'source_evidence': raw.get('raw_data') or raw.get('evidence', ''),
        'source_remediation': raw.get('remediation') or raw.get('recommendation', ''),
    }


# Normalizer dispatch map
NORMALIZERS = {
    'mobile_sast': normalize_mobile_sast_finding,
    'mobile_dast': normalize_mobile_dast_finding,
    'code_scan': normalize_code_scan_finding,
    'easm': normalize_easm_finding,
    'bas': normalize_bas_result,
    'threat_model': normalize_threat_model_finding,
    'vuln_management': normalize_vuln_finding,
}


# ---------------------------------------------------------------------------
# Ingestion Orchestrator (Task 3.4)
# ---------------------------------------------------------------------------

# Source table name mapping for fetching raw findings
SOURCE_TABLE_MAP = {
    'mobile_sast': 'mobile_sast_findings',
    'mobile_dast': 'mobile_dast_findings',
    'code_scan': 'code_scan_findings',
    'easm': 'easm_findings',
    'bas': 'bas_results',
    'threat_model': 'threat_model_findings',
    'vuln_management': 'vuln_findings',
}


def _fetch_raw_findings(module_name: str, scan_id: str) -> List[dict]:
    """Fetch raw findings from source module table for a given scan."""
    table_name = SOURCE_TABLE_MAP.get(module_name)
    if not table_name:
        return []

    # Determine scan_id column name
    scan_id_col = 'scan_id'
    if module_name == 'bas':
        scan_id_col = 'run_id'
    elif module_name == 'threat_model':
        scan_id_col = 'session_id'
    elif module_name == 'vuln_management':
        scan_id_col = 'report_id'

    try:
        conn = database.get_db_connection()
        conn.row_factory = database.sqlite3.Row
        c = conn.cursor()
        c.execute(f'SELECT * FROM {table_name} WHERE {scan_id_col} = ?', (scan_id,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to fetch raw findings from {table_name} for scan {scan_id}: {e}")
        return []


def _escalate_severity(current_severity: str, new_severity: str) -> str:
    """Return the higher severity between current and new."""
    current_idx = SEVERITY_ORDER.index(current_severity) if current_severity in SEVERITY_ORDER else 4
    new_idx = SEVERITY_ORDER.index(new_severity) if new_severity in SEVERITY_ORDER else 4
    return SEVERITY_ORDER[min(current_idx, new_idx)]


def _get_scope_for_module(module_name: str, raw_findings: List[dict]) -> Optional[str]:
    """Determine scope from raw findings (e.g., repo name, target)."""
    if not raw_findings:
        return None
    first = raw_findings[0]
    if module_name == 'code_scan':
        return first.get('repo') or first.get('repository') or first.get('scope')
    elif module_name == 'easm':
        return first.get('domain') or first.get('scope')
    elif module_name == 'threat_model':
        return first.get('application') or first.get('scope')
    return first.get('scope')


async def trigger_ingestion(module_name: str, scan_id: str) -> dict:
    """
    Main ingestion entry point. Fetch raw findings, normalize, deduplicate,
    create/update unified findings, run build comparison, create scan_run record.
    """
    if module_name not in SUPPORTED_MODULES:
        raise ValueError(f"Unsupported module: {module_name}")

    normalizer = NORMALIZERS.get(module_name)
    if not normalizer:
        raise ValueError(f"No normalizer for module: {module_name}")

    # Fetch raw findings from source table
    raw_findings = _fetch_raw_findings(module_name, scan_id)
    if not raw_findings:
        logger.info(f"No findings found for {module_name} scan {scan_id}")
        return {'status': 'no_findings', 'count': 0}

    scope = _get_scope_for_module(module_name, raw_findings)
    now = datetime.datetime.utcnow().isoformat()

    # Get previous scan run for build comparison
    previous_run = database.get_previous_scan_run(module_name, scope)

    current_finding_ids = []

    for raw in raw_findings:
        try:
            normalized = normalizer(raw)
        except Exception as e:
            logger.error(f"Normalization failed for finding {raw.get('id')}: {e}")
            continue

        # Run deduplication
        matched_id, action = deduplicate_finding(normalized)

        if action == 'merge' and matched_id:
            # Auto-merge: update existing finding
            existing = database.get_unified_finding(matched_id)
            if existing:
                new_severity = _escalate_severity(existing.get('severity', 'Medium'), normalized['severity'])
                module_tags = existing.get('module_tags', [])
                if isinstance(module_tags, str):
                    try:
                        module_tags = json.loads(module_tags)
                    except (json.JSONDecodeError, TypeError):
                        module_tags = []
                if normalized['source_module'] not in module_tags:
                    module_tags.append(normalized['source_module'])
                database.update_unified_finding(
                    matched_id,
                    severity=new_severity,
                    evidence_count=(existing.get('evidence_count', 1) + 1),
                    last_seen_at=now,
                    module_tags=module_tags,
                )
                # Add evidence source
                database.add_evidence_source(
                    unified_finding_id=matched_id,
                    source_module=normalized['source_module'],
                    source_finding_id=normalized['source_finding_id'],
                    source_scan_id=normalized['source_scan_id'],
                    source_title=normalized['title'],
                    source_severity=normalized['severity'],
                    source_evidence=normalized.get('source_evidence'),
                    source_remediation=normalized.get('source_remediation'),
                )
                current_finding_ids.append(matched_id)

        elif action == 'fuzzy_merge' and matched_id:
            # Fuzzy merge: same as merge
            existing = database.get_unified_finding(matched_id)
            if existing:
                new_severity = _escalate_severity(existing.get('severity', 'Medium'), normalized['severity'])
                module_tags = existing.get('module_tags', [])
                if isinstance(module_tags, str):
                    try:
                        module_tags = json.loads(module_tags)
                    except (json.JSONDecodeError, TypeError):
                        module_tags = []
                if normalized['source_module'] not in module_tags:
                    module_tags.append(normalized['source_module'])
                database.update_unified_finding(
                    matched_id,
                    severity=new_severity,
                    evidence_count=(existing.get('evidence_count', 1) + 1),
                    last_seen_at=now,
                    module_tags=module_tags,
                )
                database.add_evidence_source(
                    unified_finding_id=matched_id,
                    source_module=normalized['source_module'],
                    source_finding_id=normalized['source_finding_id'],
                    source_scan_id=normalized['source_scan_id'],
                    source_title=normalized['title'],
                    source_severity=normalized['severity'],
                    source_evidence=normalized.get('source_evidence'),
                    source_remediation=normalized.get('source_remediation'),
                )
                current_finding_ids.append(matched_id)

        elif action == 'review' and matched_id:
            # Flag for manual review, but still link evidence
            existing = database.get_unified_finding(matched_id)
            if existing:
                database.update_unified_finding(matched_id, review_flag=1)
                database.add_evidence_source(
                    unified_finding_id=matched_id,
                    source_module=normalized['source_module'],
                    source_finding_id=normalized['source_finding_id'],
                    source_scan_id=normalized['source_scan_id'],
                    source_title=normalized['title'],
                    source_severity=normalized['severity'],
                    source_evidence=normalized.get('source_evidence'),
                    source_remediation=normalized.get('source_remediation'),
                )
                current_finding_ids.append(matched_id)

        else:
            # New finding
            correlation_key = compute_correlation_key(
                normalized.get('cwe_id'), normalized.get('affected_component')
            )
            title_tokens = ' '.join(tokenize_title(normalized.get('title', '')))

            finding_data = {
                'id': str(uuid.uuid4()),
                'title': normalized['title'],
                'description': normalized.get('description', ''),
                'severity': normalized['severity'],
                'cwe_id': normalized.get('cwe_id'),
                'affected_component': normalized.get('affected_component', ''),
                'status': 'Open',
                'correlation_key': correlation_key,
                'title_tokens': title_tokens,
                'module_tags': json.dumps([normalized['source_module']]),
                'evidence_count': 1,
                'first_seen_at': now,
                'last_seen_at': now,
                'sla_breach': 0,
                'review_flag': 0,
            }

            # Auto-assign by component owner
            if normalized.get('affected_component'):
                owner_id = database.get_component_owner(normalized['affected_component'])
                if owner_id:
                    finding_data['assignee_id'] = owner_id

            finding_id = database.create_unified_finding(finding_data)

            # Add evidence source
            database.add_evidence_source(
                unified_finding_id=finding_id,
                source_module=normalized['source_module'],
                source_finding_id=normalized['source_finding_id'],
                source_scan_id=normalized['source_scan_id'],
                source_title=normalized['title'],
                source_severity=normalized['severity'],
                source_evidence=normalized.get('source_evidence'),
                source_remediation=normalized.get('source_remediation'),
            )

            # Audit log for creation
            database.add_audit_entry(
                unified_finding_id=finding_id,
                action='created',
                new_value='Open',
                user_display_name='system (ingestion)',
            )

            current_finding_ids.append(finding_id)

    # Build comparison
    comparison = compute_build_comparison(module_name, scope, current_finding_ids, previous_run)

    # Auto-fix status transitions for findings classified as FIXED
    auto_fix_status_transitions(comparison.get('fixed', []))

    # Create scan run record
    database.create_scan_run(
        source_module=module_name,
        source_scan_id=scan_id,
        scope=scope,
        finding_ids=current_finding_ids,
        new_count=comparison.get('new_count', 0),
        persisted_count=comparison.get('persisted_count', 0),
        fixed_count=comparison.get('fixed_count', 0),
    )

    # Compute SLA breaches
    compute_sla_breaches()

    return {
        'status': 'completed',
        'count': len(current_finding_ids),
        'new': comparison.get('new_count', 0),
        'persisted': comparison.get('persisted_count', 0),
        'fixed': comparison.get('fixed_count', 0),
    }


# ---------------------------------------------------------------------------
# Build Comparison Engine (Task 4.1)
# ---------------------------------------------------------------------------

def compute_build_comparison(
    module_name: str,
    scope: Optional[str],
    current_finding_ids: List[str],
    previous_run: Optional[dict],
) -> dict:
    """
    Compare current finding IDs with previous scan run.
    Returns {new: [], persisted: [], fixed: [], new_count, persisted_count, fixed_count}.
    """
    current_set = set(current_finding_ids)

    if not previous_run:
        # No previous run — all are new
        return {
            'new': list(current_set),
            'persisted': [],
            'fixed': [],
            'new_count': len(current_set),
            'persisted_count': 0,
            'fixed_count': 0,
        }

    previous_ids = previous_run.get('finding_ids', [])
    previous_set = set(previous_ids)

    new_ids = list(current_set - previous_set)
    persisted_ids = list(current_set & previous_set)
    fixed_ids = list(previous_set - current_set)

    return {
        'new': new_ids,
        'persisted': persisted_ids,
        'fixed': fixed_ids,
        'new_count': len(new_ids),
        'persisted_count': len(persisted_ids),
        'fixed_count': len(fixed_ids),
    }


# ---------------------------------------------------------------------------
# Auto-Fix Status Transitions (Task 4.2)
# ---------------------------------------------------------------------------

def auto_fix_status_transitions(fixed_finding_ids: List[str]):
    """
    For findings classified as FIXED: if current status is Open, Acknowledged,
    or In_Progress, transition to Fixed. Create audit log entry.
    """
    statuses_to_transition = {'Open', 'Acknowledged', 'In_Progress'}

    for finding_id in fixed_finding_ids:
        finding = database.get_unified_finding(finding_id)
        if not finding:
            continue

        current_status = finding.get('status', '')
        if current_status in statuses_to_transition:
            now = datetime.datetime.utcnow().isoformat()
            database.update_unified_finding(
                finding_id,
                status='Fixed',
                resolved_at=now,
            )
            database.add_audit_entry(
                unified_finding_id=finding_id,
                action='status_change',
                previous_value=current_status,
                new_value='Fixed',
                user_display_name='system (build comparison)',
            )


# ---------------------------------------------------------------------------
# Status Transition Validation (Task 7.1)
# ---------------------------------------------------------------------------

def validate_transition(current_status: str, target_status: str, comment: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validate a status transition.
    Returns (valid, error_msg). If valid, error_msg is empty string.
    """
    valid_targets = VALID_TRANSITIONS.get(current_status, [])
    if target_status not in valid_targets:
        return (False, f"Invalid transition from {current_status} to {target_status}. Valid: {valid_targets}")

    if target_status in REQUIRES_COMMENT and not comment:
        return (False, f"Comment required for transition to {target_status}")

    return (True, '')


# ---------------------------------------------------------------------------
# SLA Breach Detection (Task 7.2)
# ---------------------------------------------------------------------------

def compute_sla_breaches():
    """
    Batch check all open findings against SLA thresholds.
    Update sla_breach flag on findings exceeding threshold.
    Critical: 7d, High: 30d, Medium: 90d.
    """
    now = datetime.datetime.utcnow()

    # Get all open findings (not resolved)
    filters = {'status': ['Open', 'Acknowledged', 'In_Progress']}
    findings, _ = database.list_unified_findings(filters=filters, page=1, page_size=100000)

    for finding in findings:
        severity = finding.get('severity', '')
        threshold_days = SLA_THRESHOLDS.get(severity)
        if threshold_days is None:
            # Low and Informational have no SLA threshold
            if finding.get('sla_breach', 0) != 0:
                database.update_unified_finding(finding['id'], sla_breach=0)
            continue

        first_seen = finding.get('first_seen_at')
        if not first_seen:
            continue

        try:
            first_seen_dt = datetime.datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            # Make naive for comparison if needed
            if first_seen_dt.tzinfo:
                first_seen_dt = first_seen_dt.replace(tzinfo=None)
            age_days = (now - first_seen_dt).total_seconds() / 86400.0
        except (ValueError, TypeError):
            continue

        should_breach = 1 if age_days > threshold_days else 0
        if finding.get('sla_breach', 0) != should_breach:
            database.update_unified_finding(finding['id'], sla_breach=should_breach)


# ---------------------------------------------------------------------------
# API Endpoints: Findings CRUD (Task 5.1)
# ---------------------------------------------------------------------------

@router.get("/findings")
async def list_findings(
    module: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    component: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_field: str = Query('first_seen_at'),
    sort_dir: str = Query('DESC'),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Paginated list of findings with filters, sort, and pagination."""
    filters = {}
    if module:
        filters['module'] = module
    if severity:
        filters['severity'] = severity.split(',') if ',' in severity else severity
    if status:
        filters['status'] = status.split(',') if ',' in status else status
    if cwe_id:
        filters['cwe_id'] = cwe_id
    if component:
        filters['affected_component'] = component
    if assignee:
        filters['assignee_id'] = assignee
    if finding_type:
        filters['finding_type'] = finding_type
    if date_from:
        filters['date_from'] = date_from
    if date_to:
        filters['date_to'] = date_to

    if search:
        findings, total = database.search_findings(
            query=search, filters=filters, page=page, page_size=page_size
        )
    else:
        findings, total = database.list_unified_findings(
            filters=filters, sort_field=sort_field, sort_dir=sort_dir,
            page=page, page_size=page_size
        )

    return {
        'findings': findings,
        'total': total,
        'page': page,
        'page_size': page_size,
    }


@router.get("/findings/{finding_id}")
async def get_finding_detail(finding_id: str):
    """Single finding with evidence_sources and audit_log included."""
    finding = database.get_unified_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence_sources = database.get_evidence_sources(finding_id)
    audit_log = database.get_audit_log(finding_id)

    return {
        **finding,
        'evidence_sources': evidence_sources,
        'audit_log': audit_log,
    }


# ---------------------------------------------------------------------------
# API Endpoints: Status Transition and Assignment (Task 5.2)
# ---------------------------------------------------------------------------

@router.patch("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, req: StatusTransitionRequest):
    """Validate transition and update finding status."""
    finding = database.get_unified_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    current_status = finding.get('status', 'Open')
    valid, error_msg = validate_transition(current_status, req.status, req.comment)
    if not valid:
        valid_targets = VALID_TRANSITIONS.get(current_status, [])
        raise HTTPException(
            status_code=422,
            detail={
                'message': error_msg,
                'valid_transitions': valid_targets,
            }
        )

    # Update status
    now = datetime.datetime.utcnow().isoformat()
    update_fields = {'status': req.status}
    if req.status in ('Fixed', 'Verified', 'Closed'):
        update_fields['resolved_at'] = now

    database.update_unified_finding(finding_id, **update_fields)

    # Create audit entry
    database.add_audit_entry(
        unified_finding_id=finding_id,
        action='status_change',
        previous_value=current_status,
        new_value=req.status,
        user_id=req.user_id,
        user_display_name=req.user_display_name,
        comment=req.comment,
    )

    return {'status': 'updated', 'finding_id': finding_id, 'new_status': req.status}


@router.patch("/findings/{finding_id}/assign")
async def assign_finding(finding_id: str, req: AssignRequest):
    """Assign a finding to a user."""
    finding = database.get_unified_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify user exists
    user = database.get_dashboard_user(req.assignee_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    previous_assignee = finding.get('assignee_id')
    database.update_unified_finding(finding_id, assignee_id=req.assignee_id)

    # Create audit entry
    database.add_audit_entry(
        unified_finding_id=finding_id,
        action='assignment',
        previous_value=previous_assignee,
        new_value=req.assignee_id,
        user_id=req.user_id,
        user_display_name=req.user_display_name,
    )

    return {'status': 'assigned', 'finding_id': finding_id, 'assignee_id': req.assignee_id}


@router.post("/findings/bulk-status")
async def bulk_status_transition(req: BulkStatusRequest):
    """Bulk status transition. Returns 207 with succeeded/failed arrays."""
    # Validate comment requirement
    if req.status in REQUIRES_COMMENT and not req.comment:
        raise HTTPException(
            status_code=422,
            detail=f"Comment required for transition to {req.status}"
        )

    succeeded, failed = database.bulk_update_status(
        finding_ids=req.finding_ids,
        new_status=req.status,
        user_id=req.user_id,
        comment=req.comment,
    )

    return {
        'succeeded': succeeded,
        'failed': failed,
        'succeeded_count': len(succeeded),
        'failed_count': len(failed),
    }


# ---------------------------------------------------------------------------
# API Endpoints: Metrics (Task 5.3)
# ---------------------------------------------------------------------------

@router.get("/metrics")
async def get_metrics(
    module: Optional[str] = Query(None),
    component: Optional[str] = Query(None),
):
    """Executive metrics: risk posture, severity distribution, MTTR, SLA compliance."""
    filters = {}
    if module:
        filters['module'] = module
    if component:
        filters['component'] = component

    severity_dist = database.get_severity_distribution(filters)

    # Compute risk posture score from severity distribution
    risk_posture_score = sum(
        severity_dist.get(sev, 0) * SEVERITY_WEIGHTS.get(sev, 0)
        for sev in SEVERITY_ORDER
    )

    mttr = database.get_mttr_by_severity()
    sla_compliance = database.get_sla_compliance()

    # Get open/closed counts
    open_statuses = ['Open', 'Acknowledged', 'In_Progress']
    closed_statuses = ['Fixed', 'Verified', 'Closed']

    open_findings, open_count = database.list_unified_findings(
        filters={'status': open_statuses}, page=1, page_size=1
    )
    closed_findings, closed_count = database.list_unified_findings(
        filters={'status': closed_statuses}, page=1, page_size=1
    )

    return {
        'risk_posture_score': risk_posture_score,
        'severity_distribution': severity_dist,
        'mttr_by_severity': mttr,
        'sla_compliance': sla_compliance,
        'open_count': open_count,
        'closed_count': closed_count,
    }


@router.get("/metrics/trend")
async def get_metrics_trend(
    days: int = Query(90, ge=1, le=365),
    module: Optional[str] = Query(None),
    component: Optional[str] = Query(None),
):
    """Daily risk posture timeseries."""
    filters = {}
    if module:
        filters['module'] = module
    if component:
        filters['component'] = component

    timeseries = database.get_risk_posture_timeseries(days=days, filters=filters)
    return {'trend': timeseries, 'days': days}


# ---------------------------------------------------------------------------
# API Endpoints: Build Comparison (Task 5.4)
# ---------------------------------------------------------------------------

@router.get("/build-comparison")
async def get_build_comparison(
    module: str = Query(..., description="Source module name"),
    scope: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
):
    """Compare a scan run with the previous one. Returns new/persisted/fixed sets."""
    if module not in SUPPORTED_MODULES:
        raise HTTPException(status_code=400, detail=f"Invalid module: {module}")

    if run_id:
        # Compare specified run with the one before it
        run = database.get_scan_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Scan run not found")

        current_finding_ids = run.get('finding_ids', [])
        # Get previous run (the run before this one)
        previous_run = database.get_previous_scan_run(module, scope)

        # If the previous run IS the one we're looking at, there's no prior
        if previous_run and previous_run.get('id') == run_id:
            previous_run = None

        comparison = compute_build_comparison(module, scope, current_finding_ids, previous_run)
    else:
        # Get the latest run
        latest_run = database.get_previous_scan_run(module, scope)
        if not latest_run:
            return {
                'new': [], 'persisted': [], 'fixed': [],
                'new_count': 0, 'persisted_count': 0, 'fixed_count': 0,
            }

        return {
            'new': [],
            'persisted': latest_run.get('finding_ids', []),
            'fixed': [],
            'new_count': latest_run.get('new_count', 0),
            'persisted_count': latest_run.get('persisted_count', 0),
            'fixed_count': latest_run.get('fixed_count', 0),
        }

    return comparison


# ---------------------------------------------------------------------------
# API Endpoints: Component and Export (Task 5.5)
# ---------------------------------------------------------------------------

@router.get("/components")
async def list_components():
    """Component health list with finding_count, highest_severity, health_score."""
    components = database.get_component_health()
    return {'components': components}


@router.get("/components/{component:path}")
async def get_component_findings(
    component: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Findings for a specific component."""
    findings, total = database.list_unified_findings(
        filters={'affected_component': component},
        page=page,
        page_size=page_size,
    )
    return {
        'component': component,
        'findings': findings,
        'total': total,
        'page': page,
        'page_size': page_size,
    }


@router.get("/export")
async def export_findings(
    format: str = Query('json', pattern='^(csv|json)$'),
    module: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    """Export findings with audit trail in CSV or JSON format."""
    filters = {}
    if module:
        filters['module'] = module
    if severity:
        filters['severity'] = severity.split(',') if ',' in severity else severity
    if status:
        filters['status'] = status.split(',') if ',' in status else status
    if date_from:
        filters['date_from'] = date_from
    if date_to:
        filters['date_to'] = date_to

    # Fetch all matching findings (no pagination for export)
    findings, total = database.list_unified_findings(
        filters=filters, page=1, page_size=100000
    )

    # Enrich with audit trail
    for finding in findings:
        finding['audit_log'] = database.get_audit_log(finding['id'])

    if format == 'json':
        content = json.dumps({'findings': findings, 'total': total}, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode('utf-8')),
            media_type='application/json',
            headers={'Content-Disposition': 'attachment; filename="findings_export.json"'}
        )
    else:
        # CSV format
        output = io.StringIO()
        fieldnames = [
            'id', 'title', 'severity', 'status', 'cwe_id', 'affected_component',
            'assignee_id', 'first_seen_at', 'last_seen_at', 'resolved_at',
            'evidence_count', 'sla_breach', 'module_tags',
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            row = {k: finding.get(k, '') for k in fieldnames}
            if isinstance(row.get('module_tags'), list):
                row['module_tags'] = ','.join(row['module_tags'])
            writer.writerow(row)

        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode('utf-8')),
            media_type='text/csv',
            headers={'Content-Disposition': 'attachment; filename="findings_export.csv"'}
        )


# ---------------------------------------------------------------------------
# API Endpoints: Ingestion Trigger (Task 5.6)
# ---------------------------------------------------------------------------

@router.post("/ingest/{module}/{scan_id}")
async def ingest_scan(module: str, scan_id: str):
    """Trigger ingestion for a completed scan. Validates module name."""
    if module not in SUPPORTED_MODULES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid module '{module}'. Supported: {SUPPORTED_MODULES}"
        )

    try:
        result = await trigger_ingestion(module, scan_id)
        return result
    except Exception as e:
        logger.error(f"Ingestion failed for {module}/{scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


# ---------------------------------------------------------------------------
# API Endpoints: User Management (Task 5.7)
# ---------------------------------------------------------------------------

@router.get("/users")
async def list_users():
    """List all dashboard users."""
    users = database.list_dashboard_users()
    return {'users': users}


@router.post("/users")
async def create_user(req: UserRequest):
    """Create a new dashboard user."""
    try:
        user_id = database.create_dashboard_user(
            email=req.email,
            display_name=req.display_name,
            role_id=req.role_id,
        )
        return {'user_id': user_id, 'email': req.email, 'display_name': req.display_name}
    except Exception as e:
        if 'UNIQUE' in str(e).upper():
            raise HTTPException(status_code=409, detail="User with this email already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/users/{user_id}/role")
async def update_role(user_id: str, role_id: str = Query(...)):
    """Assign a role to a user."""
    user = database.get_dashboard_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    database.update_user_role(user_id, role_id)
    return {'status': 'updated', 'user_id': user_id, 'role_id': role_id}

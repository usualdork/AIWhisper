
import sqlite3
import datetime
import uuid
import json
import os
from typing import List, Dict, Optional

DB_NAME = "chats.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=15) # Add timeout for concurrent access
    conn.execute('PRAGMA journal_mode=WAL;') # Enable Write-Ahead Logging for concurrency
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Existing Chat Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Existing Chat Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            images TEXT, -- JSON array of image paths
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions (id)
        )
    ''')
    
    # New TPRM Vendor Assessments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vendor_assessments (
            id TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            vendor_type TEXT DEFAULT NULL,
            current_phase INTEGER DEFAULT 1,
            workflow_state TEXT DEFAULT 'TIER_PROCESSING',
            status_details TEXT DEFAULT NULL,
            risk_tier TEXT DEFAULT NULL,
            impact_scores TEXT DEFAULT NULL,
            internal_score_data TEXT DEFAULT NULL,
            external_recon_data TEXT DEFAULT NULL,
            email_draft TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE vendor_assessments ADD COLUMN status_details TEXT')
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute('ALTER TABLE vendor_assessments ADD COLUMN vendor_type TEXT')
    except sqlite3.OperationalError:
        pass
        
    # New RepoScans table for GitHub Agent
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS repo_scans (
            id TEXT PRIMARY KEY,
            repo_url TEXT NOT NULL,
            branch_name TEXT DEFAULT 'main',
            status TEXT DEFAULT 'INITIALIZED',
            status_details TEXT DEFAULT NULL,
            sast_findings TEXT DEFAULT NULL,
            agentic_findings TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            vendor TEXT,
            doc_type TEXT,
            access_scope TEXT,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            status TEXT NOT NULL,
            page_count INTEGER DEFAULT 0,
            chunk_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS document_chunks (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            session_id TEXT,
            vendor TEXT,
            chunk_index INTEGER NOT NULL,
            page_start INTEGER,
            page_end INTEGER,
            content TEXT NOT NULL,
            vector_id TEXT NOT NULL,
            embedding TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents (id)
        )
    ''')
    try:
        cursor.execute('ALTER TABLE document_chunks ADD COLUMN embedding TEXT')
    except sqlite3.OperationalError:
        pass
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rag_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rag_citations (
            message_id INTEGER NOT NULL,
            session_id TEXT,
            citations TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            status TEXT NOT NULL,
            chunk_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_chunks (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            chunk_text TEXT NOT NULL,
            embedding TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES policy_documents (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_analyses (
            id TEXT PRIMARY KEY,
            framework TEXT NOT NULL,
            status TEXT DEFAULT 'INITIALIZED',
            analysis_data TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Vulnerability Management Tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vuln_reports (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            status TEXT DEFAULT 'UPLOADED',
            vuln_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vuln_findings (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            cve_id TEXT,
            title TEXT,
            asset TEXT,
            cvss TEXT,
            augmented_score TEXT DEFAULT 'PENDING',
            rbi_context TEXT,
            remediation TEXT,
            raw_data TEXT,
            FOREIGN KEY (report_id) REFERENCES vuln_reports (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_sast_scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            apk_path TEXT NOT NULL,
            status TEXT DEFAULT 'INITIALIZED',
            phase TEXT DEFAULT 'APK_UPLOAD_VALIDATION',
            progress INTEGER DEFAULT 0,
            status_details TEXT DEFAULT NULL,
            scan_metadata TEXT DEFAULT NULL,
            raw_findings_count INTEGER DEFAULT 0,
            unique_findings_count INTEGER DEFAULT 0,
            confirmed_findings_count INTEGER DEFAULT 0,
            false_positive_count INTEGER DEFAULT 0,
            report_json TEXT DEFAULT NULL,
            stop_requested INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_sast_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            title TEXT,
            category TEXT,
            cwe_id TEXT,
            masvs_category TEXT,
            severity TEXT,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            evidence TEXT,
            tool_sources TEXT,
            verdict TEXT DEFAULT 'NEEDS_MANUAL_REVIEW',
            reasoning TEXT,
            compliance_mapping TEXT,
            raw_payload TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES mobile_sast_scans (id) ON DELETE CASCADE
        )
    ''')
    
    # Mobile DAST (Ostorlab Dynamic Analysis) tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_dast_scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            status TEXT DEFAULT 'INITIALIZED',
            phase TEXT DEFAULT 'QUEUED',
            progress INTEGER DEFAULT 0,
            status_details TEXT DEFAULT NULL,
            ostorlab_scan_id TEXT DEFAULT NULL,
            ostorlab_scan_url TEXT DEFAULT NULL,
            platform TEXT DEFAULT NULL,
            scan_profile TEXT DEFAULT 'Fast Scan',
            risk_rating TEXT DEFAULT NULL,
            vulnerability_count INTEGER DEFAULT 0,
            scan_metadata TEXT DEFAULT NULL,
            report_json TEXT DEFAULT NULL,
            stop_requested INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_dast_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            title TEXT,
            risk_rating TEXT,
            cvss_score TEXT,
            tags TEXT,
            status TEXT,
            ticket_id TEXT,
            short_description TEXT,
            full_description TEXT,
            technical_details TEXT,
            recommendation TEXT,
            references_text TEXT,
            category TEXT,
            raw_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES mobile_dast_scans (id) ON DELETE CASCADE
        )
    ''')

    # ==========================================
    # Code Scanning (Multi-Repo Agentic SAST) Tables
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scans (
            id TEXT PRIMARY KEY,
            label TEXT,
            status TEXT DEFAULT 'INITIALIZED',
            phase TEXT DEFAULT 'QUEUED',
            progress INTEGER DEFAULT 0,
            status_details TEXT DEFAULT NULL,
            repos_json TEXT DEFAULT NULL,
            config_json TEXT DEFAULT NULL,
            ingest_summary_json TEXT DEFAULT NULL,
            cost_report_json TEXT DEFAULT NULL,
            severity_summary_json TEXT DEFAULT NULL,
            findings_count INTEGER DEFAULT 0,
            disputed_count INTEGER DEFAULT 0,
            stop_requested INTEGER DEFAULT 0,
            started_at TIMESTAMP DEFAULT NULL,
            completed_at TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            vuln_id TEXT,
            vuln_class TEXT,
            repo TEXT,
            source_type TEXT,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            severity TEXT,
            confidence INTEGER,
            title TEXT,
            description TEXT,
            business_impact TEXT,
            poc TEXT,
            remediation TEXT,
            false_positive_risk TEXT,
            false_positive_rationale TEXT,
            chunk_id TEXT,
            fingerprint TEXT,
            validated_by_critic INTEGER DEFAULT 0,
            critic_agreement_score INTEGER DEFAULT NULL,
            critic_verdict TEXT DEFAULT NULL,
            critic_explanation TEXT DEFAULT NULL,
            critic_recommended_action TEXT DEFAULT NULL,
            owasp_category TEXT DEFAULT NULL,
            cwe_id TEXT DEFAULT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_disputed (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            reason TEXT,
            critic_review_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ==========================================
    # External Attack Surface Management (EASM) Tables
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_scans (
            id TEXT PRIMARY KEY,
            label TEXT,
            status TEXT DEFAULT 'INITIALIZED',
            phase TEXT DEFAULT 'QUEUED',
            progress INTEGER DEFAULT 0,
            status_details TEXT,
            stage TEXT DEFAULT 'PASSIVE',
            targets_json TEXT,
            config_json TEXT,
            stats_json TEXT,
            cost_report_json TEXT,
            mitre_summary_json TEXT,
            audit_log_json TEXT,
            assets_count INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            high_risk_count INTEGER DEFAULT 0,
            stop_requested INTEGER DEFAULT 0,
            attestation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_scans_created ON easm_scans (created_at DESC)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_assets (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            asset_type TEXT,
            os_name TEXT,
            risk_level TEXT,
            correlation_score INTEGER DEFAULT 0,
            ports_json TEXT,
            services_json TEXT,
            geolocation_json TEXT,
            enrichment_json TEXT,
            fp_verdict TEXT,
            fp_confidence INTEGER,
            fp_rationale TEXT,
            tags_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES easm_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_assets_scan ON easm_assets (scan_id)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            asset_id TEXT,
            ip TEXT,
            hostname TEXT,
            port INTEGER,
            category TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            evidence TEXT,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            owasp_category TEXT,
            cve_id TEXT,
            confidence INTEGER DEFAULT 0,
            source TEXT,
            ai_verdict TEXT,
            ai_rationale TEXT,
            validated INTEGER DEFAULT 0,
            validation_evidence TEXT,
            validation_method TEXT,
            fingerprint TEXT,
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES easm_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_findings_scan ON easm_findings (scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_findings_severity ON easm_findings (severity)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_validations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            finding_id TEXT,
            ip TEXT,
            port INTEGER,
            probe_type TEXT,
            probe_target TEXT,
            probe_method TEXT,
            mitre_technique TEXT,
            request_summary TEXT,
            response_summary TEXT,
            outcome TEXT,
            evidence TEXT,
            risk_delta TEXT,
            duration_ms INTEGER,
            error TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES easm_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_validations_scan ON easm_validations (scan_id)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_attestations (
            id TEXT PRIMARY KEY,
            operator TEXT,
            scope_type TEXT,
            scope_value TEXT,
            statement TEXT,
            signature TEXT,
            metadata_json TEXT,
            revoked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_easm_attestations_scope ON easm_attestations (scope_type, scope_value)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS easm_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bas_runs (
            id TEXT PRIMARY KEY,
            label TEXT,
            status TEXT DEFAULT 'INITIALIZED',
            phase TEXT DEFAULT 'QUEUED',
            progress INTEGER DEFAULT 0,
            status_details TEXT,
            targets_json TEXT,
            scenario_ids_json TEXT,
            config_json TEXT,
            stats_json TEXT,
            audit_log_json TEXT,
            results_count INTEGER DEFAULT 0,
            observed_count INTEGER DEFAULT 0,
            blocked_count INTEGER DEFAULT 0,
            inconclusive_count INTEGER DEFAULT 0,
            stop_requested INTEGER DEFAULT 0,
            attestation_id TEXT,
            operator TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bas_runs_created ON bas_runs (created_at DESC)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bas_results (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            scenario_id TEXT,
            scenario_name TEXT,
            target TEXT,
            asset TEXT,
            control TEXT,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            owasp_category TEXT,
            outcome TEXT,
            severity TEXT,
            confidence INTEGER DEFAULT 0,
            evidence TEXT,
            recommendation TEXT,
            request_summary TEXT,
            response_summary TEXT,
            duration_ms INTEGER DEFAULT 0,
            details_json TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (run_id) REFERENCES bas_runs (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bas_results_run ON bas_results (run_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bas_results_outcome ON bas_results (outcome)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_findings_scan ON code_scan_findings(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_findings_severity ON code_scan_findings(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_findings_repo ON code_scan_findings(repo)')

    # ==========================================
    # Threat Modeling Tables
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_model_sessions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            input_mode TEXT NOT NULL CHECK(input_mode IN ('documentation', 'binary', 'hybrid')),
            status TEXT DEFAULT 'CREATED' CHECK(status IN ('CREATED', 'RUNNING', 'COMPLETED', 'FAILED')),
            phase TEXT DEFAULT 'INTAKE',
            progress INTEGER DEFAULT 0,
            status_details TEXT,
            decomposition TEXT,
            threats TEXT,
            attack_scenarios TEXT,
            risk_matrix TEXT,
            mitigations TEXT,
            report_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_model_uploads (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            storage_path TEXT NOT NULL,
            parsed_content TEXT,
            extraction_metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES threat_model_sessions(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_model_findings (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            threat_id TEXT NOT NULL,
            stride_category TEXT NOT NULL CHECK(stride_category IN ('Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege')),
            title TEXT NOT NULL,
            description TEXT,
            affected_component TEXT,
            affected_asset TEXT,
            threat_actor TEXT,
            prerequisites TEXT,
            likelihood TEXT,
            impact TEXT,
            dread_damage INTEGER,
            dread_reproducibility INTEGER,
            dread_exploitability INTEGER,
            dread_affected_users INTEGER,
            dread_discoverability INTEGER,
            dread_score REAL,
            risk_level TEXT CHECK(risk_level IN ('Critical','High','Medium','Low')),
            mitigations TEXT,
            rbi_reference TEXT,
            sebi_reference TEXT,
            nist_mapping TEXT,
            owasp_reference TEXT,
            attack_scenario TEXT,
            status TEXT DEFAULT 'OPEN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES threat_model_sessions(id) ON DELETE CASCADE
        )
    ''')

    # ==========================================
    # Unified Vulnerability Dashboard Tables
    # ==========================================

    # Dashboard Roles table (for future RBAC)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dashboard_roles (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            permissions_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Dashboard Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dashboard_users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            role_id TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES dashboard_roles(id)
        )
    ''')

    # Core Unified Findings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS unified_findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Informational')),
            cwe_id TEXT,
            affected_component TEXT,
            status TEXT DEFAULT 'Open' CHECK(status IN ('Open','Acknowledged','In_Progress','Fixed','Verified','Closed','Wont_Fix','False_Positive')),
            assignee_id TEXT,
            correlation_key TEXT NOT NULL,
            title_tokens TEXT,
            module_tags TEXT,
            evidence_count INTEGER DEFAULT 1,
            first_seen_at TIMESTAMP NOT NULL,
            last_seen_at TIMESTAMP NOT NULL,
            resolved_at TIMESTAMP,
            sla_breach INTEGER DEFAULT 0,
            review_flag INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assignee_id) REFERENCES dashboard_users(id)
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_severity ON unified_findings(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_status ON unified_findings(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_component ON unified_findings(affected_component)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_cwe ON unified_findings(cwe_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_assignee ON unified_findings(assignee_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_correlation ON unified_findings(correlation_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_first_seen ON unified_findings(first_seen_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_last_seen ON unified_findings(last_seen_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_sla ON unified_findings(sla_breach)')

    # Add finding_type column to unified_findings if not exists
    try:
        cursor.execute("ALTER TABLE unified_findings ADD COLUMN finding_type TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass  # Column already exists
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_uf_finding_type ON unified_findings(finding_type)')

    # Evidence Sources table (links unified finding to raw source findings)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence_sources (
            id TEXT PRIMARY KEY,
            unified_finding_id TEXT NOT NULL,
            source_module TEXT NOT NULL,
            source_finding_id TEXT NOT NULL,
            source_scan_id TEXT NOT NULL,
            source_title TEXT,
            source_severity TEXT,
            source_evidence TEXT,
            source_remediation TEXT,
            ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (unified_finding_id) REFERENCES unified_findings(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_es_unified ON evidence_sources(unified_finding_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_es_module ON evidence_sources(source_module)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_es_scan ON evidence_sources(source_scan_id)')

    # Finding Audit Log table (status transitions, assignments, comments)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_audit_log (
            id TEXT PRIMARY KEY,
            unified_finding_id TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_value TEXT,
            new_value TEXT,
            user_id TEXT,
            user_display_name TEXT,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (unified_finding_id) REFERENCES unified_findings(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_al_finding ON finding_audit_log(unified_finding_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_al_created ON finding_audit_log(created_at)')

    # Unified Scan Runs table (tracks ingestion history for build comparison)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS unified_scan_runs (
            id TEXT PRIMARY KEY,
            source_module TEXT NOT NULL,
            source_scan_id TEXT NOT NULL,
            scope TEXT,
            finding_ids_json TEXT,
            new_count INTEGER DEFAULT 0,
            persisted_count INTEGER DEFAULT 0,
            fixed_count INTEGER DEFAULT 0,
            ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_usr_module ON unified_scan_runs(source_module)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_usr_scope ON unified_scan_runs(scope)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_usr_ingested ON unified_scan_runs(ingested_at)')

    # Component Owners table (for auto-assignment)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS component_owners (
            id TEXT PRIMARY KEY,
            component_pattern TEXT NOT NULL,
            owner_user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_user_id) REFERENCES dashboard_users(id)
        )
    ''')

    conn.commit()
    conn.close()

    # Initialize RBAC tables
    init_rbac_tables()

    # Initialize Holistic Code Scanner tables
    init_holistic_scanner_tables()


def init_rbac_tables():
    """Create RBAC users and revoked tokens tables for role-based access control."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rbac_users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Admin', 'Agent', 'Viewer')),
            permitted_modules TEXT NOT NULL DEFAULT '[]',
            is_active INTEGER DEFAULT 1,
            force_password_change INTEGER DEFAULT 0,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_jti TEXT PRIMARY KEY,
            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    ''')

    # Add tokens_revoked_at column to rbac_users if it doesn't exist (for bulk token revocation)
    try:
        cursor.execute("ALTER TABLE rbac_users ADD COLUMN tokens_revoked_at TIMESTAMP DEFAULT NULL")
    except sqlite3.OperationalError:
        # Column already exists
        pass

    conn.commit()
    conn.close()


def init_holistic_scanner_tables():
    """Create/extend tables for the Holistic Code Scanner V2 integration.

    Extends existing code_scans and code_scan_findings tables with new columns,
    and creates new tables for repos, SBOM, SCA, chains, licenses, container,
    PRs, budget, and settings defaults.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # ==========================================
    # Extend existing code_scans table with new columns
    # ==========================================
    new_code_scans_columns = [
        ("scan_phase", "TEXT DEFAULT 'CREATED'"),
        ("total_repos", "INTEGER DEFAULT 0"),
        ("repos_completed", "INTEGER DEFAULT 0"),
        ("repos_failed", "INTEGER DEFAULT 0"),
        ("repos_skipped", "INTEGER DEFAULT 0"),
        ("cost_usd", "REAL DEFAULT 0.0"),
        ("budget_limit_usd", "REAL DEFAULT NULL"),
        ("diff_aware", "INTEGER DEFAULT 0"),
        ("resumed_from_scan_id", "TEXT DEFAULT NULL"),
    ]
    for col_name, col_def in new_code_scans_columns:
        try:
            cursor.execute(f'ALTER TABLE code_scans ADD COLUMN {col_name} {col_def}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    # ==========================================
    # Extend existing code_scan_findings table with new columns
    # ==========================================
    new_findings_columns = [
        ("finding_type", "TEXT DEFAULT 'sast'"),
        ("sbom_ref", "TEXT DEFAULT NULL"),
        ("chain_id", "TEXT DEFAULT NULL"),
        ("sca_cve_id", "TEXT DEFAULT NULL"),
        ("container_finding_id", "TEXT DEFAULT NULL"),
        ("repo_identifier", "TEXT DEFAULT NULL"),
    ]
    for col_name, col_def in new_findings_columns:
        try:
            cursor.execute(f'ALTER TABLE code_scan_findings ADD COLUMN {col_name} {col_def}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    # ==========================================
    # New Table: code_scan_repos
    # Tracks per-repo status within a multi-repo scan
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_repos (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            status TEXT DEFAULT 'QUEUED',
            head_sha TEXT DEFAULT NULL,
            error_message TEXT DEFAULT NULL,
            cost_usd REAL DEFAULT 0.0,
            started_at TIMESTAMP DEFAULT NULL,
            completed_at TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_repos_scan ON code_scan_repos(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_repos_repo ON code_scan_repos(repo_identifier)')

    # ==========================================
    # New Table: code_scan_sbom
    # Stores CycloneDX SBOM documents per repo per scan
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_sbom (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            cyclonedx_json TEXT NOT NULL,
            component_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sbom_scan ON code_scan_sbom(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sbom_repo ON code_scan_sbom(scan_id, repo_identifier)')

    # ==========================================
    # New Table: code_scan_sca
    # Stores SCA/CVE records with reachability verdicts
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_sca (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            package_version TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL DEFAULT NULL,
            reachability TEXT DEFAULT 'UNKNOWN',
            fix_version TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sca_scan ON code_scan_sca(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sca_repo ON code_scan_sca(scan_id, repo_identifier)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sca_severity ON code_scan_sca(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_sca_reachability ON code_scan_sca(reachability)')

    # ==========================================
    # New Table: code_scan_chains
    # Stores cross-repo exploit chains
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_chains (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            chain_json TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence_score REAL DEFAULT 0.0,
            affected_repos TEXT NOT NULL,
            step_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_chains_scan ON code_scan_chains(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_chains_severity ON code_scan_chains(severity)')

    # ==========================================
    # New Table: code_scan_licenses
    # Stores license compliance records per dependency
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_licenses (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            package_name TEXT NOT NULL,
            package_version TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            license_id TEXT DEFAULT NULL,
            license_category TEXT NOT NULL,
            requires_review INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_licenses_scan ON code_scan_licenses(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_licenses_repo ON code_scan_licenses(scan_id, repo_identifier)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_licenses_category ON code_scan_licenses(license_category)')

    # ==========================================
    # New Table: code_scan_container
    # Stores Dockerfile/container misconfiguration findings
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_container (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            dockerfile_path TEXT NOT NULL,
            misconfiguration_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            recommended_fix TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_container_scan ON code_scan_container(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_container_repo ON code_scan_container(scan_id, repo_identifier)')

    # ==========================================
    # New Table: code_scan_prs
    # Stores auto-PR records linking findings to pull requests
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_prs (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT NOT NULL,
            pr_url TEXT DEFAULT NULL,
            pr_status TEXT DEFAULT 'PENDING',
            findings_addressed TEXT NOT NULL,
            branch_name TEXT DEFAULT NULL,
            error_message TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_prs_scan ON code_scan_prs(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_prs_repo ON code_scan_prs(scan_id, repo_identifier)')

    # ==========================================
    # New Table: code_scan_budget
    # Tracks LLM token usage and cost per scan/repo
    # ==========================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_scan_budget (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_identifier TEXT DEFAULT NULL,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            budget_limit_usd REAL DEFAULT NULL,
            budget_warning_emitted INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES code_scans (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_budget_scan ON code_scan_budget(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_code_scan_budget_repo ON code_scan_budget(scan_id, repo_identifier)')

    # ==========================================
    # Populate code_scan_settings with default rows
    # Uses INSERT OR IGNORE so existing values are not overwritten
    # ==========================================
    default_settings = [
        ('model', 'claude-opus-4-7'),
        ('budget_limit_usd', '50.0'),
        ('sca_enabled', 'true'),
        ('auto_pr_enabled', 'false'),
        ('auto_pr_min_severity', 'HIGH'),
        ('chain_reasoning_enabled', 'true'),
        ('diff_aware_enabled', 'false'),
        ('concurrency_limit', '5'),
        ('budget_30d_limit_usd', '500.0'),
    ]
    for key, value in default_settings:
        cursor.execute(
            'INSERT OR IGNORE INTO code_scan_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
            (key, value)
        )

    conn.commit()
    conn.close()


# --- RBAC User DAO Functions ---

def rbac_create_user(id: str, username: str, password_hash: str, role: str, permitted_modules: list) -> dict:
    """Create a new RBAC user and return the user record (excluding password_hash)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    modules_json = json.dumps(permitted_modules)
    try:
        cursor.execute('''
            INSERT INTO rbac_users (id, username, password_hash, role, permitted_modules, is_active, force_password_change, failed_login_attempts, locked_until, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 0, 0, NULL, ?, ?)
        ''', (id, username, password_hash, role, modules_json, now, now))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        raise e
    # Retrieve the created user
    cursor.execute('SELECT * FROM rbac_users WHERE id = ?', (id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        del user['password_hash']
        return user
    return None


def rbac_get_user_by_id(user_id: str) -> Optional[dict]:
    """Retrieve a user by ID, returns dict with parsed permitted_modules or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM rbac_users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_get_user_by_username(username: str) -> Optional[dict]:
    """Retrieve a user by username, returns dict with parsed permitted_modules or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM rbac_users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_list_users() -> list:
    """List all RBAC users, excluding password_hash from results."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, permitted_modules, is_active, force_password_change, failed_login_attempts, locked_until, created_at, updated_at FROM rbac_users')
    rows = cursor.fetchall()
    conn.close()
    users = []
    for row in rows:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        users.append(user)
    return users


def rbac_update_user(user_id: str, fields_dict: dict) -> Optional[dict]:
    """Update specified fields for a user. Updates updated_at timestamp. Returns updated user dict or None."""
    if not fields_dict:
        return rbac_get_user_by_id(user_id)

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()

    # Build the SET clause dynamically
    set_clauses = []
    values = []
    for key, value in fields_dict.items():
        if key == 'permitted_modules':
            set_clauses.append(f'{key} = ?')
            values.append(json.dumps(value))
        else:
            set_clauses.append(f'{key} = ?')
            values.append(value)

    # Always update updated_at
    set_clauses.append('updated_at = ?')
    values.append(now)

    values.append(user_id)
    query = f"UPDATE rbac_users SET {', '.join(set_clauses)} WHERE id = ?"
    cursor.execute(query, values)
    conn.commit()

    # Retrieve updated user
    cursor.execute('SELECT * FROM rbac_users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_delete_user(user_id: str) -> Optional[dict]:
    """Soft-delete a user by setting is_active=0 and updating updated_at. Returns updated user dict or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute('UPDATE rbac_users SET is_active = 0, updated_at = ? WHERE id = ?', (now, user_id))
    conn.commit()

    # Retrieve updated user
    cursor.execute('SELECT * FROM rbac_users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_increment_failed_attempts(username: str) -> Optional[dict]:
    """Increment failed login attempts for a user. If threshold (5) is reached, set locked_until to now + 15 minutes."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM rbac_users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    user = dict(row)
    new_count = user['failed_login_attempts'] + 1
    now = datetime.datetime.utcnow()

    if new_count >= 5:
        locked_until = (now + datetime.timedelta(minutes=15)).isoformat()
        cursor.execute(
            'UPDATE rbac_users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE username = ?',
            (new_count, locked_until, now.isoformat(), username)
        )
    else:
        cursor.execute(
            'UPDATE rbac_users SET failed_login_attempts = ?, updated_at = ? WHERE username = ?',
            (new_count, now.isoformat(), username)
        )

    conn.commit()

    # Retrieve updated user
    cursor.execute('SELECT * FROM rbac_users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_reset_failed_attempts(username: str) -> Optional[dict]:
    """Reset failed login attempts and locked_until for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute(
        'UPDATE rbac_users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE username = ?',
        (now, username)
    )
    conn.commit()

    # Retrieve updated user
    cursor.execute('SELECT * FROM rbac_users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


# --- RBAC Revoked Tokens DAO Functions ---


def rbac_revoke_token(jti: str, expires_at: str) -> dict:
    """Insert a token JTI into the revoked_tokens table. Returns the inserted record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO revoked_tokens (token_jti, expires_at) VALUES (?, ?)',
            (jti, expires_at)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Token already revoked, ignore duplicate
        conn.close()
        return {"token_jti": jti, "expires_at": expires_at}
    cursor.execute('SELECT * FROM revoked_tokens WHERE token_jti = ?', (jti,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {"token_jti": jti, "expires_at": expires_at}


def rbac_is_token_revoked(jti: str) -> bool:
    """Check if a token JTI exists in the revoked_tokens table. Returns True if revoked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM revoked_tokens WHERE token_jti = ?', (jti,))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def rbac_revoke_all_user_tokens(user_id: str) -> Optional[dict]:
    """Revoke all tokens for a user by setting tokens_revoked_at timestamp.
    The auth layer should compare token iat against this timestamp to reject older tokens."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute(
        'UPDATE rbac_users SET tokens_revoked_at = ?, updated_at = ? WHERE id = ?',
        (now, now, user_id)
    )
    conn.commit()

    # Retrieve updated user
    cursor.execute('SELECT * FROM rbac_users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['permitted_modules'] = json.loads(user['permitted_modules'])
        return user
    return None


def rbac_get_user_tokens_revoked_at(user_id: str) -> Optional[str]:
    """Get the tokens_revoked_at timestamp for a user. Returns ISO timestamp string or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT tokens_revoked_at FROM rbac_users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row and row['tokens_revoked_at']:
        return row['tokens_revoked_at']
    return None


def rbac_cleanup_expired_revocations() -> int:
    """Delete revoked token entries where expires_at is in the past. Returns number of rows deleted."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute('DELETE FROM revoked_tokens WHERE expires_at < ?', (now,))
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted_count


# --- End RBAC User DAO Functions ---


def create_session(title: str = "New Chat") -> str:
    session_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO sessions (id, title) VALUES (?, ?)', (session_id, title))
    conn.commit()
    conn.close()
    return session_id

def add_message(session_id: str, role: str, content: str, images: List[str] = None) -> int:
    conn = get_db_connection()
    c = conn.cursor()
    images_json = json.dumps(images) if images else None
    c.execute('INSERT INTO messages (session_id, role, content, images) VALUES (?, ?, ?, ?)',
              (session_id, role, content, images_json))
    message_id = c.lastrowid
    conn.commit()
    conn.close()
    return message_id

def get_messages(session_id: str) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC', (session_id,))
    rows = c.fetchall()
    messages = []
    for row in rows:
        msg = dict(row)
        if msg['images']:
            msg['images'] = json.loads(msg['images'])
        messages.append(msg)
    conn.close()
    return messages

def list_policy_analyses() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM policy_analyses ORDER BY created_at DESC')
    rows = c.fetchall()
    analyses = [dict(row) for row in rows]
    conn.close()
    return analyses

# ==========================================
# VULNERABILITY MANAGEMENT
# ==========================================

def create_vuln_report(report_id: str, filename: str, vuln_count: int):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO vuln_reports (id, filename, vuln_count)
        VALUES (?, ?, ?)
    ''', (report_id, filename, vuln_count))
    conn.commit()
    conn.close()

def update_vuln_report_status(report_id: str, status: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        UPDATE vuln_reports
        SET status = ?
        WHERE id = ?
    ''', (status, report_id))
    conn.commit()
    conn.close()

def add_vuln_finding(finding_id: str, report_id: str, cve_id: str, title: str, asset: str, cvss: str, raw_data: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO vuln_findings (id, report_id, cve_id, title, asset, cvss, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (finding_id, report_id, cve_id, title, asset, cvss, raw_data))
    conn.commit()
    conn.close()

def update_vuln_finding_augmentation(finding_id: str, augmented_score: str, rbi_context: str, remediation: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        UPDATE vuln_findings
        SET augmented_score = ?, rbi_context = ?, remediation = ?
        WHERE id = ?
    ''', (augmented_score, rbi_context, remediation, finding_id))
    conn.commit()
    conn.close()

def get_vuln_reports() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM vuln_reports ORDER BY created_at DESC')
    rows = c.fetchall()
    reports = [dict(row) for row in rows]
    conn.close()
    return reports

def get_vuln_report(report_id: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM vuln_reports WHERE id = ?', (report_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_vuln_findings(report_id: str) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM vuln_findings WHERE report_id = ? ORDER BY cvss DESC', (report_id,))
    rows = c.fetchall()
    findings = [dict(row) for row in rows]
    conn.close()
    return findings

def get_sessions() -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM sessions ORDER BY created_at DESC')
    rows = c.fetchall()
    sessions = [dict(row) for row in rows]
    conn.close()
    return sessions

def delete_session(session_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
    c.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
    conn.commit()
    conn.close()

def get_session(session_id: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def create_document(doc_id: str, session_id: Optional[str], vendor: Optional[str], doc_type: Optional[str], access_scope: Optional[str], filename: str, storage_path: str, status: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO documents (id, session_id, vendor, doc_type, access_scope, filename, storage_path, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (doc_id, session_id, vendor, doc_type, access_scope, filename, storage_path, status))
    conn.commit()
    conn.close()

def update_document_status(doc_id: str, status: str, page_count: Optional[int] = None, chunk_count: Optional[int] = None):
    conn = get_db_connection()
    c = conn.cursor()
    if page_count is not None and chunk_count is not None:
        c.execute('''
            UPDATE documents
            SET status = ?, page_count = ?, chunk_count = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, page_count, chunk_count, doc_id))
    else:
        c.execute('''
            UPDATE documents
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, doc_id))
    conn.commit()
    conn.close()

def list_documents(session_id: Optional[str] = None, vendor: Optional[str] = None) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    query = 'SELECT * FROM documents WHERE deleted_at IS NULL'
    params: List = []
    if session_id:
        query += ' AND session_id = ?'
        params.append(session_id)
    if vendor:
        query += ' AND vendor = ?'
        params.append(vendor)
    query += ' ORDER BY created_at DESC'
    c.execute(query, tuple(params))
    rows = c.fetchall()
    docs = [dict(row) for row in rows]
    conn.close()
    return docs

def get_document(doc_id: str) -> Optional[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM documents WHERE id = ? AND deleted_at IS NULL', (doc_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def add_document_chunk(chunk_id: str, document_id: str, session_id: Optional[str], vendor: Optional[str], chunk_index: int, page_start: Optional[int], page_end: Optional[int], content: str, vector_id: str, embedding: Optional[List[float]] = None):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO document_chunks (id, document_id, session_id, vendor, chunk_index, page_start, page_end, content, vector_id, embedding)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (chunk_id, document_id, session_id, vendor, chunk_index, page_start, page_end, content, vector_id, json.dumps(embedding) if embedding else None))
    conn.commit()
    conn.close()

def list_document_chunks(document_id: str) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM document_chunks WHERE document_id = ? ORDER BY chunk_index ASC', (document_id,))
    rows = c.fetchall()
    chunks = [dict(row) for row in rows]
    conn.close()
    return chunks

def list_chunks_for_retrieval(session_id: Optional[str] = None, vendor: Optional[str] = None) -> List[Dict]:
    conn = get_db_connection()
    c = conn.cursor()
    query = '''
        SELECT dc.*, d.filename as filename, d.doc_type as doc_type, d.vendor as doc_vendor
        FROM document_chunks dc
        JOIN documents d ON d.id = dc.document_id
        WHERE d.deleted_at IS NULL
    '''
    params: List = []
    if session_id:
        query += ' AND dc.session_id = ?'
        params.append(session_id)
    if vendor:
        query += ' AND (dc.vendor = ? OR d.vendor = ?)'
        params.extend([vendor, vendor])
    c.execute(query, tuple(params))
    rows = c.fetchall()
    chunks = []
    for row in rows:
        chunk = dict(row)
        if chunk.get('embedding'):
            chunk['embedding'] = json.loads(chunk['embedding'])
        if not chunk.get('vendor'):
            chunk['vendor'] = chunk.get('doc_vendor')
        chunks.append(chunk)
    conn.close()
    return chunks

def delete_document(doc_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT storage_path FROM documents WHERE id = ? AND deleted_at IS NULL', (doc_id,))
    row = c.fetchone()
    storage_path = row['storage_path'] if row else None
    c.execute('UPDATE documents SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?', (doc_id,))
    c.execute('DELETE FROM document_chunks WHERE document_id = ?', (doc_id,))
    conn.commit()
    conn.close()
    if storage_path and os.path.exists(storage_path):
        try:
            os.remove(storage_path)
            doc_dir = os.path.dirname(storage_path)
            if doc_dir and os.path.isdir(doc_dir) and not os.listdir(doc_dir):
                os.rmdir(doc_dir)
        except OSError:
            pass

def set_setting(key: str, value: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO rag_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', (key, value))
    conn.commit()
    conn.close()

def get_setting(key: str) -> Optional[str]:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT value FROM rag_settings WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()
    if row:
        return row['value']
    return None

def add_citations(message_id: int, session_id: Optional[str], citations: List[Dict]):
    conn = get_db_connection()
    c = conn.cursor()
    citations_json = json.dumps(citations) if citations else None
    c.execute('INSERT INTO rag_citations (message_id, session_id, citations) VALUES (?, ?, ?)', (message_id, session_id, citations_json))
    conn.commit()
    conn.close()

def get_rag_metrics(session_id: Optional[str] = None) -> Dict:
    conn = get_db_connection()
    c = conn.cursor()
    doc_query = 'SELECT COUNT(*) as total, SUM(CASE WHEN status = "ready" THEN 1 ELSE 0 END) as ready FROM documents WHERE deleted_at IS NULL'
    doc_params: List = []
    if session_id:
        doc_query += ' AND session_id = ?'
        doc_params.append(session_id)
    c.execute(doc_query, tuple(doc_params))
    doc_row = c.fetchone()
    chunk_query = 'SELECT COUNT(*) as total FROM document_chunks'
    chunk_params: List = []
    if session_id:
        chunk_query += ' WHERE session_id = ?'
        chunk_params.append(session_id)
    c.execute(chunk_query, tuple(chunk_params))
    chunk_row = c.fetchone()
    citation_query = 'SELECT COUNT(*) as total FROM rag_citations'
    citation_params: List = []
    if session_id:
        citation_query += ' WHERE session_id = ?'
        citation_params.append(session_id)
    c.execute(citation_query, tuple(citation_params))
    citation_row = c.fetchone()
    assistant_query = 'SELECT COUNT(*) as total FROM messages WHERE role = "assistant"'
    assistant_params: List = []
    if session_id:
        assistant_query += ' AND session_id = ?'
        assistant_params.append(session_id)
    c.execute(assistant_query, tuple(assistant_params))
    assistant_row = c.fetchone()
    conn.close()
    total_docs = doc_row['total'] or 0
    ready_docs = doc_row['ready'] or 0
    total_chunks = chunk_row['total'] or 0
    total_citations = citation_row['total'] or 0
    total_assistant = assistant_row['total'] or 0
    citation_rate = round((total_citations / total_assistant), 4) if total_assistant else 0
    avg_chunks = round((total_chunks / total_docs), 2) if total_docs else 0
    extraction_coverage = round((ready_docs / total_docs), 4) if total_docs else 0
    time_saved_setting = get_setting("analyst_time_saved_pct")
    analyst_time_saved = float(time_saved_setting) if time_saved_setting else 0
    return {
        "documents_total": total_docs,
        "documents_ready": ready_docs,
        "chunks_total": total_chunks,
        "chunks_avg_per_document": avg_chunks,
        "citation_rate": citation_rate,
        "extraction_coverage": extraction_coverage,
        "analyst_time_saved_pct": analyst_time_saved,
        "analyst_time_saved_target_min": 40,
        "analyst_time_saved_target_max": 60
    }

def purge_retention(days: int) -> int:
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT id, storage_path FROM documents WHERE deleted_at IS NULL AND created_at < ?', (cutoff,))
    rows = c.fetchall()
    doc_ids = [row['id'] for row in rows]
    storage_paths = [row['storage_path'] for row in rows if row['storage_path']]
    if doc_ids:
        c.execute('UPDATE documents SET deleted_at = CURRENT_TIMESTAMP WHERE id IN (%s)' % ','.join('?' * len(doc_ids)), doc_ids)
        c.execute('DELETE FROM document_chunks WHERE document_id IN (%s)' % ','.join('?' * len(doc_ids)), doc_ids)
    conn.commit()
    conn.close()
    for storage_path in storage_paths:
        if storage_path and os.path.exists(storage_path):
            try:
                os.remove(storage_path)
                doc_dir = os.path.dirname(storage_path)
                if doc_dir and os.path.isdir(doc_dir) and not os.listdir(doc_dir):
                    os.rmdir(doc_dir)
            except OSError:
                pass
    return len(doc_ids)

# ==========================================
# TPRM Vendor Assessments CRUD Operations
# ==========================================

def create_vendor_assessment(vendor_name: str, risk_tier: str = None) -> str:
    conn = get_db_connection()
    c = conn.cursor()
    assessment_id = str(uuid.uuid4())
    c.execute('''
        INSERT INTO vendor_assessments (id, vendor_name, risk_tier)
        VALUES (?, ?, ?)
    ''', (assessment_id, vendor_name, risk_tier))
    conn.commit()
    conn.close()
    return assessment_id

def get_vendor_assessments() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM vendor_assessments ORDER BY created_at DESC')
    assessments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    for a in assessments:
        for field in ['impact_scores', 'internal_score_data', 'external_recon_data']:
            if a[field]:
                try:
                    a[field] = json.loads(a[field])
                except Exception:
                    pass
    return assessments

def get_vendor_assessment_by_id(assessment_id: str) -> dict:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM vendor_assessments WHERE id = ?', (assessment_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return None
        
    assessment = dict(row)
    # Fix for JSON parsing issues
    for field in ['impact_scores', 'internal_score_data', 'external_recon_data']:
        if field in assessment and assessment[field]:
            if isinstance(assessment[field], str):
                try:
                    assessment[field] = json.loads(assessment[field])
                except Exception:
                    pass
    return assessment

def delete_vendor_assessment(assessment_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM vendor_assessments WHERE id = ?', (assessment_id,))
    conn.commit()
    conn.close()

def update_vendor_assessment_state(assessment_id: str, phase: int, state: str, **kwargs):
    conn = get_db_connection()
    c = conn.cursor()
    
    updates = ["current_phase = ?", "workflow_state = ?", "updated_at = CURRENT_TIMESTAMP"]
    params = [phase, state]
    
    valid_fields = ['vendor_type', 'risk_tier', 'impact_scores', 'internal_score_data', 'external_recon_data', 'email_draft', 'status_details']
    for k, v in kwargs.items():
        if k in valid_fields:
            updates.append(f"{k} = ?")
            if isinstance(v, (dict, list)):
                params.append(json.dumps(v))
            else:
                params.append(v)
                
    params.append(assessment_id)
    query = f"UPDATE vendor_assessments SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()

# ==========================================
# Repo Scans CRUD Operations
# ==========================================

def create_repo_scan(repo_url: str, branch_name: str = "main") -> str:
    conn = get_db_connection()
    c = conn.cursor()
    scan_id = str(uuid.uuid4())
    c.execute('''
        INSERT INTO repo_scans (id, repo_url, branch_name)
        VALUES (?, ?, ?)
    ''', (scan_id, repo_url, branch_name))
    conn.commit()
    conn.close()
    return scan_id

def get_repo_scans() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM repo_scans ORDER BY created_at DESC')
    scans = [dict(row) for row in c.fetchall()]
    conn.close()
    
    for s in scans:
        for field in ['sast_findings', 'agentic_findings']:
            if s[field]:
                try:
                    s[field] = json.loads(s[field])
                except Exception:
                    pass
    return scans

def get_repo_scan_by_id(scan_id: str) -> dict:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM repo_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return None
        
    scan = dict(row)
    # Fix for JSON parsing issues
    for field in ['sast_findings', 'agentic_findings']:
        if field in scan and scan[field]:
            if isinstance(scan[field], str):
                try:
                    scan[field] = json.loads(scan[field])
                except Exception:
                    pass
    return scan

def delete_repo_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM repo_scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()

def update_repo_scan_state(scan_id: str, state: str, **kwargs):
    conn = get_db_connection()
    c = conn.cursor()
    
    updates = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
    params = [state]
    
    valid_fields = ['status_details', 'sast_findings', 'agentic_findings']
    for k, v in kwargs.items():
        if k in valid_fields:
            updates.append(f"{k} = ?")
            if isinstance(v, (dict, list)):
                params.append(json.dumps(v))
            else:
                params.append(v)
                
    params.append(scan_id)
    query = f"UPDATE repo_scans SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()

def create_mobile_sast_scan(filename: str, apk_path: str) -> str:
    conn = get_db_connection()
    c = conn.cursor()
    scan_id = str(uuid.uuid4())
    c.execute('''
        INSERT INTO mobile_sast_scans (id, filename, apk_path)
        VALUES (?, ?, ?)
    ''', (scan_id, filename, apk_path))
    conn.commit()
    conn.close()
    return scan_id

def get_mobile_sast_scans() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT
            id,
            filename,
            status,
            phase,
            progress,
            status_details,
            scan_metadata,
            raw_findings_count,
            unique_findings_count,
            confirmed_findings_count,
            false_positive_count,
            created_at,
            updated_at
        FROM mobile_sast_scans
        ORDER BY created_at DESC
        '''
    )
    scans = [dict(row) for row in c.fetchall()]
    conn.close()
    for scan in scans:
        if scan.get("scan_metadata"):
            try:
                scan["scan_metadata"] = json.loads(scan["scan_metadata"])
            except Exception:
                pass
    return scans

def get_mobile_sast_scan_by_id(scan_id: str) -> Optional[Dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM mobile_sast_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    scan = dict(row)
    if scan.get("scan_metadata"):
        try:
            scan["scan_metadata"] = json.loads(scan["scan_metadata"])
        except Exception:
            pass
    if scan.get("report_json"):
        try:
            scan["report_json"] = json.loads(scan["report_json"])
        except Exception:
            pass
    return scan

def update_mobile_sast_scan(scan_id: str, status: str, **kwargs):
    conn = get_db_connection()
    c = conn.cursor()
    updates = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
    params = [status]
    valid_fields = [
        "phase", "progress", "status_details", "scan_metadata", "raw_findings_count",
        "unique_findings_count", "confirmed_findings_count", "false_positive_count",
        "report_json", "stop_requested"
    ]
    for key, value in kwargs.items():
        if key in valid_fields:
            updates.append(f"{key} = ?")
            if isinstance(value, (dict, list)):
                params.append(json.dumps(value))
            else:
                params.append(value)
    params.append(scan_id)
    query = f"UPDATE mobile_sast_scans SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()

def request_stop_mobile_sast_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        UPDATE mobile_sast_scans
        SET stop_requested = 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (scan_id,))
    conn.commit()
    conn.close()

def is_mobile_sast_stop_requested(scan_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT stop_requested FROM mobile_sast_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return bool(row and row["stop_requested"])

def reset_inflight_mobile_sast_scans(reason: str = "Stopped after backend restart"):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE mobile_sast_scans
        SET status = 'STOPPED',
            stop_requested = 1,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING', 'INITIALIZED', 'STOPPING')
        ''',
        (reason,),
    )
    conn.commit()
    conn.close()

def delete_mobile_sast_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mobile_sast_scans WHERE id = ?', (scan_id,))
    c.execute('DELETE FROM mobile_sast_findings WHERE scan_id = ?', (scan_id,))
    conn.commit()
    conn.close()

def replace_mobile_sast_findings(scan_id: str, findings: List[Dict]):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mobile_sast_findings WHERE scan_id = ?', (scan_id,))
    for finding in findings:
        c.execute('''
            INSERT INTO mobile_sast_findings (
                id, scan_id, title, category, cwe_id, masvs_category, severity,
                file_path, line_start, line_end, evidence, tool_sources, verdict,
                reasoning, compliance_mapping, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get("id") or str(uuid.uuid4()),
            scan_id,
            finding.get("title"),
            finding.get("category"),
            finding.get("cwe_id"),
            finding.get("masvs_category"),
            finding.get("severity"),
            finding.get("file_path"),
            finding.get("line_start"),
            finding.get("line_end"),
            finding.get("evidence"),
            json.dumps(finding.get("tool_sources") or []),
            finding.get("verdict", "NEEDS_MANUAL_REVIEW"),
            finding.get("reasoning"),
            json.dumps(finding.get("compliance_mapping") or {}),
            json.dumps(finding.get("raw_payload") or {})
        ))
    conn.commit()
    conn.close()

def get_mobile_sast_findings(scan_id: str) -> List[Dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM mobile_sast_findings WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get("tool_sources"):
            try:
                row["tool_sources"] = json.loads(row["tool_sources"])
            except Exception:
                pass
        if row.get("compliance_mapping"):
            try:
                row["compliance_mapping"] = json.loads(row["compliance_mapping"])
            except Exception:
                pass
        if row.get("raw_payload"):
            try:
                row["raw_payload"] = json.loads(row["raw_payload"])
            except Exception:
                pass
    return rows

# ==========================================
# MOBILE DAST (Ostorlab) SCAN MANAGEMENT
# ==========================================

def create_mobile_dast_scan(scan_id: str, filename: str, file_path: str, platform: str) -> str:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO mobile_dast_scans (id, filename, file_path, platform)
        VALUES (?, ?, ?, ?)
    ''', (scan_id, filename, file_path, platform))
    conn.commit()
    conn.close()
    return scan_id

def get_mobile_dast_scans() -> List[Dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''
        SELECT
            id, filename, status, phase, progress, status_details,
            ostorlab_scan_id, ostorlab_scan_url, platform, scan_profile,
            risk_rating, vulnerability_count, scan_metadata,
            created_at, updated_at
        FROM mobile_dast_scans
        ORDER BY created_at DESC
    ''')
    scans = [dict(row) for row in c.fetchall()]
    conn.close()
    for scan in scans:
        if scan.get("scan_metadata"):
            try:
                scan["scan_metadata"] = json.loads(scan["scan_metadata"])
            except Exception:
                pass
    return scans

def get_mobile_dast_scan_by_id(scan_id: str) -> Optional[Dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM mobile_dast_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    scan = dict(row)
    if scan.get("scan_metadata"):
        try:
            scan["scan_metadata"] = json.loads(scan["scan_metadata"])
        except Exception:
            pass
    if scan.get("report_json"):
        try:
            scan["report_json"] = json.loads(scan["report_json"])
        except Exception:
            pass
    return scan

def update_mobile_dast_scan(scan_id: str, status: str, **kwargs):
    conn = get_db_connection()
    c = conn.cursor()
    updates = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
    params = [status]
    valid_fields = [
        "phase", "progress", "status_details", "scan_metadata",
        "ostorlab_scan_id", "ostorlab_scan_url", "platform",
        "risk_rating", "vulnerability_count", "report_json", "stop_requested"
    ]
    for key, value in kwargs.items():
        if key in valid_fields:
            updates.append(f"{key} = ?")
            if isinstance(value, (dict, list)):
                params.append(json.dumps(value))
            else:
                params.append(value)
    params.append(scan_id)
    query = f"UPDATE mobile_dast_scans SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()

def request_stop_mobile_dast_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        UPDATE mobile_dast_scans
        SET stop_requested = 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (scan_id,))
    conn.commit()
    conn.close()

def is_mobile_dast_stop_requested(scan_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT stop_requested FROM mobile_dast_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return bool(row and row["stop_requested"])

def reset_inflight_mobile_dast_scans(reason: str = "Stopped after backend restart"):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE mobile_dast_scans
        SET status = 'STOPPED',
            stop_requested = 1,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING', 'INITIALIZED', 'STOPPING')
        ''',
        (reason,),
    )
    conn.commit()
    conn.close()

def delete_mobile_dast_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mobile_dast_scans WHERE id = ?', (scan_id,))
    c.execute('DELETE FROM mobile_dast_findings WHERE scan_id = ?', (scan_id,))
    conn.commit()
    conn.close()

def upsert_mobile_dast_finding(scan_id: str, finding: Dict):
    """Insert or update a single finding — used for incremental scraping."""
    conn = get_db_connection()
    c = conn.cursor()
    finding_id = finding.get("id") or str(uuid.uuid4())
    c.execute('''
        INSERT OR REPLACE INTO mobile_dast_findings (
            id, scan_id, title, risk_rating, cvss_score, tags,
            status, ticket_id, short_description, full_description,
            technical_details, recommendation, references_text,
            category, raw_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        finding_id,
        scan_id,
        finding.get("title"),
        finding.get("risk_rating"),
        finding.get("cvss_score"),
        json.dumps(finding.get("tags") or []),
        finding.get("status"),
        finding.get("ticket_id"),
        finding.get("short_description"),
        finding.get("full_description"),
        finding.get("technical_details"),
        finding.get("recommendation"),
        finding.get("references_text"),
        finding.get("category"),
        json.dumps(finding.get("raw_data") or {})
    ))
    conn.commit()
    conn.close()
    return finding_id

def replace_mobile_dast_findings(scan_id: str, findings: List[Dict]):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mobile_dast_findings WHERE scan_id = ?', (scan_id,))
    for finding in findings:
        c.execute('''
            INSERT INTO mobile_dast_findings (
                id, scan_id, title, risk_rating, cvss_score, tags,
                status, ticket_id, short_description, full_description,
                technical_details, recommendation, references_text,
                category, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get("id") or str(uuid.uuid4()),
            scan_id,
            finding.get("title"),
            finding.get("risk_rating"),
            finding.get("cvss_score"),
            json.dumps(finding.get("tags") or []),
            finding.get("status"),
            finding.get("ticket_id"),
            finding.get("short_description"),
            finding.get("full_description"),
            finding.get("technical_details"),
            finding.get("recommendation"),
            finding.get("references_text"),
            finding.get("category"),
            json.dumps(finding.get("raw_data") or {})
        ))
    conn.commit()
    conn.close()

def get_mobile_dast_findings(scan_id: str) -> List[Dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM mobile_dast_findings WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get("tags"):
            try:
                row["tags"] = json.loads(row["tags"])
            except Exception:
                pass
        if row.get("raw_data"):
            try:
                row["raw_data"] = json.loads(row["raw_data"])
            except Exception:
                pass
    return rows

# ==========================================
# Code Scanning (Multi-Repo Agentic SAST) DAOs
# ==========================================

def _maybe_load_json(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def create_code_scan(label: str, repos: list, config: dict) -> str:
    scan_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scans (id, label, status, phase, progress, status_details, repos_json, config_json)
        VALUES (?, ?, 'INITIALIZED', 'QUEUED', 0, ?, ?, ?)
        ''',
        (
            scan_id,
            label or 'Code Scan',
            'Scan queued',
            json.dumps(repos or []),
            json.dumps(config or {}),
        ),
    )
    conn.commit()
    conn.close()
    return scan_id


def update_code_scan_state(scan_id: str, **fields):
    if not fields:
        return
    json_fields = {
        'repos_json', 'config_json', 'ingest_summary_json',
        'cost_report_json', 'severity_summary_json'
    }
    allowed = {
        'label', 'status', 'phase', 'progress', 'status_details',
        'repos_json', 'config_json', 'ingest_summary_json',
        'cost_report_json', 'severity_summary_json',
        'findings_count', 'disputed_count', 'stop_requested',
        'started_at', 'completed_at',
    }
    sets = []
    params = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key in json_fields and not isinstance(value, str):
            value = json.dumps(value)
        sets.append(f"{key} = ?")
        params.append(value)
    sets.append("updated_at = CURRENT_TIMESTAMP")
    params.append(scan_id)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(f"UPDATE code_scans SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


def get_code_scans() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM code_scans ORDER BY created_at DESC')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        for key in ('repos_json', 'config_json', 'ingest_summary_json',
                    'cost_report_json', 'severity_summary_json'):
            if row.get(key):
                row[key.replace('_json', '')] = _maybe_load_json(row[key])
                row.pop(key, None)
    return rows


def get_code_scan(scan_id: str) -> dict:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM code_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    for key in ('repos_json', 'config_json', 'ingest_summary_json',
                'cost_report_json', 'severity_summary_json'):
        if record.get(key):
            record[key.replace('_json', '')] = _maybe_load_json(record[key])
            record.pop(key, None)
    return record


def delete_code_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM code_scan_findings WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM code_scan_disputed WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM code_scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()


def request_code_scan_stop(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE code_scans
        SET stop_requested = 1,
            status = CASE WHEN status IN ('INITIALIZED', 'RUNNING') THEN 'STOPPING' ELSE status END,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        ('Stop requested by operator', scan_id),
    )
    conn.commit()
    conn.close()


def is_code_scan_stop_requested(scan_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT stop_requested FROM code_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])


def reset_inflight_code_scans(reason: str = "Stopped after backend restart"):
    conn = get_db_connection()
    c = conn.cursor()
    # Legacy: reset old status column for backward compatibility
    c.execute(
        '''
        UPDATE code_scans
        SET status = 'STOPPED',
            stop_requested = 1,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING', 'INITIALIZED', 'STOPPING')
        ''',
        (reason,),
    )
    # New holistic scanner: mark active scan_phase values as INTERRUPTED
    active_phases = ('INGESTING', 'SCANNING', 'ENRICHING', 'CHAINING', 'PATCHING', 'REPORTING')
    placeholders = ",".join("?" for _ in active_phases)
    c.execute(
        f'''
        UPDATE code_scans
        SET scan_phase = 'INTERRUPTED',
            updated_at = CURRENT_TIMESTAMP
        WHERE scan_phase IN ({placeholders})
        ''',
        active_phases,
    )
    # Mark any SCANNING repos as INTERRUPTED
    c.execute(
        '''
        UPDATE code_scan_repos
        SET status = 'INTERRUPTED', completed_at = CURRENT_TIMESTAMP
        WHERE status = 'SCANNING'
        '''
    )
    conn.commit()
    conn.close()


def insert_code_scan_findings(scan_id: str, findings: list):
    if not findings:
        return
    conn = get_db_connection()
    c = conn.cursor()
    for finding in findings:
        def _safe_str(val):
            """Ensure value is a string or None — convert dicts/lists to JSON."""
            if val is None:
                return None
            if isinstance(val, (dict, list)):
                return json.dumps(val)
            return str(val) if val else None

        c.execute(
            '''
            INSERT INTO code_scan_findings (
                id, scan_id, vuln_id, vuln_class, repo, source_type, file_path,
                line_start, line_end, severity, confidence, title, description,
                business_impact, poc, remediation, false_positive_risk,
                false_positive_rationale, chunk_id, fingerprint,
                validated_by_critic, critic_agreement_score, critic_verdict,
                critic_explanation, critic_recommended_action, owasp_category,
                cwe_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                finding.get('id') or str(uuid.uuid4()),
                scan_id,
                _safe_str(finding.get('vuln_id')),
                _safe_str(finding.get('vuln_class')),
                _safe_str(finding.get('repo')),
                _safe_str(finding.get('source_type')),
                _safe_str(finding.get('file_path')),
                int(finding.get('line_start') or 0),
                int(finding.get('line_end') or 0),
                _safe_str(finding.get('severity')),
                int(finding.get('confidence') or 0),
                _safe_str(finding.get('title')),
                _safe_str(finding.get('description')),
                _safe_str(finding.get('business_impact')),
                _safe_str(finding.get('poc')),
                _safe_str(finding.get('remediation')),
                _safe_str(finding.get('false_positive_risk')),
                _safe_str(finding.get('false_positive_rationale')),
                _safe_str(finding.get('chunk_id')),
                _safe_str(finding.get('fingerprint')),
                1 if finding.get('validated_by_critic') else 0,
                finding.get('critic_agreement_score'),
                _safe_str(finding.get('critic_verdict')),
                _safe_str(finding.get('critic_explanation')),
                _safe_str(finding.get('critic_recommended_action')),
                _safe_str(finding.get('owasp_category')),
                _safe_str(finding.get('cwe_id')),
            ),
        )
    conn.commit()
    conn.close()


def get_code_scan_findings(scan_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT * FROM code_scan_findings WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            confidence DESC,
            repo,
            file_path,
            line_start
        ''',
        (scan_id,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        row['validated_by_critic'] = bool(row.get('validated_by_critic'))
    return rows


def insert_code_scan_disputed(scan_id: str, disputed: list):
    if not disputed:
        return
    conn = get_db_connection()
    c = conn.cursor()
    for item in disputed:
        finding_dict = item.get('finding') or {}
        critic_review = item.get('critic_review')
        c.execute(
            '''
            INSERT INTO code_scan_disputed (id, scan_id, finding_json, reason, critic_review_json)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (
                str(uuid.uuid4()),
                scan_id,
                json.dumps(finding_dict),
                item.get('reason'),
                json.dumps(critic_review) if critic_review is not None else None,
            ),
        )
    conn.commit()
    conn.close()


def get_code_scan_disputed(scan_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM code_scan_disputed WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get('finding_json'):
            row['finding'] = _maybe_load_json(row['finding_json'])
        if row.get('critic_review_json'):
            row['critic_review'] = _maybe_load_json(row['critic_review_json'])
        row.pop('finding_json', None)
        row.pop('critic_review_json', None)
    return rows


def set_code_scan_setting(key: str, value):
    if value is None:
        delete_code_scan_setting(key)
        return
    conn = get_db_connection()
    c = conn.cursor()
    payload = value if isinstance(value, str) else json.dumps(value)
    c.execute(
        '''
        INSERT INTO code_scan_settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        ''',
        (key, payload),
    )
    conn.commit()
    conn.close()


def get_code_scan_setting(key: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT value FROM code_scan_settings WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return row[0]


def get_all_code_scan_settings() -> dict:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT key, value FROM code_scan_settings')
    rows = c.fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}


def delete_code_scan_setting(key: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM code_scan_settings WHERE key = ?', (key,))
    conn.commit()
    conn.close()


# ==========================================
# Holistic Code Scanner V2 — DAO Functions
# ==========================================

# --- code_scan_repos ---

def code_scan_repo_create(scan_id: str, repo_identifier: str, status: str = 'QUEUED', head_sha: str = None) -> dict:
    """Create a per-repo record within a multi-repo scan."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scan_repos (id, scan_id, repo_identifier, status, head_sha, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, repo_identifier, status, head_sha),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_repos WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def code_scan_repo_get_by_scan_id(scan_id: str) -> list:
    """Get all repo records for a given scan."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM code_scan_repos WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def code_scan_repo_update_status(repo_id: str, status: str, error_message: str = None, cost_usd: float = None) -> None:
    """Update the status of a repo record. Optionally set error_message, cost, and timestamps."""
    conn = get_db_connection()
    c = conn.cursor()
    sets = ['status = ?', 'completed_at = CURRENT_TIMESTAMP']
    params = [status]
    if status == 'SCANNING':
        sets = ['status = ?', 'started_at = CURRENT_TIMESTAMP']
        params = [status]
    else:
        sets = ['status = ?', 'completed_at = CURRENT_TIMESTAMP']
        params = [status]
    if error_message is not None:
        sets.append('error_message = ?')
        params.append(error_message)
    if cost_usd is not None:
        sets.append('cost_usd = ?')
        params.append(cost_usd)
    params.append(repo_id)
    c.execute(f"UPDATE code_scan_repos SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


def code_scan_repo_get_by_identifier(scan_id: str, repo_identifier: str) -> dict:
    """Get a specific repo record by scan_id and repo_identifier."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_repos WHERE scan_id = ? AND repo_identifier = ?',
        (scan_id, repo_identifier),
    )
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


# --- code_scan_sbom ---

def code_scan_sbom_create(scan_id: str, repo_identifier: str, cyclonedx_json: str, component_count: int = 0) -> dict:
    """Create an SBOM record for a repo within a scan."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scan_sbom (id, scan_id, repo_identifier, cyclonedx_json, component_count, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, repo_identifier, cyclonedx_json, component_count),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_sbom WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def code_scan_sbom_get(scan_id: str, repo_identifier: str) -> dict:
    """Get the SBOM record for a specific scan + repo."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_sbom WHERE scan_id = ? AND repo_identifier = ?',
        (scan_id, repo_identifier),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    if record.get('cyclonedx_json'):
        record['cyclonedx'] = _maybe_load_json(record['cyclonedx_json'])
    return record


# --- code_scan_sca ---

def code_scan_sca_create_batch(scan_id: str, repo_identifier: str, records: list) -> int:
    """Insert a batch of SCA/CVE records for a repo. Returns count inserted."""
    if not records:
        return 0
    conn = get_db_connection()
    c = conn.cursor()
    count = 0
    for rec in records:
        record_id = rec.get('id') or str(uuid.uuid4())
        c.execute(
            '''
            INSERT INTO code_scan_sca (id, scan_id, repo_identifier, cve_id, package_name,
                package_version, ecosystem, severity, cvss_score, reachability, fix_version, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''',
            (
                record_id, scan_id, repo_identifier,
                rec.get('cve_id', ''),
                rec.get('package_name', ''),
                rec.get('package_version', ''),
                rec.get('ecosystem', ''),
                rec.get('severity', 'MEDIUM'),
                rec.get('cvss_score'),
                rec.get('reachability', 'UNKNOWN'),
                rec.get('fix_version'),
            ),
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def code_scan_sca_get(scan_id: str, repo_identifier: str) -> list:
    """Get all SCA records for a scan + repo."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_sca WHERE scan_id = ? AND repo_identifier = ? ORDER BY created_at ASC',
        (scan_id, repo_identifier),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def code_scan_sca_filter(scan_id: str, repo_identifier: str = None, severity: str = None, reachability: str = None) -> list:
    """Filter SCA records by severity and/or reachability."""
    conn = get_db_connection()
    c = conn.cursor()
    query = 'SELECT * FROM code_scan_sca WHERE scan_id = ?'
    params = [scan_id]
    if repo_identifier:
        query += ' AND repo_identifier = ?'
        params.append(repo_identifier)
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if reachability:
        query += ' AND reachability = ?'
        params.append(reachability)
    query += ' ORDER BY created_at ASC'
    c.execute(query, tuple(params))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --- code_scan_chains ---

def code_scan_chain_create(scan_id: str, chain_json: str, severity: str, confidence_score: float, affected_repos: str, step_count: int) -> dict:
    """Create an exploit chain record."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scan_chains (id, scan_id, chain_json, severity, confidence_score, affected_repos, step_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, chain_json, severity, confidence_score, affected_repos, step_count),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_chains WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    record['chain'] = _maybe_load_json(record.get('chain_json'))
    record['affected_repos_list'] = _maybe_load_json(record.get('affected_repos'))
    return record


def code_scan_chain_get_by_scan_id(scan_id: str) -> list:
    """Get all exploit chains for a scan."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM code_scan_chains WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        row['chain'] = _maybe_load_json(row.get('chain_json'))
        row['affected_repos_list'] = _maybe_load_json(row.get('affected_repos'))
    return rows


def code_scan_chain_filter_by_severity(scan_id: str, severity: str) -> list:
    """Get chains for a scan filtered by severity."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_chains WHERE scan_id = ? AND severity = ? ORDER BY created_at ASC',
        (scan_id, severity),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        row['chain'] = _maybe_load_json(row.get('chain_json'))
        row['affected_repos_list'] = _maybe_load_json(row.get('affected_repos'))
    return rows


# --- code_scan_licenses ---

def code_scan_license_create_batch(scan_id: str, repo_identifier: str, records: list) -> int:
    """Insert a batch of license records. Returns count inserted."""
    if not records:
        return 0
    conn = get_db_connection()
    c = conn.cursor()
    count = 0
    for rec in records:
        record_id = rec.get('id') or str(uuid.uuid4())
        c.execute(
            '''
            INSERT INTO code_scan_licenses (id, scan_id, repo_identifier, package_name,
                package_version, ecosystem, license_id, license_category, requires_review, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''',
            (
                record_id, scan_id, repo_identifier,
                rec.get('package_name', ''),
                rec.get('package_version', ''),
                rec.get('ecosystem', ''),
                rec.get('license_id'),
                rec.get('license_category', 'UNKNOWN'),
                1 if rec.get('requires_review') else 0,
            ),
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def code_scan_license_get(scan_id: str, repo_identifier: str) -> list:
    """Get all license records for a scan + repo."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_licenses WHERE scan_id = ? AND repo_identifier = ? ORDER BY created_at ASC',
        (scan_id, repo_identifier),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def code_scan_license_filter(scan_id: str, repo_identifier: str = None, category: str = None) -> list:
    """Filter license records by category."""
    conn = get_db_connection()
    c = conn.cursor()
    query = 'SELECT * FROM code_scan_licenses WHERE scan_id = ?'
    params = [scan_id]
    if repo_identifier:
        query += ' AND repo_identifier = ?'
        params.append(repo_identifier)
    if category:
        query += ' AND license_category = ?'
        params.append(category)
    query += ' ORDER BY created_at ASC'
    c.execute(query, tuple(params))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --- code_scan_container ---

def code_scan_container_create(scan_id: str, repo_identifier: str, dockerfile_path: str, misconfiguration_type: str, severity: str, description: str, recommended_fix: str = None) -> dict:
    """Create a container/Dockerfile finding record."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scan_container (id, scan_id, repo_identifier, dockerfile_path,
            misconfiguration_type, severity, description, recommended_fix, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, repo_identifier, dockerfile_path, misconfiguration_type, severity, description, recommended_fix),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_container WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def code_scan_container_get(scan_id: str, repo_identifier: str) -> list:
    """Get all container findings for a scan + repo."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM code_scan_container WHERE scan_id = ? AND repo_identifier = ? ORDER BY created_at ASC',
        (scan_id, repo_identifier),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --- code_scan_prs ---

def code_scan_pr_create(scan_id: str, repo_identifier: str, findings_addressed: list, branch_name: str = None, pr_url: str = None, pr_status: str = 'PENDING') -> dict:
    """Create a PR record linking findings to a pull request."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    findings_json = json.dumps(findings_addressed) if isinstance(findings_addressed, list) else findings_addressed
    c.execute(
        '''
        INSERT INTO code_scan_prs (id, scan_id, repo_identifier, pr_url, pr_status,
            findings_addressed, branch_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, repo_identifier, pr_url, pr_status, findings_json, branch_name),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_prs WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    record['findings_addressed_list'] = _maybe_load_json(record.get('findings_addressed'))
    return record


def code_scan_pr_get_by_scan_id(scan_id: str) -> list:
    """Get all PR records for a scan."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM code_scan_prs WHERE scan_id = ? ORDER BY created_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        row['findings_addressed_list'] = _maybe_load_json(row.get('findings_addressed'))
    return rows


def code_scan_pr_update_status(pr_id: str, pr_status: str, pr_url: str = None, error_message: str = None) -> None:
    """Update the status and optionally the URL/error of a PR record."""
    conn = get_db_connection()
    c = conn.cursor()
    sets = ['pr_status = ?', 'updated_at = CURRENT_TIMESTAMP']
    params = [pr_status]
    if pr_url is not None:
        sets.append('pr_url = ?')
        params.append(pr_url)
    if error_message is not None:
        sets.append('error_message = ?')
        params.append(error_message)
    params.append(pr_id)
    c.execute(f"UPDATE code_scan_prs SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


# --- code_scan_budget ---

def code_scan_budget_create(scan_id: str, repo_identifier: str = None, budget_limit_usd: float = None) -> dict:
    """Create a budget tracking record for a scan (or per-repo within a scan)."""
    record_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO code_scan_budget (id, scan_id, repo_identifier, input_tokens, output_tokens,
            cost_usd, budget_limit_usd, budget_warning_emitted, updated_at)
        VALUES (?, ?, ?, 0, 0, 0.0, ?, 0, CURRENT_TIMESTAMP)
        ''',
        (record_id, scan_id, repo_identifier, budget_limit_usd),
    )
    conn.commit()
    c.execute('SELECT * FROM code_scan_budget WHERE id = ?', (record_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def code_scan_budget_update(budget_id: str, input_tokens: int = None, output_tokens: int = None, cost_usd: float = None, budget_warning_emitted: bool = None) -> None:
    """Update budget tracking metrics."""
    conn = get_db_connection()
    c = conn.cursor()
    sets = ['updated_at = CURRENT_TIMESTAMP']
    params = []
    if input_tokens is not None:
        sets.append('input_tokens = ?')
        params.append(input_tokens)
    if output_tokens is not None:
        sets.append('output_tokens = ?')
        params.append(output_tokens)
    if cost_usd is not None:
        sets.append('cost_usd = ?')
        params.append(cost_usd)
    if budget_warning_emitted is not None:
        sets.append('budget_warning_emitted = ?')
        params.append(1 if budget_warning_emitted else 0)
    params.append(budget_id)
    c.execute(f"UPDATE code_scan_budget SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


def code_scan_budget_get_by_scan_id(scan_id: str) -> list:
    """Get all budget records for a scan (scan-level + per-repo)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM code_scan_budget WHERE scan_id = ? ORDER BY updated_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def code_scan_budget_get_30day_rolling() -> list:
    """Get budget records from the last 30 days for rolling cost tracking."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        SELECT * FROM code_scan_budget
        WHERE updated_at >= datetime('now', '-30 days')
        ORDER BY updated_at DESC
        ''',
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --- code_scan_settings (extended) ---

def code_scan_settings_get_all() -> dict:
    """Get all code scan settings as a key-value dict. Alias for get_all_code_scan_settings."""
    return get_all_code_scan_settings()


def code_scan_settings_get(key: str):
    """Get a single code scan setting by key. Alias for get_code_scan_setting."""
    return get_code_scan_setting(key)


def code_scan_settings_upsert(key: str, value: str) -> None:
    """Insert or update a code scan setting."""
    set_code_scan_setting(key, value)


# --- Update functions for code_scans new columns ---

def code_scan_update_phase(scan_id: str, scan_phase: str) -> None:
    """Update the scan_phase column of a code_scans record."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'UPDATE code_scans SET scan_phase = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (scan_phase, scan_id),
    )
    conn.commit()
    conn.close()


def code_scan_update_cost(scan_id: str, cost_usd: float) -> None:
    """Update the cost_usd column of a code_scans record."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'UPDATE code_scans SET cost_usd = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (cost_usd, scan_id),
    )
    conn.commit()
    conn.close()


def code_scan_update_repo_counts(scan_id: str, total_repos: int = None, repos_completed: int = None, repos_failed: int = None, repos_skipped: int = None) -> None:
    """Update per-repo count columns on the code_scans record."""
    conn = get_db_connection()
    c = conn.cursor()
    sets = ['updated_at = CURRENT_TIMESTAMP']
    params = []
    if total_repos is not None:
        sets.append('total_repos = ?')
        params.append(total_repos)
    if repos_completed is not None:
        sets.append('repos_completed = ?')
        params.append(repos_completed)
    if repos_failed is not None:
        sets.append('repos_failed = ?')
        params.append(repos_failed)
    if repos_skipped is not None:
        sets.append('repos_skipped = ?')
        params.append(repos_skipped)
    params.append(scan_id)
    c.execute(f"UPDATE code_scans SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


# --- Update functions for code_scan_findings new columns ---

def code_scan_finding_update_type(finding_id: str, finding_type: str, repo_identifier: str = None, sbom_ref: str = None, chain_id: str = None, sca_cve_id: str = None, container_finding_id: str = None) -> None:
    """Update the new holistic-scanner columns on a code_scan_findings record."""
    conn = get_db_connection()
    c = conn.cursor()
    sets = ['finding_type = ?']
    params = [finding_type]
    if repo_identifier is not None:
        sets.append('repo_identifier = ?')
        params.append(repo_identifier)
    if sbom_ref is not None:
        sets.append('sbom_ref = ?')
        params.append(sbom_ref)
    if chain_id is not None:
        sets.append('chain_id = ?')
        params.append(chain_id)
    if sca_cve_id is not None:
        sets.append('sca_cve_id = ?')
        params.append(sca_cve_id)
    if container_finding_id is not None:
        sets.append('container_finding_id = ?')
        params.append(container_finding_id)
    params.append(finding_id)
    c.execute(f"UPDATE code_scan_findings SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


# ==========================================
# EASM (External Attack Surface Management) DAOs
# ==========================================

EASM_SCAN_JSON_FIELDS = (
    'targets_json', 'config_json', 'stats_json',
    'cost_report_json', 'mitre_summary_json', 'audit_log_json',
)

EASM_SCAN_ALLOWED_FIELDS = {
    'label', 'status', 'phase', 'progress', 'status_details', 'stage',
    'targets_json', 'config_json', 'stats_json', 'cost_report_json',
    'mitre_summary_json', 'audit_log_json',
    'assets_count', 'findings_count', 'high_risk_count',
    'stop_requested', 'attestation_id', 'started_at', 'completed_at',
}


def _hydrate_easm_scan(row: dict) -> dict:
    for key in EASM_SCAN_JSON_FIELDS:
        if row.get(key):
            row[key.replace('_json', '')] = _maybe_load_json(row[key])
        row.pop(key, None)
    return row


def create_easm_scan(label: str, targets: list, config: dict, attestation_id: Optional[str] = None) -> str:
    scan_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO easm_scans
            (id, label, status, phase, progress, status_details,
             targets_json, config_json, attestation_id)
        VALUES (?, ?, 'INITIALIZED', 'QUEUED', 0, ?, ?, ?, ?)
        ''',
        (
            scan_id,
            label or 'EASM scan queued',
            'Scan queued',
            json.dumps(targets or []),
            json.dumps(config or {}),
            attestation_id,
        ),
    )
    conn.commit()
    conn.close()
    return scan_id


def update_easm_scan_state(scan_id: str, **fields):
    if not fields:
        return
    sets = []
    params = []
    for key, value in fields.items():
        if key not in EASM_SCAN_ALLOWED_FIELDS:
            continue
        if key in EASM_SCAN_JSON_FIELDS and not isinstance(value, str):
            value = json.dumps(value)
        sets.append(f"{key} = ?")
        params.append(value)
    if not sets:
        return
    sets.append("updated_at = CURRENT_TIMESTAMP")
    params.append(scan_id)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(f"UPDATE easm_scans SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


def get_easm_scans() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM easm_scans ORDER BY created_at DESC')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return [_hydrate_easm_scan(r) for r in rows]


def get_easm_scan(scan_id: str) -> Optional[dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM easm_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_easm_scan(dict(row))


def delete_easm_scan(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM easm_findings WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM easm_validations WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM easm_assets WHERE scan_id = ?', (scan_id,))
    c.execute('DELETE FROM easm_scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()


def request_easm_scan_stop(scan_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_scans
        SET stop_requested = 1,
            status = CASE WHEN status IN ('INITIALIZED', 'RUNNING') THEN 'STOPPING' ELSE status END,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        ('Stop requested by operator', scan_id),
    )
    conn.commit()
    conn.close()


def is_easm_scan_stop_requested(scan_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT stop_requested FROM easm_scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])


def reset_inflight_easm_scans(reason: str = "Stopped after backend restart"):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_scans
        SET status = 'STOPPED',
            stop_requested = 1,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING', 'INITIALIZED', 'STOPPING')
        ''',
        (reason,),
    )
    conn.commit()
    conn.close()


# ---- assets ----

def insert_easm_assets(scan_id: str, assets: list) -> list:
    if not assets:
        return []
    conn = get_db_connection()
    c = conn.cursor()
    inserted_ids = []
    for asset in assets:
        asset_id = asset.get('id') or str(uuid.uuid4())
        c.execute(
            '''
            INSERT INTO easm_assets (
                id, scan_id, ip, hostname, asset_type, os_name, risk_level,
                correlation_score, ports_json, services_json,
                geolocation_json, enrichment_json,
                fp_verdict, fp_confidence, fp_rationale, tags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                asset_id,
                scan_id,
                asset.get('ip'),
                asset.get('hostname'),
                asset.get('asset_type'),
                asset.get('os_name') or asset.get('os'),
                asset.get('risk_level'),
                int(asset.get('correlation_score') or 0),
                json.dumps(asset.get('ports') or []),
                json.dumps(asset.get('services') or []),
                json.dumps(asset.get('geolocation') or {}),
                json.dumps(asset.get('enrichment') or {}),
                asset.get('fp_verdict'),
                asset.get('fp_confidence'),
                asset.get('fp_rationale'),
                json.dumps(asset.get('tags') or []),
            ),
        )
        inserted_ids.append(asset_id)
    conn.commit()
    conn.close()
    return inserted_ids


def get_easm_assets(scan_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM easm_assets WHERE scan_id = ? ORDER BY risk_level DESC, ip ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        for key in ('ports_json', 'services_json', 'geolocation_json', 'enrichment_json', 'tags_json'):
            if r.get(key):
                r[key.replace('_json', '')] = _maybe_load_json(r[key])
            r.pop(key, None)
    return rows


def update_easm_asset_fp_verdict(asset_id: str, verdict: str, confidence: Optional[int], rationale: Optional[str]):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_assets
        SET fp_verdict = ?, fp_confidence = ?, fp_rationale = ?
        WHERE id = ?
        ''',
        (verdict, confidence, rationale, asset_id),
    )
    conn.commit()
    conn.close()


# ---- findings ----

def insert_easm_findings(scan_id: str, findings: list):
    if not findings:
        return
    conn = get_db_connection()
    c = conn.cursor()
    for finding in findings:
        c.execute(
            '''
            INSERT INTO easm_findings (
                id, scan_id, asset_id, ip, hostname, port,
                category, severity, title, description, evidence,
                mitre_technique, mitre_tactic, owasp_category, cve_id,
                confidence, source, ai_verdict, ai_rationale,
                validated, validation_evidence, validation_method,
                fingerprint, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                finding.get('id') or str(uuid.uuid4()),
                scan_id,
                finding.get('asset_id'),
                finding.get('ip'),
                finding.get('hostname'),
                finding.get('port'),
                finding.get('category'),
                finding.get('severity'),
                finding.get('title'),
                finding.get('description'),
                finding.get('evidence'),
                finding.get('mitre_technique'),
                finding.get('mitre_tactic'),
                finding.get('owasp_category'),
                finding.get('cve_id'),
                int(finding.get('confidence') or 0),
                finding.get('source'),
                finding.get('ai_verdict'),
                finding.get('ai_rationale'),
                1 if finding.get('validated') else 0,
                finding.get('validation_evidence'),
                finding.get('validation_method'),
                finding.get('fingerprint'),
                json.dumps(finding.get('details') or {}),
            ),
        )
    conn.commit()
    conn.close()


def update_easm_finding_validation(finding_id: str, validated: bool, evidence: Optional[str], method: Optional[str]):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_findings
        SET validated = ?, validation_evidence = ?, validation_method = ?
        WHERE id = ?
        ''',
        (1 if validated else 0, evidence, method, finding_id),
    )
    conn.commit()
    conn.close()


def update_easm_finding_ai_verdict(finding_id: str, verdict: str, rationale: Optional[str]):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_findings
        SET ai_verdict = ?, ai_rationale = ?
        WHERE id = ?
        ''',
        (verdict, rationale, finding_id),
    )
    conn.commit()
    conn.close()


def get_easm_findings(scan_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT * FROM easm_findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                WHEN 'INFO' THEN 4
                ELSE 5
            END,
            confidence DESC, ip, port
        ''',
        (scan_id,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        r['validated'] = bool(r.get('validated'))
        if r.get('details_json'):
            r['details'] = _maybe_load_json(r['details_json'])
        r.pop('details_json', None)
    return rows


# ---- validations ----

def insert_easm_validation(scan_id: str, validation: dict) -> str:
    val_id = validation.get('id') or str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO easm_validations (
            id, scan_id, finding_id, ip, port, probe_type, probe_target,
            probe_method, mitre_technique, request_summary, response_summary,
            outcome, evidence, risk_delta, duration_ms, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            val_id,
            scan_id,
            validation.get('finding_id'),
            validation.get('ip'),
            validation.get('port'),
            validation.get('probe_type'),
            validation.get('probe_target'),
            validation.get('probe_method'),
            validation.get('mitre_technique'),
            validation.get('request_summary'),
            validation.get('response_summary'),
            validation.get('outcome'),
            validation.get('evidence'),
            validation.get('risk_delta'),
            int(validation.get('duration_ms') or 0),
            validation.get('error'),
        ),
    )
    conn.commit()
    conn.close()
    return val_id


def get_easm_validations(scan_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM easm_validations WHERE scan_id = ? ORDER BY executed_at ASC', (scan_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ---- attestations ----

def create_easm_attestation(operator: str, scope_type: str, scope_value: str,
                            statement: str, signature: str, metadata: dict) -> str:
    att_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO easm_attestations
            (id, operator, scope_type, scope_value, statement, signature, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            att_id,
            operator or 'operator',
            scope_type,
            scope_value,
            statement,
            signature,
            json.dumps(metadata or {}),
        ),
    )
    conn.commit()
    conn.close()
    return att_id


def get_easm_attestations() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT * FROM easm_attestations
        WHERE revoked = 0
        ORDER BY created_at DESC
        '''
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        if r.get('metadata_json'):
            r['metadata'] = _maybe_load_json(r['metadata_json'])
        r.pop('metadata_json', None)
    return rows


def get_easm_attestation(att_id: str) -> Optional[dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM easm_attestations WHERE id = ?', (att_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    record = dict(row)
    if record.get('metadata_json'):
        record['metadata'] = _maybe_load_json(record['metadata_json'])
    record.pop('metadata_json', None)
    return record


def revoke_easm_attestation(att_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE easm_attestations
        SET revoked = 1, revoked_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        (att_id,),
    )
    conn.commit()
    conn.close()


# ---- settings ----

def set_easm_setting(key: str, value):
    if value is None:
        delete_easm_setting(key)
        return
    conn = get_db_connection()
    c = conn.cursor()
    payload = value if isinstance(value, str) else json.dumps(value)
    c.execute(
        '''
        INSERT INTO easm_settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        ''',
        (key, payload),
    )
    conn.commit()
    conn.close()


def get_easm_setting(key: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT value FROM easm_settings WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return row[0]


def get_all_easm_settings() -> dict:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT key, value FROM easm_settings')
    rows = c.fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}


def delete_easm_setting(key: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM easm_settings WHERE key = ?', (key,))
    conn.commit()
    conn.close()


BAS_RUN_JSON_FIELDS = (
    'targets_json', 'scenario_ids_json', 'config_json', 'stats_json', 'audit_log_json',
)

BAS_RUN_ALLOWED_FIELDS = {
    'label', 'status', 'phase', 'progress', 'status_details',
    'targets_json', 'scenario_ids_json', 'config_json', 'stats_json', 'audit_log_json',
    'results_count', 'observed_count', 'blocked_count', 'inconclusive_count',
    'stop_requested', 'attestation_id', 'operator', 'started_at', 'completed_at',
}


def _hydrate_bas_run(row: dict) -> dict:
    for key in BAS_RUN_JSON_FIELDS:
        if row.get(key):
            row[key.replace('_json', '')] = _maybe_load_json(row[key])
        row.pop(key, None)
    return row


def create_bas_run(label: str, targets: list, scenario_ids: list, config: dict,
                   attestation_id: Optional[str], operator: str) -> str:
    run_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO bas_runs
            (id, label, status, phase, progress, status_details,
             targets_json, scenario_ids_json, config_json, attestation_id, operator)
        VALUES (?, ?, 'INITIALIZED', 'QUEUED', 0, ?, ?, ?, ?, ?, ?)
        ''',
        (
            run_id,
            label or 'External BAS validation queued',
            'Run queued',
            json.dumps(targets or []),
            json.dumps(scenario_ids or []),
            json.dumps(config or {}),
            attestation_id,
            operator or 'operator',
        ),
    )
    conn.commit()
    conn.close()
    return run_id


def update_bas_run_state(run_id: str, **fields):
    if not fields:
        return
    sets = []
    params = []
    for key, value in fields.items():
        if key not in BAS_RUN_ALLOWED_FIELDS:
            continue
        if key in BAS_RUN_JSON_FIELDS and not isinstance(value, str):
            value = json.dumps(value)
        sets.append(f"{key} = ?")
        params.append(value)
    if not sets:
        return
    sets.append("updated_at = CURRENT_TIMESTAMP")
    params.append(run_id)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(f"UPDATE bas_runs SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()


def get_bas_runs() -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM bas_runs ORDER BY created_at DESC')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return [_hydrate_bas_run(r) for r in rows]


def get_bas_run(run_id: str) -> Optional[dict]:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM bas_runs WHERE id = ?', (run_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_bas_run(dict(row))


def delete_bas_run(run_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM bas_results WHERE run_id = ?', (run_id,))
    c.execute('DELETE FROM bas_runs WHERE id = ?', (run_id,))
    conn.commit()
    conn.close()


def request_bas_run_stop(run_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE bas_runs
        SET stop_requested = 1,
            status = CASE WHEN status IN ('INITIALIZED', 'RUNNING') THEN 'STOPPING' ELSE status END,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        ('Stop requested by operator', run_id),
    )
    conn.commit()
    conn.close()


def is_bas_run_stop_requested(run_id: str) -> bool:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT stop_requested FROM bas_runs WHERE id = ?', (run_id,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])


def reset_inflight_bas_runs(reason: str = "Stopped after backend restart"):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE bas_runs
        SET status = 'STOPPED',
            stop_requested = 1,
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING', 'INITIALIZED', 'STOPPING')
        ''',
        (reason,),
    )
    conn.commit()
    conn.close()


def insert_bas_result(run_id: str, result: dict) -> str:
    result_id = result.get('id') or str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    details = result.get('details')
    c.execute(
        '''
        INSERT INTO bas_results (
            id, run_id, scenario_id, scenario_name, target, asset, control,
            mitre_technique, mitre_tactic, owasp_category, outcome, severity,
            confidence, evidence, recommendation, request_summary, response_summary,
            duration_ms, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            result_id,
            run_id,
            result.get('scenario_id'),
            result.get('scenario_name'),
            result.get('target'),
            result.get('asset'),
            result.get('control'),
            result.get('mitre_technique'),
            result.get('mitre_tactic'),
            result.get('owasp_category'),
            result.get('outcome'),
            result.get('severity'),
            int(result.get('confidence') or 0),
            result.get('evidence'),
            result.get('recommendation'),
            result.get('request_summary'),
            result.get('response_summary'),
            int(result.get('duration_ms') or 0),
            json.dumps(details or {}),
        ),
    )
    conn.commit()
    conn.close()
    return result_id


def get_bas_results(run_id: str) -> list:
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT * FROM bas_results
        WHERE run_id = ?
        ORDER BY
            CASE outcome
                WHEN 'observed' THEN 0
                WHEN 'inconclusive' THEN 1
                WHEN 'blocked' THEN 2
                WHEN 'not_applicable' THEN 3
                ELSE 4
            END,
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            executed_at ASC
        ''',
        (run_id,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get('details_json'):
            row['details'] = _maybe_load_json(row['details_json'])
        row.pop('details_json', None)
    return rows


# ==========================================
# Threat Model Session DAO Functions
# ==========================================

def create_threat_model_session(name: str, description: str = None, input_mode: str = "documentation") -> str:
    """Create a new threat model session and return its ID."""
    session_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO threat_model_sessions (id, name, description, input_mode)
        VALUES (?, ?, ?, ?)
        ''',
        (session_id, name, description, input_mode),
    )
    conn.commit()
    conn.close()
    return session_id


def get_threat_model_sessions() -> List[Dict]:
    """Return all threat model sessions ordered by created_at DESC (summary fields only)."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT
            id, name, description, input_mode, status, phase, progress,
            status_details, created_at, updated_at
        FROM threat_model_sessions
        ORDER BY created_at DESC
        '''
    )
    sessions = [dict(row) for row in c.fetchall()]
    conn.close()
    return sessions


def get_threat_model_session(session_id: str) -> Optional[Dict]:
    """Get a single threat model session with all fields. Hydrate JSON columns."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM threat_model_sessions WHERE id = ?', (session_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    session = dict(row)
    json_fields = ['decomposition', 'threats', 'attack_scenarios', 'risk_matrix', 'mitigations', 'report_json']
    for field in json_fields:
        if session.get(field):
            try:
                session[field] = json.loads(session[field])
            except Exception:
                pass
    return session


def update_threat_model_session(session_id: str, **fields):
    """Update a threat model session with arbitrary valid fields."""
    if not fields:
        return
    valid_fields = [
        'status', 'phase', 'progress', 'status_details',
        'decomposition', 'threats', 'attack_scenarios',
        'risk_matrix', 'mitigations', 'report_json',
    ]
    updates = []
    params = []
    for key, value in fields.items():
        if key not in valid_fields:
            continue
        updates.append(f"{key} = ?")
        if isinstance(value, (dict, list)):
            params.append(json.dumps(value))
        else:
            params.append(value)
    if not updates:
        return
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(session_id)
    conn = get_db_connection()
    c = conn.cursor()
    query = f"UPDATE threat_model_sessions SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()


def delete_threat_model_session(session_id: str):
    """Delete a threat model session and cascade to uploads and findings."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM threat_model_uploads WHERE session_id = ?', (session_id,))
    c.execute('DELETE FROM threat_model_findings WHERE session_id = ?', (session_id,))
    c.execute('DELETE FROM threat_model_sessions WHERE id = ?', (session_id,))
    conn.commit()
    conn.close()


def reset_inflight_threat_model_sessions(reason: str = "Stopped after backend restart"):
    """Mark all RUNNING threat model sessions as FAILED on startup recovery."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        UPDATE threat_model_sessions
        SET status = 'FAILED',
            status_details = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE status IN ('RUNNING')
        ''',
        (reason,),
    )
    conn.commit()
    conn.close()


# ==========================================
# Threat Model Upload DAO Functions
# ==========================================

def create_threat_model_upload(session_id: str, filename: str, file_type: str, file_size: int, storage_path: str) -> str:
    """Insert a new upload record for a threat model session. Returns the upload ID."""
    upload_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO threat_model_uploads (id, session_id, filename, file_type, file_size, storage_path)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (upload_id, session_id, filename, file_type, file_size, storage_path),
    )
    conn.commit()
    conn.close()
    return upload_id


def get_threat_model_uploads(session_id: str) -> List[Dict]:
    """Return all uploads for a given session_id, ordered by created_at ASC."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, session_id, filename, file_type, file_size, storage_path,
               parsed_content, extraction_metadata, created_at
        FROM threat_model_uploads
        WHERE session_id = ?
        ORDER BY created_at ASC
        ''',
        (session_id,),
    )
    uploads = [dict(row) for row in c.fetchall()]
    conn.close()
    for upload in uploads:
        if upload.get("extraction_metadata"):
            try:
                upload["extraction_metadata"] = json.loads(upload["extraction_metadata"])
            except Exception:
                pass
    return uploads


def update_threat_model_upload(upload_id: str, parsed_content: str = None, extraction_metadata=None):
    """Update an upload record's parsed_content and extraction_metadata fields."""
    conn = get_db_connection()
    c = conn.cursor()
    meta_value = extraction_metadata
    if isinstance(extraction_metadata, (dict, list)):
        meta_value = json.dumps(extraction_metadata)
    c.execute(
        '''
        UPDATE threat_model_uploads
        SET parsed_content = ?, extraction_metadata = ?
        WHERE id = ?
        ''',
        (parsed_content, meta_value, upload_id),
    )
    conn.commit()
    conn.close()


def delete_threat_model_uploads(session_id: str):
    """Delete all uploads for a given session_id."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM threat_model_uploads WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()


# ==========================================
# THREAT MODEL FINDINGS DAO
# ==========================================

def insert_threat_model_findings(session_id: str, findings: List[Dict]):
    """Bulk insert findings into the threat_model_findings table."""
    conn = get_db_connection()
    c = conn.cursor()
    for finding in findings:
        mitigations_val = finding.get("mitigations")
        if isinstance(mitigations_val, (list, dict)):
            mitigations_val = json.dumps(mitigations_val)

        attack_scenario_val = finding.get("attack_scenario")
        if isinstance(attack_scenario_val, dict):
            attack_scenario_val = json.dumps(attack_scenario_val)

        c.execute('''
            INSERT INTO threat_model_findings (
                id, session_id, threat_id, stride_category, title, description,
                affected_component, affected_asset, threat_actor, prerequisites,
                likelihood, impact, dread_damage, dread_reproducibility,
                dread_exploitability, dread_affected_users, dread_discoverability,
                dread_score, risk_level, mitigations, rbi_reference, sebi_reference,
                nist_mapping, owasp_reference, attack_scenario, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get("id") or str(uuid.uuid4()),
            session_id,
            finding.get("threat_id"),
            finding.get("stride_category"),
            finding.get("title"),
            finding.get("description"),
            finding.get("affected_component"),
            finding.get("affected_asset"),
            finding.get("threat_actor"),
            finding.get("prerequisites"),
            finding.get("likelihood"),
            finding.get("impact"),
            finding.get("dread_damage"),
            finding.get("dread_reproducibility"),
            finding.get("dread_exploitability"),
            finding.get("dread_affected_users"),
            finding.get("dread_discoverability"),
            finding.get("dread_score"),
            finding.get("risk_level"),
            mitigations_val,
            finding.get("rbi_reference"),
            finding.get("sebi_reference"),
            finding.get("nist_mapping"),
            finding.get("owasp_reference"),
            attack_scenario_val,
            finding.get("status", "OPEN"),
        ))
    conn.commit()
    conn.close()


def get_threat_model_findings(session_id: str) -> List[Dict]:
    """Return all findings for a session with JSON field hydration."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM threat_model_findings WHERE session_id = ? ORDER BY created_at ASC', (session_id,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for row in rows:
        if row.get("mitigations"):
            try:
                row["mitigations"] = json.loads(row["mitigations"])
            except Exception:
                pass
        if row.get("attack_scenario"):
            try:
                row["attack_scenario"] = json.loads(row["attack_scenario"])
            except Exception:
                pass
    return rows


def delete_threat_model_findings(session_id: str):
    """Delete all findings for a given session_id."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM threat_model_findings WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()


# ==========================================
# Unified Vulnerability Dashboard DAO Functions
# ==========================================

# Valid status transitions for unified findings lifecycle
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


def create_unified_finding(finding: dict) -> str:
    """Insert a unified finding with all fields from the dict. Returns the finding ID."""
    finding_id = finding.get('id') or str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO unified_findings (
            id, title, description, severity, cwe_id, affected_component,
            status, assignee_id, correlation_key, title_tokens, module_tags,
            evidence_count, first_seen_at, last_seen_at, resolved_at,
            sla_breach, review_flag, finding_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        finding_id,
        finding.get('title'),
        finding.get('description'),
        finding.get('severity'),
        finding.get('cwe_id'),
        finding.get('affected_component'),
        finding.get('status', 'Open'),
        finding.get('assignee_id'),
        finding.get('correlation_key'),
        finding.get('title_tokens'),
        finding.get('module_tags'),
        finding.get('evidence_count', 1),
        finding.get('first_seen_at', now),
        finding.get('last_seen_at', now),
        finding.get('resolved_at'),
        finding.get('sla_breach', 0),
        finding.get('review_flag', 0),
        finding.get('finding_type'),
    ))
    conn.commit()
    conn.close()
    return finding_id


def get_unified_finding(finding_id: str) -> Optional[Dict]:
    """Get a single unified finding by ID. Returns dict with all fields or None."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM unified_findings WHERE id = ?', (finding_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    finding = dict(row)
    # Hydrate JSON fields
    if finding.get('module_tags'):
        try:
            finding['module_tags'] = json.loads(finding['module_tags'])
        except Exception:
            pass
    if finding.get('title_tokens') and isinstance(finding['title_tokens'], str):
        # title_tokens stored as space-separated string; keep as-is for DAO consumers
        pass
    return finding


def list_unified_findings(filters: dict = None, sort_field: str = 'first_seen_at',
                          sort_dir: str = 'DESC', page: int = 1,
                          page_size: int = 50) -> tuple:
    """
    Return (list_of_findings, total_count). Supports filtering, sorting, and pagination.
    Filters: module, severity (list), status (list), cwe_id, affected_component,
             assignee_id, date_from, date_to, sla_breach, review_flag.
    """
    filters = filters or {}
    where_clauses = []
    params = []

    # Build WHERE clause dynamically
    if 'module' in filters and filters['module']:
        # module_tags is stored as JSON array string, use LIKE for contains check
        where_clauses.append("module_tags LIKE ?")
        params.append(f'%"{filters["module"]}"%')

    if 'severity' in filters and filters['severity']:
        severities = filters['severity'] if isinstance(filters['severity'], list) else [filters['severity']]
        placeholders = ','.join('?' * len(severities))
        where_clauses.append(f"severity IN ({placeholders})")
        params.extend(severities)

    if 'status' in filters and filters['status']:
        statuses = filters['status'] if isinstance(filters['status'], list) else [filters['status']]
        placeholders = ','.join('?' * len(statuses))
        where_clauses.append(f"status IN ({placeholders})")
        params.extend(statuses)

    if 'cwe_id' in filters and filters['cwe_id']:
        where_clauses.append("cwe_id = ?")
        params.append(filters['cwe_id'])

    if 'affected_component' in filters and filters['affected_component']:
        where_clauses.append("affected_component = ?")
        params.append(filters['affected_component'])

    if 'assignee_id' in filters and filters['assignee_id']:
        where_clauses.append("assignee_id = ?")
        params.append(filters['assignee_id'])

    if 'date_from' in filters and filters['date_from']:
        where_clauses.append("first_seen_at >= ?")
        params.append(filters['date_from'])

    if 'date_to' in filters and filters['date_to']:
        where_clauses.append("last_seen_at <= ?")
        params.append(filters['date_to'])

    if 'sla_breach' in filters and filters['sla_breach'] is not None:
        where_clauses.append("sla_breach = ?")
        params.append(int(filters['sla_breach']))

    if 'review_flag' in filters and filters['review_flag'] is not None:
        where_clauses.append("review_flag = ?")
        params.append(int(filters['review_flag']))

    if 'finding_type' in filters and filters['finding_type']:
        where_clauses.append("finding_type = ?")
        params.append(filters['finding_type'])

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Sorting with severity special case
    allowed_sort_fields = ['title', 'severity', 'status', 'first_seen_at', 'last_seen_at', 'evidence_count']
    if sort_field not in allowed_sort_fields:
        sort_field = 'first_seen_at'
    sort_dir = 'ASC' if sort_dir.upper() == 'ASC' else 'DESC'

    if sort_field == 'severity':
        order_sql = f"""ORDER BY CASE severity
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 4
            WHEN 'Informational' THEN 5
            ELSE 6 END {sort_dir}"""
    else:
        order_sql = f"ORDER BY {sort_field} {sort_dir}"

    # Get total count
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    count_query = f"SELECT COUNT(*) as cnt FROM unified_findings{where_sql}"
    c.execute(count_query, tuple(params))
    total_count = c.fetchone()['cnt']

    # Get paginated results
    offset = (page - 1) * page_size
    data_query = f"SELECT * FROM unified_findings{where_sql} {order_sql} LIMIT ? OFFSET ?"
    c.execute(data_query, tuple(params) + (page_size, offset))
    rows = c.fetchall()
    conn.close()

    findings = []
    for row in rows:
        finding = dict(row)
        if finding.get('module_tags'):
            try:
                finding['module_tags'] = json.loads(finding['module_tags'])
            except Exception:
                pass
        findings.append(finding)

    return (findings, total_count)


def update_unified_finding(finding_id: str, **fields):
    """Partial update of a unified finding. Accepts any subset of valid fields."""
    valid_fields = [
        'status', 'assignee_id', 'severity', 'resolved_at', 'sla_breach',
        'review_flag', 'evidence_count', 'last_seen_at', 'module_tags',
        'title_tokens', 'updated_at'
    ]
    updates = []
    params = []
    for key, value in fields.items():
        if key not in valid_fields:
            continue
        updates.append(f"{key} = ?")
        if key == 'module_tags' and isinstance(value, (list, dict)):
            params.append(json.dumps(value))
        else:
            params.append(value)
    if not updates:
        return
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(finding_id)
    conn = get_db_connection()
    c = conn.cursor()
    query = f"UPDATE unified_findings SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
    conn.commit()
    conn.close()


def find_by_correlation_key(key: str) -> Optional[Dict]:
    """Find a single unified finding by exact correlation_key match."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM unified_findings WHERE correlation_key = ?', (key,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    finding = dict(row)
    if finding.get('module_tags'):
        try:
            finding['module_tags'] = json.loads(finding['module_tags'])
        except Exception:
            pass
    return finding


def find_by_component(component: str) -> List[Dict]:
    """Find all unified findings matching an affected_component (exact match)."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM unified_findings WHERE affected_component = ?', (component,))
    rows = c.fetchall()
    conn.close()
    findings = []
    for row in rows:
        finding = dict(row)
        if finding.get('module_tags'):
            try:
                finding['module_tags'] = json.loads(finding['module_tags'])
            except Exception:
                pass
        findings.append(finding)
    return findings


def search_findings(query: str, filters: dict = None, page: int = 1,
                    page_size: int = 50) -> tuple:
    """
    Full-text search on title and description using LIKE '%query%'.
    Apply same filters as list_unified_findings. Returns (list, total_count).
    """
    filters = filters or {}
    where_clauses = ["(title LIKE ? OR description LIKE ?)"]
    search_pattern = f"%{query}%"
    params = [search_pattern, search_pattern]

    # Apply additional filters (same logic as list_unified_findings)
    if 'module' in filters and filters['module']:
        where_clauses.append("module_tags LIKE ?")
        params.append(f'%"{filters["module"]}"%')

    if 'severity' in filters and filters['severity']:
        severities = filters['severity'] if isinstance(filters['severity'], list) else [filters['severity']]
        placeholders = ','.join('?' * len(severities))
        where_clauses.append(f"severity IN ({placeholders})")
        params.extend(severities)

    if 'status' in filters and filters['status']:
        statuses = filters['status'] if isinstance(filters['status'], list) else [filters['status']]
        placeholders = ','.join('?' * len(statuses))
        where_clauses.append(f"status IN ({placeholders})")
        params.extend(statuses)

    if 'cwe_id' in filters and filters['cwe_id']:
        where_clauses.append("cwe_id = ?")
        params.append(filters['cwe_id'])

    if 'affected_component' in filters and filters['affected_component']:
        where_clauses.append("affected_component = ?")
        params.append(filters['affected_component'])

    if 'assignee_id' in filters and filters['assignee_id']:
        where_clauses.append("assignee_id = ?")
        params.append(filters['assignee_id'])

    if 'date_from' in filters and filters['date_from']:
        where_clauses.append("first_seen_at >= ?")
        params.append(filters['date_from'])

    if 'date_to' in filters and filters['date_to']:
        where_clauses.append("last_seen_at <= ?")
        params.append(filters['date_to'])

    if 'sla_breach' in filters and filters['sla_breach'] is not None:
        where_clauses.append("sla_breach = ?")
        params.append(int(filters['sla_breach']))

    if 'review_flag' in filters and filters['review_flag'] is not None:
        where_clauses.append("review_flag = ?")
        params.append(int(filters['review_flag']))

    if 'finding_type' in filters and filters['finding_type']:
        where_clauses.append("finding_type = ?")
        params.append(filters['finding_type'])

    where_sql = " WHERE " + " AND ".join(where_clauses)

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Total count
    count_query = f"SELECT COUNT(*) as cnt FROM unified_findings{where_sql}"
    c.execute(count_query, tuple(params))
    total_count = c.fetchone()['cnt']

    # Paginated results
    offset = (page - 1) * page_size
    data_query = f"SELECT * FROM unified_findings{where_sql} ORDER BY first_seen_at DESC LIMIT ? OFFSET ?"
    c.execute(data_query, tuple(params) + (page_size, offset))
    rows = c.fetchall()
    conn.close()

    findings = []
    for row in rows:
        finding = dict(row)
        if finding.get('module_tags'):
            try:
                finding['module_tags'] = json.loads(finding['module_tags'])
            except Exception:
                pass
        findings.append(finding)

    return (findings, total_count)


def bulk_update_status(finding_ids: list, new_status: str, user_id: str = None,
                       comment: str = None) -> tuple:
    """
    Batch status transition with validation. Returns (succeeded_ids, failed_ids).
    For each finding, validates the transition against VALID_TRANSITIONS.
    If valid, updates status and creates an audit entry.
    """
    succeeded_ids = []
    failed_ids = []

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    for finding_id in finding_ids:
        c.execute('SELECT id, status FROM unified_findings WHERE id = ?', (finding_id,))
        row = c.fetchone()
        if not row:
            failed_ids.append(finding_id)
            continue

        current_status = row['status']
        valid_targets = VALID_TRANSITIONS.get(current_status, [])

        if new_status not in valid_targets:
            failed_ids.append(finding_id)
            continue

        # Update the finding status
        now = datetime.datetime.utcnow().isoformat()
        resolved_at = now if new_status in ('Fixed', 'Verified', 'Closed') else None

        update_params = [new_status, finding_id]
        if resolved_at:
            c.execute('''
                UPDATE unified_findings
                SET status = ?, resolved_at = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (new_status, resolved_at, finding_id))
        else:
            c.execute('''
                UPDATE unified_findings
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (new_status, finding_id))

        # Create audit log entry
        audit_id = str(uuid.uuid4())
        c.execute('''
            INSERT INTO finding_audit_log (
                id, unified_finding_id, action, previous_value, new_value,
                user_id, user_display_name, comment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_id,
            finding_id,
            'status_change',
            current_status,
            new_status,
            user_id,
            None,
            comment,
        ))

        succeeded_ids.append(finding_id)

    conn.commit()
    conn.close()
    return (succeeded_ids, failed_ids)


###############################################################################
# Evidence Sources DAO
###############################################################################


def add_evidence_source(unified_finding_id: str, source_module: str,
                        source_finding_id: str, source_scan_id: str,
                        source_title: str = None, source_severity: str = None,
                        source_evidence: str = None,
                        source_remediation: str = None) -> str:
    """
    Insert a new evidence source linking a raw source finding to a unified finding.
    Returns the generated evidence source ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    evidence_id = str(uuid.uuid4())

    cursor.execute('''
        INSERT INTO evidence_sources (
            id, unified_finding_id, source_module, source_finding_id,
            source_scan_id, source_title, source_severity,
            source_evidence, source_remediation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        evidence_id,
        unified_finding_id,
        source_module,
        source_finding_id,
        source_scan_id,
        source_title,
        source_severity,
        source_evidence,
        source_remediation,
    ))

    conn.commit()
    conn.close()
    return evidence_id


def get_evidence_sources(unified_finding_id: str) -> List[Dict]:
    """
    Get all evidence sources for a given unified finding, ordered by ingested_at ASC.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, unified_finding_id, source_module, source_finding_id,
               source_scan_id, source_title, source_severity,
               source_evidence, source_remediation, ingested_at
        FROM evidence_sources
        WHERE unified_finding_id = ?
        ORDER BY ingested_at ASC
    ''', (unified_finding_id,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def count_distinct_modules(unified_finding_id: str) -> int:
    """
    Count distinct source_module values for a given unified finding.
    Used for the cross-validated indicator (>=2 means cross-validated).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT COUNT(DISTINCT source_module)
        FROM evidence_sources
        WHERE unified_finding_id = ?
    ''', (unified_finding_id,))

    count = cursor.fetchone()[0]
    conn.close()
    return count


def add_audit_entry(unified_finding_id: str, action: str,
                    previous_value: str = None, new_value: str = None,
                    user_id: str = None, user_display_name: str = None,
                    comment: str = None) -> str:
    """
    Insert a new audit log entry for a unified finding.
    Returns the generated audit entry ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    entry_id = str(uuid.uuid4())

    cursor.execute('''
        INSERT INTO finding_audit_log (
            id, unified_finding_id, action, previous_value,
            new_value, user_id, user_display_name, comment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry_id,
        unified_finding_id,
        action,
        previous_value,
        new_value,
        user_id,
        user_display_name,
        comment,
    ))

    conn.commit()
    conn.close()
    return entry_id


def get_audit_log(unified_finding_id: str) -> List[Dict]:
    """
    Get all audit log entries for a given unified finding, ordered by created_at ASC.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, unified_finding_id, action, previous_value,
               new_value, user_id, user_display_name, comment, created_at
        FROM finding_audit_log
        WHERE unified_finding_id = ?
        ORDER BY created_at ASC
    ''', (unified_finding_id,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


# ==========================================
# Scan Runs DAO Functions
# ==========================================

def create_scan_run(source_module: str, source_scan_id: str, scope: str = None,
                    finding_ids: list = None, new_count: int = 0,
                    persisted_count: int = 0, fixed_count: int = 0) -> str:
    """
    Insert a new scan run record into unified_scan_runs.
    Stores finding_ids as a JSON string. Returns the scan run ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    run_id = str(uuid.uuid4())

    cursor.execute('''
        INSERT INTO unified_scan_runs (
            id, source_module, source_scan_id, scope,
            finding_ids_json, new_count, persisted_count, fixed_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        run_id,
        source_module,
        source_scan_id,
        scope,
        json.dumps(finding_ids or []),
        new_count,
        persisted_count,
        fixed_count,
    ))

    conn.commit()
    conn.close()
    return run_id


def get_previous_scan_run(source_module: str, scope: str = None) -> Optional[Dict]:
    """
    Get the most recent scan run for the same source_module and scope,
    ordered by ingested_at DESC, LIMIT 1.
    Hydrates finding_ids_json back to a list. Returns None if no previous run exists.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if scope is None:
        cursor.execute('''
            SELECT id, source_module, source_scan_id, scope,
                   finding_ids_json, new_count, persisted_count, fixed_count, ingested_at
            FROM unified_scan_runs
            WHERE source_module = ? AND scope IS NULL
            ORDER BY ingested_at DESC
            LIMIT 1
        ''', (source_module,))
    else:
        cursor.execute('''
            SELECT id, source_module, source_scan_id, scope,
                   finding_ids_json, new_count, persisted_count, fixed_count, ingested_at
            FROM unified_scan_runs
            WHERE source_module = ? AND scope = ?
            ORDER BY ingested_at DESC
            LIMIT 1
        ''', (source_module, scope))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    result = dict(row)
    result['finding_ids'] = json.loads(result.pop('finding_ids_json') or '[]')
    return result


def get_scan_run(run_id: str) -> Optional[Dict]:
    """
    Get a single scan run by ID. Hydrates finding_ids_json back to a list.
    Returns None if the run does not exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, source_module, source_scan_id, scope,
               finding_ids_json, new_count, persisted_count, fixed_count, ingested_at
        FROM unified_scan_runs
        WHERE id = ?
    ''', (run_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    result = dict(row)
    result['finding_ids'] = json.loads(result.pop('finding_ids_json') or '[]')
    return result


# ==========================================
# User and Role DAO Functions
# ==========================================

def create_dashboard_user(email: str, display_name: str, role_id: str = None) -> str:
    """
    Insert a new user into dashboard_users table with a uuid4 ID.
    Returns the user ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = str(uuid.uuid4())

    cursor.execute('''
        INSERT INTO dashboard_users (id, email, display_name, role_id)
        VALUES (?, ?, ?, ?)
    ''', (user_id, email, display_name, role_id))

    conn.commit()
    conn.close()
    return user_id


def list_dashboard_users() -> List[Dict]:
    """
    Get all dashboard users. Returns as list of dicts.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, email, display_name, role_id, is_active, created_at, updated_at
        FROM dashboard_users
        ORDER BY created_at DESC
    ''')

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_user(user_id: str) -> Optional[Dict]:
    """
    Get a single dashboard user by ID. Returns None if not found.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, email, display_name, role_id, is_active, created_at, updated_at
        FROM dashboard_users
        WHERE id = ?
    ''', (user_id,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return dict(row)


def update_user_role(user_id: str, role_id: str):
    """
    Update the role_id field for a user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE dashboard_users
        SET role_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (role_id, user_id))

    conn.commit()
    conn.close()


def create_dashboard_role(name: str, description: str = None, permissions_json: str = None) -> str:
    """
    Insert a new role into dashboard_roles table with a uuid4 ID.
    Returns the role ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    role_id = str(uuid.uuid4())

    cursor.execute('''
        INSERT INTO dashboard_roles (id, name, description, permissions_json)
        VALUES (?, ?, ?, ?)
    ''', (role_id, name, description, permissions_json))

    conn.commit()
    conn.close()
    return role_id


def get_component_owner(component_path: str) -> Optional[str]:
    """
    Look up component_owners table, find the first record where
    component_path matches the component_pattern (using SQL LIKE).
    Returns the owner_user_id or None if no match.
    If multiple patterns match, returns the one with the longest pattern.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT component_pattern, owner_user_id
        FROM component_owners
        WHERE ? LIKE component_pattern
        ORDER BY LENGTH(component_pattern) DESC
        LIMIT 1
    ''', (component_path,))

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return row['owner_user_id']


# ==========================================
# Unified Dashboard: Metrics DAO Functions
# ==========================================

SEVERITY_WEIGHTS = {'Critical': 10, 'High': 5, 'Medium': 2, 'Low': 1, 'Informational': 0}


def get_severity_distribution(filters: dict = None) -> Dict[str, int]:
    """
    Count of open findings by severity.
    Query unified_findings WHERE status NOT IN ('Fixed','Verified','Closed','Wont_Fix','False_Positive').
    If filters provided, apply module/severity/component filters.
    Return dict like {'Critical': 3, 'High': 5, 'Medium': 10, 'Low': 2, 'Informational': 0}.
    """
    filters = filters or {}
    conn = get_db_connection()
    c = conn.cursor()

    closed_statuses = ('Fixed', 'Verified', 'Closed', 'Wont_Fix', 'False_Positive')
    where_clauses = [f"status NOT IN ({','.join('?' * len(closed_statuses))})"]
    params = list(closed_statuses)

    # Apply optional filters
    if 'module' in filters and filters['module']:
        where_clauses.append("module_tags LIKE ?")
        params.append(f'%"{filters["module"]}"%')

    if 'severity' in filters and filters['severity']:
        severities = filters['severity'] if isinstance(filters['severity'], list) else [filters['severity']]
        placeholders = ','.join('?' * len(severities))
        where_clauses.append(f"severity IN ({placeholders})")
        params.extend(severities)

    if 'component' in filters and filters['component']:
        where_clauses.append("affected_component LIKE ?")
        params.append(f'%{filters["component"]}%')

    where_sql = ' AND '.join(where_clauses)
    query = f"SELECT severity, COUNT(*) as cnt FROM unified_findings WHERE {where_sql} GROUP BY severity"

    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Initialize all severities to 0, then fill from query results
    result = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for row in rows:
        result[row['severity']] = row['cnt']

    return result


def get_risk_posture_timeseries(days: int = 90, filters: dict = None) -> List[Dict]:
    """
    Daily weighted sum over time.
    For each day in the last N days, count open findings (not yet resolved at that date,
    meaning first_seen_at <= date AND (resolved_at IS NULL OR resolved_at > date))
    and compute weighted sum: Critical×10, High×5, Medium×2, Low×1, Informational×0.
    Return list of dicts: [{'date': '2025-01-01', 'score': 150}, ...].
    """
    filters = filters or {}
    conn = get_db_connection()
    c = conn.cursor()

    # Query all relevant findings once (those that were open at some point in the window)
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=days - 1)

    where_clauses = ["first_seen_at <= ?"]
    params = [today.isoformat() + 'T23:59:59']

    # Only include findings that were open at some point in the window
    # (resolved_at IS NULL means still open, or resolved_at >= start_date means was open during window)
    where_clauses.append("(resolved_at IS NULL OR resolved_at >= ?)")
    params.append(start_date.isoformat())

    # Apply optional filters
    if 'module' in filters and filters['module']:
        where_clauses.append("module_tags LIKE ?")
        params.append(f'%"{filters["module"]}"%')

    if 'severity' in filters and filters['severity']:
        severities = filters['severity'] if isinstance(filters['severity'], list) else [filters['severity']]
        placeholders = ','.join('?' * len(severities))
        where_clauses.append(f"severity IN ({placeholders})")
        params.extend(severities)

    if 'component' in filters and filters['component']:
        where_clauses.append("affected_component LIKE ?")
        params.append(f'%{filters["component"]}%')

    where_sql = ' AND '.join(where_clauses)
    query = f"SELECT severity, first_seen_at, resolved_at FROM unified_findings WHERE {where_sql}"

    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Parse findings into list of dicts for iteration
    findings = []
    for row in rows:
        first_seen = row['first_seen_at'][:10] if row['first_seen_at'] else None
        resolved = row['resolved_at'][:10] if row['resolved_at'] else None
        if first_seen:
            findings.append({
                'severity': row['severity'],
                'first_seen_date': first_seen,
                'resolved_date': resolved,
            })

    # Iterate day by day and compute score
    result = []
    current_date = start_date
    while current_date <= today:
        date_str = current_date.isoformat()
        score = 0
        for f in findings:
            # Finding was open on this date if first_seen_at <= date AND (resolved_at is None OR resolved_at > date)
            if f['first_seen_date'] <= date_str:
                if f['resolved_date'] is None or f['resolved_date'] > date_str:
                    score += SEVERITY_WEIGHTS.get(f['severity'], 0)
        result.append({'date': date_str, 'score': score})
        current_date += datetime.timedelta(days=1)

    return result


def get_mttr_by_severity(days: int = 30) -> Dict[str, float]:
    """
    Mean time to resolve per severity.
    Query findings with resolved_at not null and resolved_at within the last N days.
    Compute average of (resolved_at - first_seen_at) in hours for each severity.
    Return dict like {'Critical': 48.5, 'High': 72.0, ...}. Return 0 for severities with no resolved findings.
    """
    conn = get_db_connection()
    c = conn.cursor()

    cutoff_date = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).isoformat()

    c.execute('''
        SELECT severity, first_seen_at, resolved_at
        FROM unified_findings
        WHERE resolved_at IS NOT NULL AND resolved_at >= ?
    ''', (cutoff_date,))
    rows = c.fetchall()
    conn.close()

    # Aggregate hours per severity
    severity_hours: Dict[str, List[float]] = {
        'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Informational': []
    }

    for row in rows:
        severity = row['severity']
        first_seen = row['first_seen_at']
        resolved = row['resolved_at']

        if not first_seen or not resolved:
            continue

        try:
            # Parse timestamps - handle both datetime and date formats
            first_dt = datetime.datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            resolved_dt = datetime.datetime.fromisoformat(resolved.replace('Z', '+00:00'))
            delta_hours = (resolved_dt - first_dt).total_seconds() / 3600.0
            if delta_hours >= 0 and severity in severity_hours:
                severity_hours[severity].append(delta_hours)
        except (ValueError, TypeError):
            continue

    # Compute averages
    result = {}
    for sev in ('Critical', 'High', 'Medium', 'Low', 'Informational'):
        hours_list = severity_hours[sev]
        if hours_list:
            result[sev] = round(sum(hours_list) / len(hours_list), 1)
        else:
            result[sev] = 0.0

    return result


def get_sla_compliance() -> Dict:
    """
    Percentage meeting SLA per severity.
    SLA thresholds: Critical: 7 days, High: 30 days, Medium: 90 days.
    For each severity with a threshold, count total resolved findings and count those resolved within threshold.
    Return: {'Critical': {'compliant': 5, 'total': 8, 'percentage': 62.5}, 'High': {...}, 'Medium': {...}}.
    """
    sla_thresholds = {'Critical': 7, 'High': 30, 'Medium': 90}

    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        SELECT severity, first_seen_at, resolved_at
        FROM unified_findings
        WHERE resolved_at IS NOT NULL AND severity IN ('Critical', 'High', 'Medium')
    ''')
    rows = c.fetchall()
    conn.close()

    # Track per severity
    totals: Dict[str, int] = {'Critical': 0, 'High': 0, 'Medium': 0}
    compliant_counts: Dict[str, int] = {'Critical': 0, 'High': 0, 'Medium': 0}

    for row in rows:
        severity = row['severity']
        first_seen = row['first_seen_at']
        resolved = row['resolved_at']

        if not first_seen or not resolved or severity not in sla_thresholds:
            continue

        try:
            first_dt = datetime.datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            resolved_dt = datetime.datetime.fromisoformat(resolved.replace('Z', '+00:00'))
            delta_days = (resolved_dt - first_dt).total_seconds() / 86400.0
            totals[severity] += 1
            if delta_days <= sla_thresholds[severity]:
                compliant_counts[severity] += 1
        except (ValueError, TypeError):
            continue

    result = {}
    for sev in ('Critical', 'High', 'Medium'):
        total = totals[sev]
        compliant = compliant_counts[sev]
        percentage = round((compliant / total) * 100, 1) if total > 0 else 0.0
        result[sev] = {
            'compliant': compliant,
            'total': total,
            'percentage': percentage,
        }

    return result


def get_component_health() -> List[Dict]:
    """
    For each distinct affected_component in open findings, compute:
    - finding_count
    - highest_severity
    - health_score = max(0, 100 - (Critical×25 + High×10 + Medium×3 + Low×1))
    Return sorted by health_score ASC (worst first).
    """
    conn = get_db_connection()
    c = conn.cursor()

    closed_statuses = ('Fixed', 'Verified', 'Closed', 'Wont_Fix', 'False_Positive')
    placeholders = ','.join('?' * len(closed_statuses))

    c.execute(f'''
        SELECT affected_component, severity, COUNT(*) as cnt
        FROM unified_findings
        WHERE status NOT IN ({placeholders})
        AND affected_component IS NOT NULL AND affected_component != ''
        GROUP BY affected_component, severity
    ''', closed_statuses)
    rows = c.fetchall()
    conn.close()

    # Aggregate per component
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    health_deductions = {'Critical': 25, 'High': 10, 'Medium': 3, 'Low': 1, 'Informational': 0}

    components: Dict[str, Dict] = {}
    for row in rows:
        comp = row['affected_component']
        sev = row['severity']
        cnt = row['cnt']

        if comp not in components:
            components[comp] = {
                'component': comp,
                'finding_count': 0,
                'severity_counts': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0},
            }

        components[comp]['finding_count'] += cnt
        components[comp]['severity_counts'][sev] = cnt

    # Compute health_score and highest_severity for each component
    result = []
    for comp, data in components.items():
        sev_counts = data['severity_counts']

        # Health score
        deduction = sum(sev_counts[s] * health_deductions[s] for s in severity_order)
        health_score = max(0, 100 - deduction)

        # Highest severity (first non-zero in severity_order)
        highest_severity = 'Informational'
        for sev in severity_order:
            if sev_counts[sev] > 0:
                highest_severity = sev
                break

        result.append({
            'component': data['component'],
            'finding_count': data['finding_count'],
            'highest_severity': highest_severity,
            'health_score': health_score,
        })

    # Sort by health_score ascending (worst first)
    result.sort(key=lambda x: x['health_score'])

    return result


if __name__ == "__main__":
    init_db()
    print("Database initialized.")


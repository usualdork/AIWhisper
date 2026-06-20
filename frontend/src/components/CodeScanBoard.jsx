import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, ChevronDown, ChevronRight, Clipboard, Download,
  ExternalLink, FileText, Filter, GitPullRequest, Link2, Loader2,
  Lock, Package, Play, Plus, RefreshCw, Save, Search, Settings2,
  Shield, ShieldAlert, Square, Trash2, Upload, X,
} from 'lucide-react';
import { useAuth, fetchWithAuth } from '../contexts/AuthContext';

// ─── Constants ───────────────────────────────────────────────────────────────

const API_BASE = '/api/code-scan';

const SEVERITY_COLORS = {
  CRITICAL: { fg: '#fb7185', bg: 'rgba(251,113,133,0.15)', border: '#fb7185' },
  HIGH:     { fg: '#fb923c', bg: 'rgba(251,146,60,0.14)', border: '#fb923c' },
  MEDIUM:   { fg: '#facc15', bg: 'rgba(250,204,21,0.14)', border: '#facc15' },
  LOW:      { fg: '#34d399', bg: 'rgba(52,211,153,0.14)', border: '#34d399' },
};

const TABS = [
  { id: 'findings', label: 'Findings', icon: Shield },
  { id: 'sbom', label: 'SBOM', icon: Package },
  { id: 'sca', label: 'SCA', icon: ShieldAlert },
  { id: 'chains', label: 'Chains', icon: Link2 },
  { id: 'prs', label: 'PRs', icon: GitPullRequest },
  { id: 'licenses', label: 'Licenses', icon: FileText },
  { id: 'container', label: 'Container', icon: Lock },
];

const SCAN_MODULES = [
  { key: 'sast_enabled', label: 'SAST (Vulnerability Scanning)', defaultOn: true, tooltip: 'Core vulnerability detection using LLM-powered full-context analysis. ~$1.00/repo.' },
  { key: 'sca_enabled', label: 'SCA (Software Composition Analysis)', defaultOn: true, tooltip: 'CVE lookup via OSV.dev with reachability analysis. Minimal additional cost.' },
  { key: 'sbom_enabled', label: 'SBOM Generation', defaultOn: true, tooltip: 'CycloneDX 1.5 software bill of materials from lockfiles. No LLM cost.' },
  { key: 'cbom_enabled', label: 'CBOM (Cryptographic BOM)', defaultOn: true, tooltip: 'Detect weak crypto and quantum-risk patterns. ~$0.05/repo additional.' },
  { key: 'license_scan_enabled', label: 'License Compliance', defaultOn: false, tooltip: 'Classify dependency licenses by risk level. Minimal cost.' },
  { key: 'container_analysis_enabled', label: 'Container Analysis', defaultOn: false, tooltip: 'Dockerfile misconfiguration detection. ~$0.02/repo.' },
  { key: 'chain_reasoning_enabled', label: 'Cross-Repo Chain Reasoning', defaultOn: false, tooltip: 'Detect exploit chains across repos. ~$0.15/chain candidate. Multi-repo only.' },
  { key: 'auto_pr_enabled', label: 'Auto-PR (Fix Generation)', defaultOn: false, tooltip: 'Generate fix patches and open PRs. ~$0.20/finding patched.' },
];

const DEFAULT_CONFIG = Object.fromEntries(SCAN_MODULES.map(m => [m.key, m.defaultOn]));

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PR_MODES = [
  { value: 'draft', label: 'Draft PR' },
  { value: 'open', label: 'Open PR' },
  { value: 'dry_run', label: 'Dry-run (no PR)' },
];

const LICENSE_CATEGORIES = ['PERMISSIVE', 'WEAK_COPYLEFT', 'STRONG_COPYLEFT', 'COMMERCIAL', 'UNKNOWN'];
const LICENSE_COLORS = {
  PERMISSIVE: '#34d399',
  WEAK_COPYLEFT: '#facc15',
  STRONG_COPYLEFT: '#fb923c',
  COMMERCIAL: '#a78bfa',
  UNKNOWN: '#94a3b8',
};

const REPO_STATUS_COLORS = {
  QUEUED: 'text-[#8b9bb4]',
  SCANNING: 'text-yellow-300',
  COMPLETED: 'text-green-400',
  FAILED: 'text-red-400',
  SKIPPED: 'text-[#8b9bb4]',
  INTERRUPTED: 'text-orange-400',
};

const STORAGE_KEY = 'angela_codescan_config';
const TEMPLATES_KEY = 'angela_codescan_templates';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const downloadBlob = (filename, content, mime) => {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; document.body.appendChild(a);
  a.click(); a.remove(); URL.revokeObjectURL(url);
};

const estimateCost = (repoCount, config) => {
  let perRepo = 0;
  if (config.sast_enabled) perRepo += 1.0;
  if (config.sca_enabled) perRepo += 0.05;
  if (config.cbom_enabled) perRepo += 0.05;
  if (config.license_scan_enabled) perRepo += 0.02;
  if (config.container_analysis_enabled) perRepo += 0.02;
  if (config.chain_reasoning_enabled) perRepo += 0.15;
  if (config.auto_pr_enabled) perRepo += 0.20;
  const low = (repoCount * perRepo * 0.7).toFixed(2);
  const high = (repoCount * perRepo * 1.3).toFixed(2);
  return { low, high };
};


// ─── Sub-Components ──────────────────────────────────────────────────────────

const SeverityBadge = ({ severity }) => {
  const c = SEVERITY_COLORS[severity] || { fg: '#94a3b8', bg: 'rgba(148,163,184,0.14)', border: '#94a3b8' };
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-mono font-bold tracking-wider rounded border"
      style={{ color: c.fg, backgroundColor: c.bg, borderColor: c.border }}>
      {severity}
    </span>
  );
};

const StatusBadge = ({ status }) => {
  const colorClass = REPO_STATUS_COLORS[status] || 'text-[#8b9bb4]';
  return <span className={`text-[11px] font-mono font-semibold ${colorClass}`}>{status}</span>;
};

const Tooltip = ({ text, children }) => (
  <span className="relative group inline-flex">
    {children}
    <span className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-1 px-2 py-1 text-[10px] font-mono bg-[#1a1f2e] border border-[#2a3441] rounded shadow-lg text-[#c5c6c7] whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity">
      {text}
    </span>
  </span>
);

const Card = ({ title, children, className = '' }) => (
  <div className={`bg-[#0f1215] border border-[#1f2833] rounded-md p-4 ${className}`}>
    {title && <div className="text-[11px] font-mono tracking-widest text-[#45a29e] mb-3">{title}</div>}
    {children}
  </div>
);

// ─── Main Component ──────────────────────────────────────────────────────────

const CodeScanBoard = () => {
  const { isViewer, isAdmin, user } = useAuth();

  // ─── State: Scan list & selection ──────────────────────────────────────────
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');

  // ─── State: Scan form (Task 14.1) ─────────────────────────────────────────
  const [reposText, setReposText] = useState('');
  const [scanConfig, setScanConfig] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? { ...DEFAULT_CONFIG, ...JSON.parse(saved) } : { ...DEFAULT_CONFIG };
    } catch { return { ...DEFAULT_CONFIG }; }
  });
  const [autoPrMinSeverity, setAutoPrMinSeverity] = useState('HIGH');
  const [autoPrMode, setAutoPrMode] = useState('draft');
  const [autoPrBaseBranch, setAutoPrBaseBranch] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [budgetLimit, setBudgetLimit] = useState('');
  const [model, setModel] = useState('');
  const [concurrency, setConcurrency] = useState('5');
  const [diffAware, setDiffAware] = useState(false);
  const [generateLockfiles, setGenerateLockfiles] = useState(false);
  const [creatingScan, setCreatingScan] = useState(false);
  const [templates, setTemplates] = useState(() => {
    try {
      const saved = localStorage.getItem(TEMPLATES_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });
  const [templateName, setTemplateName] = useState('');
  const fileInputRef = useRef(null);

  // ─── State: Results tabs (Tasks 14.2-14.8) ────────────────────────────────
  const [activeTab, setActiveTab] = useState('findings');
  const [findings, setFindings] = useState([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsPage, setFindingsPage] = useState(1);
  const [findingTypeFilter, setFindingTypeFilter] = useState('');
  const [sbomData, setSbomData] = useState(null);
  const [scaData, setScaData] = useState([]);
  const [chainsData, setChainsData] = useState([]);
  const [prsData, setPrsData] = useState([]);
  const [licensesData, setLicensesData] = useState([]);
  const [containerData, setContainerData] = useState([]);
  const [expandedRows, setExpandedRows] = useState(new Set());

  // ─── State: Filters ────────────────────────────────────────────────────────
  const [scaSeverityFilter, setScaSeverityFilter] = useState('');
  const [scaReachFilter, setScaReachFilter] = useState('');
  const [sbomEcosystemFilter, setSbomEcosystemFilter] = useState('');

  // ─── Persist config ────────────────────────────────────────────────────────
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scanConfig));
  }, [scanConfig]);

  // ─── Data fetching ─────────────────────────────────────────────────────────
  const fetchScans = useCallback(async () => {
    try {
      const res = await fetchWithAuth(`${API_BASE}/scans`);
      if (!res.ok) throw new Error('Failed to load scans');
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.scans || [];
      setScans(list);
      if (!selectedScanId && list.length > 0) setSelectedScanId(list[0].id);
    } catch (err) { setError(err.message); }
  }, [selectedScanId]);

  const fetchScanDetails = useCallback(async (scanId) => {
    if (!scanId) return;
    try {
      const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}`);
      if (res.ok) setSelectedScan(await res.json());
    } catch { /* swallow */ }
  }, []);

  const fetchFindings = useCallback(async (scanId, page = 1, findingType = '') => {
    if (!scanId) return;
    try {
      let url = `${API_BASE}/scans/${scanId}/findings?limit=50&offset=${(page - 1) * 50}`;
      if (findingType) url += `&finding_type=${findingType}`;
      const res = await fetchWithAuth(url);
      if (res.ok) {
        const data = await res.json();
        setFindings(data.items || data.findings || []);
        setFindingsTotal(data.total || 0);
      }
    } catch { /* swallow */ }
  }, []);

  const fetchTabData = useCallback(async (scanId, tab) => {
    if (!scanId) return;
    const repos = selectedScan?.repos || [];
    const firstRepo = repos.length > 0 ? repos[0].repo_identifier || repos[0].repo || '' : '';
    try {
      switch (tab) {
        case 'sbom': {
          if (!firstRepo) { setSbomData(null); return; }
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/sbom/${encodeURIComponent(firstRepo)}`);
          if (res.ok) setSbomData(await res.json());
          break;
        }
        case 'sca': {
          if (!firstRepo) { setScaData([]); return; }
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/sca/${encodeURIComponent(firstRepo)}`);
          if (res.ok) {
            const data = await res.json();
            setScaData(Array.isArray(data) ? data : data.cves || []);
          }
          break;
        }
        case 'chains': {
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/chains`);
          if (res.ok) {
            const data = await res.json();
            setChainsData(Array.isArray(data) ? data : data.chains || []);
          }
          break;
        }
        case 'prs': {
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/prs`);
          if (res.ok) {
            const data = await res.json();
            setPrsData(Array.isArray(data) ? data : data.prs || []);
          }
          break;
        }
        case 'licenses': {
          if (!firstRepo) { setLicensesData([]); return; }
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/licenses/${encodeURIComponent(firstRepo)}`);
          if (res.ok) {
            const data = await res.json();
            setLicensesData(Array.isArray(data) ? data : data.licenses || []);
          }
          break;
        }
        case 'container': {
          if (!firstRepo) { setContainerData([]); return; }
          const res = await fetchWithAuth(`${API_BASE}/scans/${scanId}/container/${encodeURIComponent(firstRepo)}`);
          if (res.ok) {
            const data = await res.json();
            setContainerData(Array.isArray(data) ? data : data.findings || []);
          }
          break;
        }
        default: break;
      }
    } catch { /* swallow */ }
  }, [selectedScan]);

  // ─── Effects ───────────────────────────────────────────────────────────────
  useEffect(() => { fetchScans(); }, []);
  useEffect(() => { if (selectedScanId) fetchScanDetails(selectedScanId); }, [selectedScanId]);
  useEffect(() => { if (selectedScanId) fetchFindings(selectedScanId, findingsPage, findingTypeFilter); }, [selectedScanId, findingsPage, findingTypeFilter]);
  useEffect(() => { if (selectedScanId && activeTab !== 'findings') fetchTabData(selectedScanId, activeTab); }, [selectedScanId, activeTab]);

  // Auto-refresh for active scans
  const hasActiveScan = useMemo(() => scans.some(s =>
    ['CREATED', 'INGESTING', 'SCANNING', 'ENRICHING', 'CHAINING', 'PATCHING', 'REPORTING'].includes(s.scan_phase || s.status)
  ), [scans]);

  useEffect(() => {
    const interval = setInterval(() => {
      fetchScans();
      if (selectedScanId && hasActiveScan) fetchScanDetails(selectedScanId);
    }, hasActiveScan ? 5000 : 20000);
    return () => clearInterval(interval);
  }, [fetchScans, fetchScanDetails, hasActiveScan, selectedScanId]);


  // ─── Handlers ────────────────────────────────────────────────────────────────

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target.result;
      const repos = text.split('\n').map(s => s.trim()).filter(Boolean);
      setReposText(prev => {
        const existing = prev.split('\n').map(s => s.trim()).filter(Boolean);
        return [...new Set([...existing, ...repos])].join('\n');
      });
      setInfo(`Loaded ${repos.length} repo(s) from file`);
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      const repos = text.split('\n').map(s => s.trim()).filter(Boolean);
      setReposText(prev => {
        const existing = prev.split('\n').map(s => s.trim()).filter(Boolean);
        return [...new Set([...existing, ...repos])].join('\n');
      });
      setInfo(`Pasted ${repos.length} line(s) from clipboard`);
    } catch {
      setError('Clipboard access denied');
    }
  };

  const handleStartScan = async (e) => {
    e.preventDefault();
    const repos = reposText.split('\n').map(s => s.trim()).filter(Boolean);
    if (!repos.length) { setError('Add at least one repository'); return; }
    setCreatingScan(true);
    setError('');
    try {
      const body = {
        repos,
        ...scanConfig,
        auto_pr_min_severity: autoPrMinSeverity,
        auto_pr_mode: autoPrMode,
        auto_pr_base_branch: autoPrBaseBranch || null,
        model: model || null,
        budget_limit_usd: budgetLimit ? parseFloat(budgetLimit) : null,
        concurrency: concurrency ? parseInt(concurrency, 10) : null,
        diff_aware: diffAware,
        generate_lockfiles: generateLockfiles,
      };
      const res = await fetchWithAuth(`${API_BASE}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || 'Failed to start scan');
      }
      const data = await res.json();
      setReposText('');
      setInfo('Scan started');
      await fetchScans();
      if (data.id || data.scan_id) setSelectedScanId(data.id || data.scan_id);
    } catch (err) { setError(err.message); } finally { setCreatingScan(false); }
  };

  const handleStopScan = async (scanId) => {
    try {
      await fetchWithAuth(`${API_BASE}/scans/${scanId}/stop`, { method: 'POST' });
      await fetchScans();
      if (scanId === selectedScanId) await fetchScanDetails(scanId);
    } catch { setError('Failed to stop scan'); }
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await fetchWithAuth(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
      if (scanId === selectedScanId) { setSelectedScanId(null); setSelectedScan(null); }
      await fetchScans();
    } catch { setError('Failed to delete scan'); }
  };

  const handleExport = async (format) => {
    if (!selectedScanId) return;
    try {
      const res = await fetchWithAuth(`${API_BASE}/scans/${selectedScanId}/export?format=${format}`);
      if (!res.ok) throw new Error('Export failed');
      const ext = { json: 'json', sarif: 'sarif', markdown: 'md', html: 'html' }[format] || format;
      const mime = { json: 'application/json', sarif: 'application/sarif+json', markdown: 'text/markdown', html: 'text/html' }[format] || 'text/plain';
      const text = await res.text();
      downloadBlob(`scan_${selectedScanId.slice(0, 8)}.${ext}`, text, mime);
    } catch (err) { setError(err.message); }
  };

  const handleSaveTemplate = () => {
    if (!templateName.trim()) return;
    const tpl = {
      name: templateName.trim(),
      config: { ...scanConfig },
      autoPrMinSeverity, autoPrMode, autoPrBaseBranch,
      budgetLimit, model, concurrency, diffAware, generateLockfiles,
    };
    const updated = [...templates.filter(t => t.name !== tpl.name), tpl];
    setTemplates(updated);
    localStorage.setItem(TEMPLATES_KEY, JSON.stringify(updated));
    setTemplateName('');
    setInfo(`Template "${tpl.name}" saved`);
  };

  const handleLoadTemplate = (name) => {
    const tpl = templates.find(t => t.name === name);
    if (!tpl) return;
    setScanConfig(tpl.config || { ...DEFAULT_CONFIG });
    setAutoPrMinSeverity(tpl.autoPrMinSeverity || 'HIGH');
    setAutoPrMode(tpl.autoPrMode || 'draft');
    setAutoPrBaseBranch(tpl.autoPrBaseBranch || '');
    setBudgetLimit(tpl.budgetLimit || '');
    setModel(tpl.model || '');
    setConcurrency(tpl.concurrency || '5');
    setDiffAware(tpl.diffAware || false);
    setGenerateLockfiles(tpl.generateLockfiles || false);
    setInfo(`Loaded template "${name}"`);
  };

  const toggleExpanded = (id) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // ─── Derived ───────────────────────────────────────────────────────────────
  const repoCount = useMemo(() => reposText.split('\n').map(s => s.trim()).filter(Boolean).length, [reposText]);
  const costEstimate = useMemo(() => estimateCost(repoCount, scanConfig), [repoCount, scanConfig]);

  const filteredSca = useMemo(() => scaData.filter(c => {
    if (scaSeverityFilter && c.severity !== scaSeverityFilter) return false;
    if (scaReachFilter && c.reachability !== scaReachFilter) return false;
    return true;
  }), [scaData, scaSeverityFilter, scaReachFilter]);

  const sbomComponents = useMemo(() => {
    if (!sbomData) return [];
    const comps = sbomData.components || [];
    if (!sbomEcosystemFilter) return comps;
    return comps.filter(c => (c.ecosystem || c.type || '').toLowerCase() === sbomEcosystemFilter.toLowerCase());
  }, [sbomData, sbomEcosystemFilter]);

  const licenseSummary = useMemo(() => {
    const counts = {};
    LICENSE_CATEGORIES.forEach(cat => { counts[cat] = []; });
    licensesData.forEach(lic => {
      const cat = lic.license_category || 'UNKNOWN';
      if (counts[cat]) counts[cat].push(lic);
      else counts['UNKNOWN'].push(lic);
    });
    return counts;
  }, [licensesData]);

  const containerByRepo = useMemo(() => {
    const grouped = {};
    containerData.forEach(f => {
      const repo = f.repo_identifier || 'unknown';
      if (!grouped[repo]) grouped[repo] = [];
      grouped[repo].push(f);
    });
    return grouped;
  }, [containerData]);


  // ─── Render: Pre-Scan Config Panel (Task 14.1) ─────────────────────────────

  const renderScanForm = () => {
    if (isViewer) return null;
    return (
      <Card title="NEW SCAN" className="mb-4">
        <form onSubmit={handleStartScan}>
          {/* Repository Input */}
          <div className="mb-4">
            <label className="block text-[11px] font-mono text-[#8b9bb4] mb-1">
              Repositories (one per line: owner/repo or https://github.com/owner/repo)
            </label>
            <textarea
              className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-3 py-2 text-sm font-mono text-[#c5c6c7] placeholder-[#5d6b7a] focus:border-[#45a29e] focus:outline-none resize-y"
              rows={4}
              placeholder={"owner/repo\nhttps://github.com/org/another-repo"}
              value={reposText}
              onChange={(e) => setReposText(e.target.value)}
            />
            <div className="flex gap-2 mt-1">
              <button type="button" onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-[#45a29e] border border-[#1f2833] rounded hover:bg-[#1f2833] transition">
                <Upload size={12} /> Upload .txt
              </button>
              <button type="button" onClick={handlePasteClipboard}
                className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-[#45a29e] border border-[#1f2833] rounded hover:bg-[#1f2833] transition">
                <Clipboard size={12} /> Paste
              </button>
              <input ref={fileInputRef} type="file" accept=".txt" className="hidden" onChange={handleFileUpload} />
              {repoCount > 0 && (
                <span className="text-[10px] font-mono text-[#5d6b7a] self-center ml-auto">
                  {repoCount} repo{repoCount !== 1 ? 's' : ''} · est. ${costEstimate.low}–${costEstimate.high}
                </span>
              )}
            </div>
          </div>

          {/* Scan Modules */}
          <div className="mb-4">
            <div className="text-[11px] font-mono text-[#8b9bb4] mb-2">Scan Modules</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {SCAN_MODULES.map(mod => (
                <Tooltip key={mod.key} text={mod.tooltip}>
                  <label className="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-[#1a1f2e] transition w-full">
                    <input
                      type="checkbox"
                      checked={!!scanConfig[mod.key]}
                      onChange={(e) => setScanConfig(prev => ({ ...prev, [mod.key]: e.target.checked }))}
                      className="accent-[#45a29e]"
                    />
                    <span className="text-[11px] font-mono text-[#c5c6c7]">{mod.label}</span>
                  </label>
                </Tooltip>
              ))}
            </div>
          </div>

          {/* Auto-PR Sub-Options */}
          {scanConfig.auto_pr_enabled && (
            <div className="mb-4 ml-4 pl-3 border-l border-[#1f2833]">
              <div className="text-[10px] font-mono text-[#5d6b7a] mb-2">AUTO-PR OPTIONS</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">Min Severity</label>
                  <select value={autoPrMinSeverity} onChange={(e) => setAutoPrMinSeverity(e.target.value)}
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-xs font-mono text-[#c5c6c7] focus:border-[#45a29e] focus:outline-none">
                    {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">PR Mode</label>
                  <div className="flex flex-col gap-1">
                    {PR_MODES.map(m => (
                      <label key={m.value} className="flex items-center gap-1.5 text-[10px] font-mono text-[#c5c6c7] cursor-pointer">
                        <input type="radio" name="pr_mode" value={m.value} checked={autoPrMode === m.value}
                          onChange={(e) => setAutoPrMode(e.target.value)} className="accent-[#45a29e]" />
                        {m.label}
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">Target Branch</label>
                  <input type="text" value={autoPrBaseBranch} onChange={(e) => setAutoPrBaseBranch(e.target.value)}
                    placeholder="default branch"
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-xs font-mono text-[#c5c6c7] placeholder-[#5d6b7a] focus:border-[#45a29e] focus:outline-none" />
                </div>
              </div>
            </div>
          )}

          {/* Advanced Options */}
          <div className="mb-4">
            <button type="button" onClick={() => setAdvancedOpen(!advancedOpen)}
              className="flex items-center gap-1 text-[11px] font-mono text-[#45a29e] hover:text-[#66fcf1] transition">
              {advancedOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Advanced Options
            </button>
            {advancedOpen && (
              <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-3 pl-4 border-l border-[#1f2833]">
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">Budget Limit (USD)</label>
                  <input type="number" step="0.01" min="2" value={budgetLimit} onChange={(e) => setBudgetLimit(e.target.value)}
                    placeholder="50.00"
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-xs font-mono text-[#c5c6c7] placeholder-[#5d6b7a] focus:border-[#45a29e] focus:outline-none" />
                </div>
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">Model</label>
                  <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
                    placeholder="claude-opus-4-7"
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-xs font-mono text-[#c5c6c7] placeholder-[#5d6b7a] focus:border-[#45a29e] focus:outline-none" />
                </div>
                <div>
                  <label className="block text-[10px] font-mono text-[#8b9bb4] mb-1">Concurrency (1-20)</label>
                  <input type="number" min="1" max="20" value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-xs font-mono text-[#c5c6c7] focus:border-[#45a29e] focus:outline-none" />
                </div>
                <label className="flex items-center gap-2 text-[11px] font-mono text-[#c5c6c7] cursor-pointer">
                  <input type="checkbox" checked={diffAware} onChange={(e) => setDiffAware(e.target.checked)} className="accent-[#45a29e]" />
                  Diff-aware (skip unchanged)
                </label>
                <label className="flex items-center gap-2 text-[11px] font-mono text-[#c5c6c7] cursor-pointer">
                  <input type="checkbox" checked={generateLockfiles} onChange={(e) => setGenerateLockfiles(e.target.checked)} className="accent-[#45a29e]" />
                  Generate lockfiles
                </label>
              </div>
            )}
          </div>

          {/* Templates */}
          <div className="mb-4 flex items-center gap-2 flex-wrap">
            {templates.length > 0 && (
              <select onChange={(e) => e.target.value && handleLoadTemplate(e.target.value)} defaultValue=""
                className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] focus:border-[#45a29e] focus:outline-none">
                <option value="">Load template…</option>
                {templates.map(t => <option key={t.name} value={t.name}>{t.name}</option>)}
              </select>
            )}
            <input type="text" value={templateName} onChange={(e) => setTemplateName(e.target.value)}
              placeholder="Template name"
              className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] placeholder-[#5d6b7a] focus:border-[#45a29e] focus:outline-none" />
            <button type="button" onClick={handleSaveTemplate} disabled={!templateName.trim()}
              className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-[#45a29e] border border-[#1f2833] rounded hover:bg-[#1f2833] transition disabled:opacity-40">
              <Save size={12} /> Save Template
            </button>
          </div>

          {/* Submit */}
          <button type="submit" disabled={creatingScan || repoCount === 0}
            className="flex items-center gap-2 px-4 py-2 bg-[#45a29e] text-[#0b0c10] font-mono text-xs font-bold rounded hover:bg-[#66fcf1] transition disabled:opacity-40">
            {creatingScan ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Start Scan
          </button>
        </form>
      </Card>
    );
  };

  // ─── Render: Per-repo progress badges (Task 14.1) ──────────────────────────

  const renderRepoProgress = () => {
    if (!selectedScan?.repos?.length) return null;
    return (
      <div className="mb-4 flex flex-wrap gap-2">
        {selectedScan.repos.map((r, i) => (
          <div key={i} className="flex items-center gap-1.5 px-2 py-1 bg-[#0b0c10] border border-[#1f2833] rounded text-[10px] font-mono">
            <StatusBadge status={r.status} />
            <span className="text-[#c5c6c7] truncate max-w-[140px]">{r.repo_identifier || r.repo}</span>
          </div>
        ))}
      </div>
    );
  };


  // ─── Render: Tab Navigation (Task 14.2) ────────────────────────────────────

  const renderTabs = () => (
    <div className="flex items-center gap-1 mb-4 border-b border-[#1f2833] pb-2 overflow-x-auto">
      {TABS.map(tab => {
        const Icon = tab.icon;
        const active = activeTab === tab.id;
        return (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono rounded-t transition whitespace-nowrap
              ${active ? 'bg-[#1f2833] text-[#66fcf1] border-b-2 border-[#66fcf1]' : 'text-[#8b9bb4] hover:text-[#c5c6c7] hover:bg-[#0f1215]'}`}>
            <Icon size={13} />
            {tab.label}
          </button>
        );
      })}
      {/* Export buttons */}
      <div className="ml-auto flex gap-1">
        {['json', 'sarif', 'markdown', 'html'].map(fmt => (
          <button key={fmt} onClick={() => handleExport(fmt)}
            className="px-2 py-1 text-[9px] font-mono text-[#8b9bb4] border border-[#1f2833] rounded hover:text-[#45a29e] hover:border-[#45a29e] transition uppercase">
            {fmt}
          </button>
        ))}
      </div>
    </div>
  );

  // ─── Render: Findings Tab (Task 14.2) ──────────────────────────────────────

  const renderFindingsTab = () => (
    <div>
      {/* Filter */}
      <div className="flex items-center gap-2 mb-3">
        <Filter size={13} className="text-[#5d6b7a]" />
        <select value={findingTypeFilter} onChange={(e) => { setFindingTypeFilter(e.target.value); setFindingsPage(1); }}
          className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] focus:outline-none">
          <option value="">All types</option>
          <option value="sast">SAST</option>
          <option value="sca">SCA</option>
          <option value="cbom">CBOM</option>
          <option value="container">Container</option>
          <option value="chain">Chain</option>
        </select>
        <span className="text-[10px] font-mono text-[#5d6b7a] ml-auto">{findingsTotal} total</span>
      </div>
      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono">
          <thead>
            <tr className="border-b border-[#1f2833] text-[#5d6b7a] text-left">
              <th className="py-1.5 px-2">Type</th>
              <th className="py-1.5 px-2">Severity</th>
              <th className="py-1.5 px-2">Title</th>
              <th className="py-1.5 px-2">File</th>
              <th className="py-1.5 px-2">Repo</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={f.id || i} className="border-b border-[#0f1215] hover:bg-[#1a1f2e] text-[#c5c6c7]">
                <td className="py-1.5 px-2"><span className="text-[#45a29e]">{f.finding_type || 'sast'}</span></td>
                <td className="py-1.5 px-2"><SeverityBadge severity={f.severity} /></td>
                <td className="py-1.5 px-2 max-w-[300px] truncate">{f.title}</td>
                <td className="py-1.5 px-2 text-[#8b9bb4] max-w-[200px] truncate">{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</td>
                <td className="py-1.5 px-2 text-[#8b9bb4] max-w-[140px] truncate">{f.repo_identifier}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={5} className="py-6 text-center text-[#5d6b7a]">No findings</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {/* Pagination */}
      {findingsTotal > 50 && (
        <div className="flex items-center justify-center gap-2 mt-3">
          <button disabled={findingsPage <= 1} onClick={() => setFindingsPage(p => p - 1)}
            className="px-2 py-1 text-[10px] font-mono text-[#8b9bb4] border border-[#1f2833] rounded disabled:opacity-30 hover:text-[#45a29e]">Prev</button>
          <span className="text-[10px] font-mono text-[#5d6b7a]">Page {findingsPage} of {Math.ceil(findingsTotal / 50)}</span>
          <button disabled={findingsPage >= Math.ceil(findingsTotal / 50)} onClick={() => setFindingsPage(p => p + 1)}
            className="px-2 py-1 text-[10px] font-mono text-[#8b9bb4] border border-[#1f2833] rounded disabled:opacity-30 hover:text-[#45a29e]">Next</button>
        </div>
      )}
    </div>
  );

  // ─── Render: SBOM Tab (Task 14.3) ─────────────────────────────────────────

  const renderSbomTab = () => {
    const ecosystems = [...new Set((sbomData?.components || []).map(c => c.ecosystem || c.type || 'unknown'))];
    return (
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Filter size={13} className="text-[#5d6b7a]" />
          <select value={sbomEcosystemFilter} onChange={(e) => setSbomEcosystemFilter(e.target.value)}
            className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] focus:outline-none">
            <option value="">All ecosystems</option>
            {ecosystems.map(e => <option key={e} value={e}>{e}</option>)}
          </select>
          <span className="text-[10px] font-mono text-[#5d6b7a] ml-auto">{sbomComponents.length} components</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr className="border-b border-[#1f2833] text-[#5d6b7a] text-left">
                <th className="py-1.5 px-2"></th>
                <th className="py-1.5 px-2">Name</th>
                <th className="py-1.5 px-2">Version</th>
                <th className="py-1.5 px-2">Ecosystem</th>
                <th className="py-1.5 px-2">License</th>
                <th className="py-1.5 px-2">CVEs</th>
              </tr>
            </thead>
            <tbody>
              {sbomComponents.map((comp, i) => {
                const id = comp.purl || `${comp.name}-${i}`;
                const expanded = expandedRows.has(id);
                return (
                  <React.Fragment key={id}>
                    <tr className="border-b border-[#0f1215] hover:bg-[#1a1f2e] text-[#c5c6c7] cursor-pointer" onClick={() => toggleExpanded(id)}>
                      <td className="py-1.5 px-2">{expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</td>
                      <td className="py-1.5 px-2">{comp.name}</td>
                      <td className="py-1.5 px-2 text-[#8b9bb4]">{comp.version}</td>
                      <td className="py-1.5 px-2 text-[#8b9bb4]">{comp.ecosystem || comp.type}</td>
                      <td className="py-1.5 px-2 text-[#8b9bb4]">{comp.license || '-'}</td>
                      <td className="py-1.5 px-2 text-[#8b9bb4]">{comp.cve_count || 0}</td>
                    </tr>
                    {expanded && (
                      <tr className="bg-[#0b0c10]">
                        <td colSpan={6} className="px-6 py-2 text-[10px] text-[#8b9bb4]">
                          {comp.cves?.length > 0 ? (
                            <div className="space-y-1">
                              {comp.cves.map((cve, ci) => (
                                <div key={ci} className="flex gap-3">
                                  <span className="text-[#fb923c]">{cve.cve_id || cve.id}</span>
                                  <SeverityBadge severity={cve.severity} />
                                  <span>{cve.fix_version ? `Fix: ${cve.fix_version}` : 'No fix available'}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <span>No associated CVEs. License: {comp.license_details || comp.license || 'Unknown'}</span>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {sbomComponents.length === 0 && (
                <tr><td colSpan={6} className="py-6 text-center text-[#5d6b7a]">No SBOM data available</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  };


  // ─── Render: SCA Tab (Task 14.4) ──────────────────────────────────────────

  const renderScaTab = () => (
    <div>
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <Filter size={13} className="text-[#5d6b7a]" />
        <select value={scaSeverityFilter} onChange={(e) => setScaSeverityFilter(e.target.value)}
          className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] focus:outline-none">
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={scaReachFilter} onChange={(e) => setScaReachFilter(e.target.value)}
          className="bg-[#0b0c10] border border-[#1f2833] rounded px-2 py-1 text-[10px] font-mono text-[#c5c6c7] focus:outline-none">
          <option value="">All reachability</option>
          <option value="REACHABLE">Reachable</option>
          <option value="UNREACHABLE">Unreachable</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
        <span className="text-[10px] font-mono text-[#5d6b7a] ml-auto">{filteredSca.length} CVEs</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono">
          <thead>
            <tr className="border-b border-[#1f2833] text-[#5d6b7a] text-left">
              <th className="py-1.5 px-2">CVE ID</th>
              <th className="py-1.5 px-2">Package</th>
              <th className="py-1.5 px-2">Severity</th>
              <th className="py-1.5 px-2">CVSS</th>
              <th className="py-1.5 px-2">Reachability</th>
              <th className="py-1.5 px-2">Fix Version</th>
            </tr>
          </thead>
          <tbody>
            {filteredSca.map((cve, i) => (
              <tr key={cve.id || i}
                className={`border-b border-[#0f1215] text-[#c5c6c7] ${cve.reachability === 'REACHABLE' ? 'bg-[#1a0f0f] hover:bg-[#2a1515]' : 'hover:bg-[#1a1f2e]'}`}>
                <td className="py-1.5 px-2 text-[#45a29e]">{cve.cve_id}</td>
                <td className="py-1.5 px-2">
                  {cve.package_name}
                  <span className="text-[#5d6b7a] ml-1">@{cve.package_version}</span>
                </td>
                <td className="py-1.5 px-2"><SeverityBadge severity={cve.severity} /></td>
                <td className="py-1.5 px-2 text-[#8b9bb4]">{cve.cvss_score ?? '-'}</td>
                <td className="py-1.5 px-2">
                  <span className={`font-semibold ${cve.reachability === 'REACHABLE' ? 'text-[#fb7185]' : cve.reachability === 'UNREACHABLE' ? 'text-[#34d399]' : 'text-[#8b9bb4]'}`}>
                    {cve.reachability}
                  </span>
                </td>
                <td className="py-1.5 px-2 text-[#8b9bb4]">{cve.fix_version || '-'}</td>
              </tr>
            ))}
            {filteredSca.length === 0 && (
              <tr><td colSpan={6} className="py-6 text-center text-[#5d6b7a]">No SCA data available</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );

  // ─── Render: Chains Tab (Task 14.5) ───────────────────────────────────────

  const renderChainsTab = () => (
    <div className="space-y-3">
      {chainsData.length === 0 && (
        <div className="py-6 text-center text-[11px] font-mono text-[#5d6b7a]">No exploit chains detected</div>
      )}
      {chainsData.map((chain, ci) => {
        const steps = chain.steps || (chain.chain_json ? JSON.parse(chain.chain_json).steps : []) || [];
        const sevColor = SEVERITY_COLORS[chain.severity] || SEVERITY_COLORS.MEDIUM;
        return (
          <div key={chain.id || ci} className="border border-[#1f2833] rounded-md p-3 bg-[#0b0c10]">
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={chain.severity} />
              <span className="text-[11px] font-mono text-[#c5c6c7]">
                Chain #{ci + 1} · {chain.step_count || steps.length} steps · confidence {((chain.confidence_score || 0) * 100).toFixed(0)}%
              </span>
              {chain.affected_repos && (
                <span className="text-[10px] font-mono text-[#5d6b7a] ml-auto">
                  {(typeof chain.affected_repos === 'string' ? JSON.parse(chain.affected_repos) : chain.affected_repos).join(', ')}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1 flex-wrap">
              {steps.map((step, si) => (
                <React.Fragment key={si}>
                  <div className="px-2 py-1 rounded text-[10px] font-mono border cursor-pointer hover:opacity-80 transition"
                    style={{ borderColor: sevColor.border, backgroundColor: sevColor.bg, color: sevColor.fg }}
                    title={step.description || step.finding_ref || ''}>
                    <div className="font-semibold">{step.repo || step.repo_identifier || '?'}</div>
                    <div className="text-[9px] opacity-80 truncate max-w-[160px]">{step.title || step.finding_ref || `Step ${si + 1}`}</div>
                  </div>
                  {si < steps.length - 1 && (
                    <span className="text-[#5d6b7a] text-lg">→</span>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );

  // ─── Render: PRs Tab (Task 14.6) ──────────────────────────────────────────

  const renderPrsTab = () => {
    const prStatusColor = (status) => {
      switch ((status || '').toUpperCase()) {
        case 'MERGED': return 'text-[#a78bfa] bg-[#a78bfa]/10 border-[#a78bfa]/40';
        case 'OPEN': return 'text-[#34d399] bg-[#34d399]/10 border-[#34d399]/40';
        case 'DRAFT': return 'text-[#8b9bb4] bg-[#8b9bb4]/10 border-[#8b9bb4]/40';
        case 'CLOSED': return 'text-[#fb7185] bg-[#fb7185]/10 border-[#fb7185]/40';
        case 'FAILED': return 'text-[#fb923c] bg-[#fb923c]/10 border-[#fb923c]/40';
        default: return 'text-[#5d6b7a] bg-[#5d6b7a]/10 border-[#5d6b7a]/40';
      }
    };
    return (
      <div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr className="border-b border-[#1f2833] text-[#5d6b7a] text-left">
                <th className="py-1.5 px-2">Repo</th>
                <th className="py-1.5 px-2">PR URL</th>
                <th className="py-1.5 px-2">Status</th>
                <th className="py-1.5 px-2">Findings</th>
              </tr>
            </thead>
            <tbody>
              {prsData.map((pr, i) => {
                const findingsAddressed = typeof pr.findings_addressed === 'string' ? JSON.parse(pr.findings_addressed) : (pr.findings_addressed || []);
                return (
                  <tr key={pr.id || i} className="border-b border-[#0f1215] hover:bg-[#1a1f2e] text-[#c5c6c7]">
                    <td className="py-1.5 px-2">{pr.repo_identifier}</td>
                    <td className="py-1.5 px-2">
                      {pr.pr_url ? (
                        <a href={pr.pr_url} target="_blank" rel="noopener noreferrer" className="text-[#45a29e] hover:underline flex items-center gap-1">
                          {pr.pr_url.split('/').slice(-1)[0]} <ExternalLink size={10} />
                        </a>
                      ) : '-'}
                    </td>
                    <td className="py-1.5 px-2">
                      <span className={`inline-flex px-1.5 py-0.5 text-[9px] font-bold rounded border ${prStatusColor(pr.pr_status)}`}>
                        {pr.pr_status}
                      </span>
                    </td>
                    <td className="py-1.5 px-2 text-[#8b9bb4]">{findingsAddressed.length}</td>
                  </tr>
                );
              })}
              {prsData.length === 0 && (
                <tr><td colSpan={4} className="py-6 text-center text-[#5d6b7a]">No PRs generated</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <button onClick={() => fetchTabData(selectedScanId, 'prs')}
          className="mt-2 flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-[#45a29e] border border-[#1f2833] rounded hover:bg-[#1f2833] transition">
          <RefreshCw size={11} /> Refresh
        </button>
      </div>
    );
  };


  // ─── Render: Licenses Tab (Task 14.7) ──────────────────────────────────────

  const renderLicensesTab = () => (
    <div className="space-y-3">
      {/* Category summary */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-4">
        {LICENSE_CATEGORIES.map(cat => {
          const items = licenseSummary[cat] || [];
          const isWarning = cat === 'STRONG_COPYLEFT' || cat === 'UNKNOWN';
          return (
            <div key={cat}
              className={`px-3 py-2 rounded border cursor-pointer hover:opacity-80 transition ${expandedRows.has(`lic-${cat}`) ? 'border-[#45a29e]' : 'border-[#1f2833]'}`}
              style={{ backgroundColor: `${LICENSE_COLORS[cat]}10` }}
              onClick={() => toggleExpanded(`lic-${cat}`)}>
              <div className="flex items-center gap-1">
                <span className="text-[10px] font-mono font-semibold" style={{ color: LICENSE_COLORS[cat] }}>{cat.replace('_', ' ')}</span>
                {isWarning && items.length > 0 && <AlertTriangle size={11} className="text-[#fb923c]" />}
              </div>
              <div className="text-lg font-mono font-bold text-[#c5c6c7] mt-0.5">{items.length}</div>
            </div>
          );
        })}
      </div>
      {/* Expanded details */}
      {LICENSE_CATEGORIES.map(cat => {
        if (!expandedRows.has(`lic-${cat}`)) return null;
        const items = licenseSummary[cat] || [];
        if (items.length === 0) return null;
        return (
          <div key={cat} className="border border-[#1f2833] rounded-md p-3 bg-[#0b0c10]">
            <div className="text-[11px] font-mono font-semibold mb-2" style={{ color: LICENSE_COLORS[cat] }}>
              {cat.replace('_', ' ')} ({items.length})
            </div>
            <table className="w-full text-[10px] font-mono">
              <thead>
                <tr className="border-b border-[#1f2833] text-[#5d6b7a]">
                  <th className="py-1 px-2 text-left">Package</th>
                  <th className="py-1 px-2 text-left">Version</th>
                  <th className="py-1 px-2 text-left">Ecosystem</th>
                  <th className="py-1 px-2 text-left">License</th>
                  <th className="py-1 px-2 text-left">Review</th>
                </tr>
              </thead>
              <tbody>
                {items.map((lic, i) => (
                  <tr key={i} className="border-b border-[#0f1215] text-[#c5c6c7]">
                    <td className="py-1 px-2">{lic.package_name}</td>
                    <td className="py-1 px-2 text-[#8b9bb4]">{lic.package_version}</td>
                    <td className="py-1 px-2 text-[#8b9bb4]">{lic.ecosystem}</td>
                    <td className="py-1 px-2 text-[#8b9bb4]">{lic.license_id || '-'}</td>
                    <td className="py-1 px-2">{lic.requires_review ? <AlertTriangle size={11} className="text-[#fb923c]" /> : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
      {licensesData.length === 0 && (
        <div className="py-6 text-center text-[11px] font-mono text-[#5d6b7a]">No license data available</div>
      )}
    </div>
  );

  // ─── Render: Container Tab (Task 14.8) ─────────────────────────────────────

  const renderContainerTab = () => {
    const repos = Object.keys(containerByRepo);
    return (
      <div className="space-y-3">
        {repos.length === 0 && containerData.length === 0 && (
          <div className="py-6 text-center text-[11px] font-mono text-[#5d6b7a]">No container findings</div>
        )}
        {repos.map(repo => (
          <div key={repo} className="border border-[#1f2833] rounded-md p-3 bg-[#0b0c10]">
            <div className="text-[11px] font-mono font-semibold text-[#45a29e] mb-2">{repo}</div>
            <table className="w-full text-[10px] font-mono">
              <thead>
                <tr className="border-b border-[#1f2833] text-[#5d6b7a]">
                  <th className="py-1 px-2 text-left">File</th>
                  <th className="py-1 px-2 text-left">Type</th>
                  <th className="py-1 px-2 text-left">Severity</th>
                  <th className="py-1 px-2 text-left">Description</th>
                  <th className="py-1 px-2 text-left">Fix</th>
                </tr>
              </thead>
              <tbody>
                {containerByRepo[repo].map((f, i) => (
                  <tr key={i} className="border-b border-[#0f1215] text-[#c5c6c7]">
                    <td className="py-1 px-2 text-[#8b9bb4]">{f.dockerfile_path}</td>
                    <td className="py-1 px-2">{f.misconfiguration_type}</td>
                    <td className="py-1 px-2"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-1 px-2 max-w-[250px] truncate">{f.description}</td>
                    <td className="py-1 px-2 text-[#8b9bb4] max-w-[200px] truncate">{f.recommended_fix || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    );
  };

  // ─── Render: Scan List Sidebar ─────────────────────────────────────────────

  const renderScanList = () => (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-mono tracking-widest text-[#45a29e]">SCANS</span>
        <button onClick={fetchScans} className="p-1 text-[#5d6b7a] hover:text-[#45a29e] transition">
          <RefreshCw size={12} />
        </button>
      </div>
      <div className="space-y-1 max-h-[200px] overflow-y-auto">
        {scans.map(scan => (
          <div key={scan.id}
            onClick={() => setSelectedScanId(scan.id)}
            className={`flex items-center justify-between px-2 py-1.5 rounded cursor-pointer text-[11px] font-mono transition
              ${selectedScanId === scan.id ? 'bg-[#1f2833] text-[#66fcf1]' : 'text-[#8b9bb4] hover:bg-[#0f1215]'}`}>
            <div className="flex items-center gap-2 truncate">
              <StatusBadge status={scan.scan_phase || scan.status} />
              <span className="truncate">{scan.id?.slice(0, 8)}</span>
            </div>
            <div className="flex items-center gap-1">
              {['INGESTING', 'SCANNING', 'ENRICHING', 'CHAINING', 'PATCHING', 'REPORTING', 'CREATED'].includes(scan.scan_phase || scan.status) && !isViewer && (
                <button onClick={(e) => { e.stopPropagation(); handleStopScan(scan.id); }}
                  className="p-0.5 text-[#fb923c] hover:text-[#fb7185]" title="Stop">
                  <Square size={10} />
                </button>
              )}
              {isAdmin && (
                <button onClick={(e) => { e.stopPropagation(); handleDeleteScan(scan.id); }}
                  className="p-0.5 text-[#5d6b7a] hover:text-[#fb7185]" title="Delete">
                  <Trash2 size={10} />
                </button>
              )}
            </div>
          </div>
        ))}
        {scans.length === 0 && (
          <div className="text-[10px] font-mono text-[#5d6b7a] text-center py-2">No scans yet</div>
        )}
      </div>
    </div>
  );


  // ─── Render: Main Layout ───────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#0b0c10] text-[#c5c6c7] p-4 sm:p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-mono font-bold text-[#c5c6c7] tracking-wide">Code Scanner</h1>
          <p className="text-[10px] font-mono text-[#5d6b7a]">Holistic multi-repo security analysis</p>
        </div>
      </div>

      {/* Error/Info banners */}
      {error && (
        <div className="mb-4 px-3 py-2 bg-[#2a1317] border border-[#fb7185]/40 rounded text-[11px] font-mono text-[#fca5a5] flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError('')} className="ml-2 text-[#fb7185] hover:text-white"><X size={12} /></button>
        </div>
      )}
      {info && (
        <div className="mb-4 px-3 py-2 bg-[#0f2922] border border-[#34d399]/40 rounded text-[11px] font-mono text-[#86efac] flex items-center justify-between">
          <span>{info}</span>
          <button onClick={() => setInfo('')} className="ml-2 text-[#34d399] hover:text-white"><X size={12} /></button>
        </div>
      )}

      {/* Scan form (hidden for Viewer) */}
      {renderScanForm()}

      {/* Scan list */}
      {renderScanList()}

      {/* Selected scan details */}
      {selectedScan && (
        <Card className="mb-4">
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <span className="text-[11px] font-mono text-[#45a29e] font-semibold">
              Scan {selectedScan.id?.slice(0, 8)}
            </span>
            <StatusBadge status={selectedScan.scan_phase || selectedScan.status} />
            {selectedScan.total_repos > 0 && (
              <span className="text-[10px] font-mono text-[#5d6b7a]">
                {selectedScan.repos_completed || 0}/{selectedScan.total_repos} repos
                {selectedScan.repos_failed > 0 && <span className="text-[#fb7185] ml-1">({selectedScan.repos_failed} failed)</span>}
                {selectedScan.repos_skipped > 0 && <span className="text-[#8b9bb4] ml-1">({selectedScan.repos_skipped} skipped)</span>}
              </span>
            )}
            {selectedScan.cost_usd > 0 && (
              <span className="text-[10px] font-mono text-[#5d6b7a] ml-auto">
                Cost: ${selectedScan.cost_usd?.toFixed(4)}
                {selectedScan.budget_limit_usd && ` / $${selectedScan.budget_limit_usd}`}
              </span>
            )}
          </div>
          {/* Per-repo progress badges */}
          {renderRepoProgress()}
        </Card>
      )}

      {/* Results area */}
      {selectedScanId && (
        <Card>
          {renderTabs()}
          {activeTab === 'findings' && renderFindingsTab()}
          {activeTab === 'sbom' && renderSbomTab()}
          {activeTab === 'sca' && renderScaTab()}
          {activeTab === 'chains' && renderChainsTab()}
          {activeTab === 'prs' && renderPrsTab()}
          {activeTab === 'licenses' && renderLicensesTab()}
          {activeTab === 'container' && renderContainerTab()}
        </Card>
      )}
    </div>
  );
};

export default CodeScanBoard;

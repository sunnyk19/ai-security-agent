import {
  Activity,
  AlertCircle,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  ExternalLink,
  FileCode2,
  GitBranch,
  Globe,
  History,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Package,
  RefreshCw,
  ScanLine,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { describeApiError, listBranches, listRepositories, listScanHistory, scanRepository } from './api';
import type {
  Branch,
  FindingSeverity,
  Repository,
  ScanHistoryRecord,
  ScanReport,
  SecurityFinding,
  ToolStatus,
} from './types';
import './dashboard.css';

type VisibilityFilter = 'all' | 'public' | 'private';

const severityOrder: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const severityLabels: Record<FindingSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
};

function isPrivateRepository(repository: Repository) {
  return repository.isPrivate || repository.visibility === 'internal';
}

function getFixLabel(finding: SecurityFinding) {
  if (typeof finding.fixAvailable === 'object' && finding.fixAvailable) {
    const fix = finding.fixAvailable;
    const packageName = fix.name ?? finding.dependency;
    const version = fix.version ? ` ${fix.version}` : '';
    const major = fix.isSemVerMajor ? ' · major version change' : '';
    return `Suggested fix: ${packageName ?? 'update'}${version}${major}`;
  }
  if (finding.fixAvailable === true) return 'A fix is available';
  if (finding.fixAvailable === false) return 'No automatic fix available';
  return null;
}

function isWebUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

function scannerName(scanner: SecurityFinding['scanner']) {
  if (scanner === 'npm-audit') return 'npm audit';
  if (scanner === 'secret-detection') return 'Secret detection';
  if (scanner === 'static-analysis') return 'Static analysis';
  return 'Semgrep';
}

function getCoverageNotes(report: ScanReport) {
  const notes: string[] = [];
  if (report.treeTruncated) notes.push('GitHub truncated the repository tree');
  if (report.sourceFilesTruncated) notes.push('source-file limit reached');
  if (report.sourceFilesSkipped > 0) {
    notes.push(`${report.sourceFilesSkipped} source files could not be scanned`);
  }
  if (report.scanners.semgrep.status !== 'completed') {
    notes.push(`Semgrep ${report.scanners.semgrep.status}`);
  }
  const incompleteProjects = report.scanners.npmAudit.projects?.filter(
    (project) => project.status !== 'completed',
  ).length ?? 0;
  if (report.scanners.npmAudit.status === 'partial' || incompleteProjects > 0) {
    notes.push(`${incompleteProjects} npm project audits did not complete`);
  } else if (report.scanners.npmAudit.status !== 'completed') {
    notes.push(`npm audit ${report.scanners.npmAudit.status}`);
  }
  return notes;
}

function getScanCoverageStatus(report: ScanReport): 'completed' | 'partial' | 'failed' {
  if (report.scanners.semgrep.status === 'failed' && report.scanners.npmAudit.status === 'failed') {
    return 'failed';
  }
  if (getCoverageNotes(report).length > 0) return 'partial';
  return 'completed';
}

function FindingRow({ finding }: { finding: SecurityFinding }) {
  const fixLabel = getFixLabel(finding);
  const identifier = finding.dependency ?? finding.id;

  return (
    <article className="finding-row">
      <div className="finding-marker" aria-hidden="true" />
      <div className="finding-body">
        <div className="finding-title-line">
          <strong>{identifier}</strong>
          <span className="scanner-chip">{scannerName(finding.scanner)}</span>
          {finding.project && <span className="project-chip">{finding.project}</span>}
        </div>
        <p className="finding-description">{finding.vulnerability}</p>
        <div className="finding-meta">
          <span className="file-location">
            <FileCode2 size={14} aria-hidden="true" />
            <code>{finding.file}{finding.line !== null ? `:${finding.line}` : ''}</code>
          </span>
          {finding.reference && isWebUrl(finding.reference) && (
            <a className="advisory-link" href={finding.reference} target="_blank" rel="noreferrer">
              Advisory <ExternalLink size={13} aria-hidden="true" />
            </a>
          )}
          {fixLabel && (
            <span className={`fix-label ${finding.fixAvailable === false ? 'fix-missing' : ''}`}>
              {finding.fixAvailable === false ? <CircleHelp size={13} /> : <Check size={13} />}
              {fixLabel}
            </span>
          )}
        </div>
        {finding.possibleImpact && <p className="finding-impact">Impact: {finding.possibleImpact}</p>}
      </div>
    </article>
  );
}

function StatusPill({ name, status, message }: { name: string; status: ToolStatus; message?: string | null }) {
  return (
    <span className={`status-pill status-${status}`} title={message ?? `${name}: ${status}`}>
      <span className="status-dot" />
      {name}: {status}
    </span>
  );
}

// Keep repository, branch, and scan state sourced from the NestJS API; do not fall back to sample findings.
function App() {
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [repositoryPage, setRepositoryPage] = useState(1);
  const [hasMoreRepositories, setHasMoreRepositories] = useState(false);
  const [repositoryLoading, setRepositoryLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [repositoryError, setRepositoryError] = useState('');
  const [search, setSearch] = useState('');
  const [visibilityFilter, setVisibilityFilter] = useState<VisibilityFilter>('all');
  const [selectedRepository, setSelectedRepository] = useState('');
  const [branches, setBranches] = useState<Branch[]>([]);
  const [branchesForRepository, setBranchesForRepository] = useState('');
  const [selectedBranch, setSelectedBranch] = useState('');
  const [branchError, setBranchError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [historyRecords, setHistoryRecords] = useState<ScanHistoryRecord[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState('');
  const [historyError, setHistoryError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    listRepositories(1, controller.signal)
      .then((page) => {
        setRepositories(page.repositories);
        setRepositoryPage(page.pagination.page);
        setHasMoreRepositories(page.pagination.hasNextPage);
        setSelectedRepository((current) => current || page.repositories[0]?.fullName || '');
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setRepositoryError(describeApiError(error, 'repositories'));
      })
      .finally(() => {
        if (!controller.signal.aborted) setRepositoryLoading(false);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    listScanHistory(20, controller.signal)
      .then(({ records }) => setHistoryRecords(records))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setHistoryError(describeApiError(error));
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!selectedRepository) return;

    const [owner, repository] = selectedRepository.split('/', 2);
    const controller = new AbortController();
    listBranches(owner, repository, controller.signal)
      .then((items) => {
        setBranches(items);
        setBranchesForRepository(selectedRepository);
        setSelectedBranch(items.find((branch) => branch.default)?.name ?? items[0]?.name ?? '');
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setBranchError(describeApiError(error));
      });
    return () => controller.abort();
  }, [selectedRepository]);

  const selectedRepo = repositories.find((repository) => repository.fullName === selectedRepository);
  const coverageNotes = report ? getCoverageNotes(report) : [];
  const scanCoverageStatus = report ? getScanCoverageStatus(report) : null;
  const branchLoading = Boolean(selectedRepository) &&
    branchesForRepository !== selectedRepository &&
    !branchError;
  const filteredRepositories = repositories.filter((repository) => {
    const matchesSearch = `${repository.fullName} ${repository.description ?? ''}`
      .toLowerCase()
      .includes(search.trim().toLowerCase());
    const privateRepository = isPrivateRepository(repository);
    const matchesVisibility =
      visibilityFilter === 'all' ||
      (visibilityFilter === 'private' && privateRepository) ||
      (visibilityFilter === 'public' && !privateRepository);
    return matchesSearch && matchesVisibility;
  });

  async function loadMoreRepositories() {
    if (loadingMore || !hasMoreRepositories) return;
    setLoadingMore(true);
    setRepositoryError('');
    try {
      const page = await listRepositories(repositoryPage + 1);
      setRepositories((current) => {
        const known = new Set(current.map((repository) => repository.fullName));
        return [...current, ...page.repositories.filter((repository) => !known.has(repository.fullName))];
      });
      setRepositoryPage(page.pagination.page);
      setHasMoreRepositories(page.pagination.hasNextPage);
    } catch (error) {
      setRepositoryError(describeApiError(error, 'repositories'));
    } finally {
      setLoadingMore(false);
    }
  }

  async function handleScan() {
    if (!selectedRepo || !selectedBranch || scanning) return;
    const [owner, repository] = selectedRepo.fullName.split('/', 2);
    setScanning(true);
    setScanError('');
    setReport(null);
    setSelectedHistoryId('');
    try {
      const result = await scanRepository(owner, repository, selectedBranch);
      setReport(result);
      if (result.history?.persisted && result.history.id) {
        setSelectedHistoryId(result.history.id);
        setHistoryError('');
        try {
          const history = await listScanHistory();
          setHistoryRecords(history.records);
        } catch (error) {
          setHistoryError(describeApiError(error));
        }
      } else if (result.history?.message) {
        setHistoryError(result.history.message);
      }
    } catch (error) {
      setScanError(describeApiError(error));
    } finally {
      setScanning(false);
    }
  }

  function restoreHistory(recordId: string) {
    setSelectedHistoryId(recordId);
    const record = historyRecords.find((item) => item.id === recordId);
    if (!record) return;
    setReport({
      ...record,
      findings: record.findings.map((finding) => ({ ...finding, evidence: finding.evidence ?? '' })),
      history: { id: record.id, persisted: true },
    });
    setScanError('');
  }

  const apiState = repositoryLoading ? 'connecting' : repositoryError ? 'offline' : 'connected';

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#dashboard" aria-label="Sentinel security dashboard">
          <span className="brand-mark"><ShieldCheck size={20} /></span>
          <span><strong>Sentinel</strong><small>SECURITY CONSOLE</small></span>
        </a>
        <div className="sidebar-caption">WORKSPACE</div>
        <div className="sidebar-item sidebar-item-active">
          <Activity size={17} aria-hidden="true" />
          <span>Repository scans</span>
          <span className="nav-indicator" />
        </div>
        <div className="sidebar-foot">
          <div className="sidebar-api-icon"><KeyRound size={16} /></div>
          <div>
            <strong>Backend access</strong>
            <span>GitHub credentials stay server-side</span>
          </div>
        </div>
      </aside>

      <div className="main-column" id="dashboard">
        <header className="topbar">
          <div className="breadcrumb"><span>Security</span><span className="breadcrumb-divider">/</span><strong>Overview</strong></div>
          <div className={`api-indicator api-${apiState}`}>
            <span className="api-indicator-dot" />
            {apiState === 'connecting' ? 'Connecting' : apiState === 'connected' ? 'API connected' : 'API unavailable'}
          </div>
        </header>

        <main className="dashboard-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><Shield size={14} /> APPLICATION SECURITY</div>
              <h1>Repository security</h1>
              <p>Inspect repository dependencies and source with the configured scanners.</p>
            </div>
            <div className="updated-mark"><span className="live-dot" /> LIVE API DATA</div>
          </section>

          <section className="selection-panel" aria-label="Repository and branch selection">
            <div className="selection-topline">
              <div className="section-label"><span>01</span> TARGET</div>
              {selectedRepo && <span className={`visibility-badge ${isPrivateRepository(selectedRepo) ? 'private' : 'public'}`}>
                {isPrivateRepository(selectedRepo) ? <LockKeyhole size={13} /> : <Globe size={13} />}
                {selectedRepo.visibility}
              </span>}
            </div>
            <div className="selection-controls">
              <label className="control-field repository-field">
                <span>Repository</span>
                <span className="select-wrap">
                  <select
                    aria-label="Repository"
                    value={selectedRepository}
                    onChange={(event) => {
                      setSelectedRepository(event.target.value);
                      setSelectedBranch('');
                      setBranches([]);
                      setBranchesForRepository('');
                      setBranchError('');
                      setReport(null);
                      setScanError('');
                    }}
                    disabled={repositoryLoading || Boolean(repositoryError) || repositories.length === 0}
                  >
                    <option value="">{repositoryLoading ? 'Loading repositories…' : 'Choose a repository'}</option>
                    {selectedRepository && !filteredRepositories.some((repository) => repository.fullName === selectedRepository) && (
                      <option value={selectedRepository}>{selectedRepository} · hidden by filter</option>
                    )}
                    {filteredRepositories.map((repository) => (
                      <option key={repository.fullName} value={repository.fullName}>
                        {repository.fullName} · {repository.visibility}
                      </option>
                    ))}
                  </select>
                  <ChevronDown size={16} aria-hidden="true" />
                </span>
              </label>
              <label className="control-field branch-field">
                <span>Branch</span>
                <span className="select-wrap">
                  <GitBranch size={15} aria-hidden="true" />
                  <select
                    aria-label="Branch"
                    value={selectedBranch}
                    onChange={(event) => {
                      setSelectedBranch(event.target.value);
                      setReport(null);
                      setScanError('');
                    }}
                    disabled={!selectedRepository || branchLoading || branches.length === 0}
                  >
                    <option value="">{branchLoading ? 'Loading branches…' : 'Choose a branch'}</option>
                    {branches.map((branch) => (
                      <option key={branch.name} value={branch.name}>
                        {branch.name}{branch.default ? ' · default' : ''}
                      </option>
                    ))}
                  </select>
                  <ChevronDown size={16} aria-hidden="true" />
                </span>
              </label>
              <button className="scan-button" type="button" onClick={handleScan} disabled={!selectedRepo || !selectedBranch || scanning}>
                {scanning ? <LoaderCircle className="spin" size={17} /> : <ScanLine size={17} />}
                {scanning ? 'Scanning' : 'Scan repository'}
              </button>
            </div>
            <div className="selection-bottomline">
              <div className="search-control">
                <Search size={15} aria-hidden="true" />
                <input
                  aria-label="Search repositories"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Filter repositories"
                  disabled={repositoryLoading || repositories.length === 0}
                />
              </div>
              <div className="visibility-filter" role="group" aria-label="Filter repositories by visibility">
                {(['all', 'public', 'private'] as const).map((filter) => (
                  <button
                    key={filter}
                    type="button"
                    aria-pressed={visibilityFilter === filter}
                    onClick={() => setVisibilityFilter(filter)}
                  >
                    {filter[0].toUpperCase() + filter.slice(1)}
                  </button>
                ))}
              </div>
              {hasMoreRepositories && (
                <button className="load-more" type="button" onClick={loadMoreRepositories} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load more'}
                  {loadingMore ? <LoaderCircle className="spin" size={14} /> : <ChevronDown size={14} />}
                </button>
              )}
            </div>
            {repositoryError && <div className="inline-error" role="alert"><AlertCircle size={17} /><span>{repositoryError}</span><button type="button" onClick={() => window.location.reload()} aria-label="Retry repository loading"><RefreshCw size={15} /></button></div>}
            {branchError && <div className="inline-error" role="alert"><AlertCircle size={17} /><span>{branchError}</span></div>}
            {!repositoryLoading && !repositoryError && repositories.length === 0 && (
              <div className="empty-repositories"><CircleHelp size={18} /> No repositories were returned by the backend.</div>
            )}
            {!repositoryLoading && !repositoryError && repositories.length > 0 && filteredRepositories.length === 0 && (
              <div className="empty-repositories"><Search size={18} /> No repositories match these filters.</div>
            )}
          </section>

          {scanError && <div className="scan-error" role="alert"><AlertCircle size={18} /><div><strong>Scan request failed</strong><p>{scanError}</p></div></div>}

          <section className="results-section" aria-live="polite" aria-busy={scanning}>
            <div className="results-heading">
              <div>
                <div className="section-label"><span>02</span> SCAN RESULTS</div>
                <h2>{report ? report.repository : 'Findings overview'}</h2>
              </div>
              {report ? (
                <div className="scan-context">
                  <span className={`coverage-badge coverage-${scanCoverageStatus}`}>
                    {scanCoverageStatus === 'completed' ? 'Complete' : scanCoverageStatus === 'failed' ? 'Failed' : 'Partial scan'}
                  </span>
                  <GitBranch size={14} /> {report.branch}<span className="context-divider" /><Clock3 size={14} /> {new Date(report.scannedAt).toLocaleString()}
                </div>
              ) : (
                <span className="awaiting-scan">{scanning ? 'Analysis in progress' : 'Awaiting scan'}</span>
              )}
            </div>

            <div className="history-control-row">
              <label className="history-picker">
                <History size={14} aria-hidden="true" />
                <span>Recent scans</span>
                <select
                  aria-label="Recent scan history"
                  value={selectedHistoryId}
                  onChange={(event) => restoreHistory(event.target.value)}
                  disabled={historyRecords.length === 0}
                >
                  <option value="">Select a saved scan</option>
                  {historyRecords.map((record) => (
                    <option key={record.id} value={record.id}>
                      {record.repository} · {record.branch} · {new Date(record.scannedAt).toLocaleString()}
                    </option>
                  ))}
                </select>
              </label>
              {historyError && <span className="history-message" role="status">{historyError}</span>}
            </div>

            {scanning && <div className="scan-progress"><span className="progress-line" /><span>Retrieving repository tree and running configured scanners</span></div>}

            {report && (
              <>
                <div className="summary-grid">
                  {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
                    <div className={`summary-stat stat-${severity}`} key={severity}>
                      <div className="stat-topline"><span>{severityLabels[severity]}</span><span className="stat-icon" aria-hidden="true" /></div>
                      <strong>{report.summary[severity]}</strong>
                      <small>findings</small>
                    </div>
                  ))}
                </div>

                <div className="scan-details-row">
                  <div className="scan-facts">
                    <span><FileCode2 size={15} /> {report.filesScanned} source files scanned</span>
                    {report.treeTruncated && <span className="fact-warning"><AlertCircle size={14} /> GitHub truncated this repository tree</span>}
                    {report.sourceFilesTruncated && <span className="fact-warning"><AlertCircle size={14} /> Source file limit reached</span>}
                  </div>
                  {selectedRepo?.htmlUrl && isWebUrl(selectedRepo.htmlUrl) && (
                    <a className="repo-link" href={selectedRepo.htmlUrl} target="_blank" rel="noreferrer">
                      Open repository <ArrowUpRight size={15} />
                    </a>
                  )}
                </div>

                <div className="scanner-status-row" aria-label="Scanner status">
                  <StatusPill name="Semgrep" status={report.scanners.semgrep.status} message={report.scanners.semgrep.message} />
                  <StatusPill name="npm audit" status={report.scanners.npmAudit.status} message={report.scanners.npmAudit.message} />
                  <StatusPill name="Secrets" status={report.scanners.secretDetection.status} />
                </div>
                {report.scanners.npmAudit.projects && report.scanners.npmAudit.projects.length > 0 && (
                  <div className="project-statuses" aria-label="npm project audit status">
                    <span className="project-status-label"><Package size={14} /> npm projects</span>
                    {report.scanners.npmAudit.projects.map((project) => (
                      <span key={project.directory} className={`project-status status-${project.status}`} title={project.message}>
                        {project.directory}: {project.status} · {project.findings === null ? 'not counted' : `${project.findings} findings`}
                      </span>
                    ))}
                  </div>
                )}
                {coverageNotes.length > 0 && (
                  <div className="scanner-note">
                    <ShieldAlert size={16} />
                    <span>Partial coverage: {coverageNotes.join(' · ')}.</span>
                  </div>
                )}

                <div className="findings-list">
                  {report.findings.length === 0 ? (
                    <div className="empty-findings"><ShieldCheck size={25} /><strong>No findings in this scan</strong><span>No findings were reported by completed scanners.</span></div>
                  ) : severityOrder.map((severity) => {
                    const findings = report.findings.filter((finding) => finding.severity === severity);
                    if (findings.length === 0) return null;
                    return (
                      <section className={`severity-section severity-${severity}`} key={severity} aria-labelledby={`severity-${severity}`}>
                        <header className="severity-heading">
                          <span className="severity-name"><span className="severity-square" /> <h3 id={`severity-${severity}`}>{severityLabels[severity]}</h3></span>
                          <span className="severity-count">{findings.length}</span>
                        </header>
                        <div className="severity-items">
                          {findings.map((finding, index) => <FindingRow key={`${finding.scanner}-${finding.id}-${finding.file}-${finding.line ?? 'na'}-${index}`} finding={finding} />)}
                        </div>
                      </section>
                    );
                  })}
                </div>
              </>
            )}
            {!report && !scanning && !scanError && (
              <div className="no-scan-state"><div className="scan-placeholder-icon"><ScanLine size={22} /></div><strong>Select a repository and branch to begin</strong><span>Results from the NestJS scanners will appear here.</span></div>
            )}
          </section>
        </main>
        <footer className="page-footer"><span>Sentinel · Repository security</span><span>Scanner reports are read-only</span></footer>
      </div>
    </div>
  );
}

export default App;

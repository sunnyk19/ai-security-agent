export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ToolStatus = 'completed' | 'partial' | 'unavailable' | 'skipped' | 'failed';

export type Repository = {
  id: number | null;
  name: string;
  fullName: string;
  description: string | null;
  visibility: 'public' | 'private' | 'internal';
  primaryLanguage: string | null;
  defaultBranch: string;
  htmlUrl: string;
  isPrivate: boolean;
};

export type Branch = {
  name: string;
  default: boolean;
  protected: boolean;
  commitSha: string | null;
};

export type SecurityFinding = {
  id: string;
  scanner: 'semgrep' | 'npm-audit' | 'secret-detection' | 'static-analysis';
  severity: FindingSeverity;
  file: string;
  line: number | null;
  vulnerability: string;
  evidence: string;
  possibleImpact: string;
  dependency?: string;
  project?: string;
  reference?: string;
  advisories?: Array<{
    title?: string;
    url?: string;
    range?: string;
    severity?: string;
  }>;
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
};

export type ScanReport = {
  repository: string;
  branch: string;
  scannedAt: string;
  filesScanned: number;
  sourceFilesSkipped: number;
  treeTruncated: boolean;
  sourceFilesTruncated: boolean;
  scanners: {
    semgrep: { status: ToolStatus; findings: number | null; message: string | null };
    npmAudit: {
      status: ToolStatus;
      findings: number | null;
      message: string | null;
      projects?: Array<{
        directory: string;
        status: ToolStatus;
        findings: number | null;
        message?: string;
      }>;
    };
    secretDetection: { status: ToolStatus; findings: number };
  };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: SecurityFinding[];
  history?: { id: string | null; persisted: boolean; message?: string };
};

export type ScanHistoryRecord = Omit<ScanReport, 'findings' | 'history'> & {
  id: string;
  findings: Array<Omit<SecurityFinding, 'evidence'> & { evidence?: string }>;
};

export type RepositoryPage = {
  repositories: Repository[];
  pagination: {
    page: number;
    perPage: number;
    hasNextPage: boolean;
    hasPreviousPage: boolean;
  };
};

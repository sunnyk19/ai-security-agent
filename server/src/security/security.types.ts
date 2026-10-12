export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ToolStatus = 'completed' | 'partial' | 'unavailable' | 'skipped' | 'failed';

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
    name?: string;
    dependency?: string;
    source?: number;
    title?: string;
    url?: string;
    range?: string;
    severity?: string;
    cwe?: string[];
    cvss?: { score?: number; vectorString?: string };
  }>;
  fixAvailable?:
    | boolean
    | { name?: string; version?: string; isSemVerMajor?: boolean };
};

export type SourceFile = {
  path: string;
  content: string;
};

export type NpmProjectAuditStatus = {
  directory: string;
  status: ToolStatus;
  findings: number | null;
  message?: string;
};

export type SecurityScanReport = {
  repository: string;
  branch: string;
  scannedAt: string;
  filesScanned: number;
  sourceFilesSkipped: number;
  sourceFileLimit: number;
  sourceFilesTruncated: boolean;
  treeTruncated: boolean;
  scanners: {
    semgrep: { status: ToolStatus; findings: number | null; message: string | null };
    npmAudit: {
      status: ToolStatus;
      findings: number | null;
      message: string | null;
      projects: NpmProjectAuditStatus[];
    };
    secretDetection: { status: 'completed'; findings: number };
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

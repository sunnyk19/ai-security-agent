export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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
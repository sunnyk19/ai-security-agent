import type { SecurityFinding, SourceFile } from './security.types.js';

const SECRET_PATTERNS = [
  {
    id: 'private-key',
    name: 'Private key exposed in source',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    impact: 'An exposed private key may allow impersonation or unauthorized access.',
  },
  {
    id: 'github-token',
    name: 'Hard-coded GitHub token',
    severity: 'critical',
    pattern: /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b/g,
    impact: 'A leaked GitHub token may grant access to repositories or account actions.',
  },
  {
    id: 'aws-access-key',
    name: 'Hard-coded AWS access key',
    severity: 'high',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    impact: 'A leaked cloud credential may enable unauthorized access to AWS resources.',
  },
  {
    id: 'hard-coded-credential',
    name: 'Hard-coded credential assignment',
    severity: 'high',
    pattern:
      /\b(?:api[_-]?key|client[_-]?secret|password|secret|token)\b\s*[:=]\s*(['"])(?!\s*(?:\$\{?process\.env|process\.env|example|placeholder|changeme|replace|your[-_]|\[REDACTED))[^'"\r\n]{12,}\1/gi,
    impact: 'A committed credential may be recovered from source history and used against the associated service.',
  },
] as const;

export function findHardcodedSecrets(files: SourceFile[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reportedLines = new Set<string>();

  for (const file of files) {
    for (const rule of SECRET_PATTERNS) {
      const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
      for (const match of file.content.matchAll(pattern)) {
        const offset = match.index ?? 0;
        const line = file.content.slice(0, offset).split('\n').length;
        const lineKey = `${file.path}:${line}`;
        if (reportedLines.has(lineKey)) continue;
        reportedLines.add(lineKey);
        findings.push({
          id: `${rule.id}:${file.path}:${line}`,
          scanner: 'secret-detection',
          severity: rule.severity,
          file: file.path,
          line,
          vulnerability: rule.name,
          evidence: 'Credential-like value detected; value redacted.',
          possibleImpact: rule.impact,
        });
      }
    }
  }

  return findings;
}

const STATIC_ANALYSIS_RULES = [
  {
    id: 'unsafe-eval',
    name: 'Unsafe dynamic code execution',
    severity: 'high' as const,
    pattern: /\b(?:eval|Function)\s*\(/g,
    impact:
      'Dynamic code execution can evaluate attacker-controlled input as executable code.',
  },
  {
    id: 'unsafe-command-exec',
    name: 'Unsafe command execution',
    severity: 'high' as const,
    pattern: /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(/g,
    impact:
      'Executing OS commands or shell commands with user-controlled input can allow command injection.',
  },
  {
    id: 'shell-enabled-exec',
    name: 'Shell execution enabled by configuration',
    severity: 'medium' as const,
    pattern: /(?:exec|spawn|execSync|spawnSync)\s*\([^)]*shell\s*:\s*true/gi,
    impact:
      'Enabling shell execution increases the risk of command injection when inputs are not strictly validated.',
  },
] as const;

export function findCommonMisconfigurations(files: SourceFile[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reportedLines = new Set<string>();

  for (const file of files) {
    for (const rule of STATIC_ANALYSIS_RULES) {
      const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
      for (const match of file.content.matchAll(pattern)) {
        const offset = match.index ?? 0;
        const line = file.content.slice(0, offset).split('\n').length;
        const lineKey = `${file.path}:${line}:${rule.id}`;
        if (reportedLines.has(lineKey)) continue;
        reportedLines.add(lineKey);
        findings.push({
          id: `${rule.id}:${file.path}:${line}`,
          scanner: 'static-analysis',
          severity: rule.severity,
          file: file.path,
          line,
          vulnerability: rule.name,
          evidence: match[0].trim(),
          possibleImpact: rule.impact,
        });
      }
    }
  }

  return findings;
}

export function redactSecrets(content: string): string {
  return content
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
      '[REDACTED PRIVATE KEY]',
    )
    .replace(/\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b/g, '[REDACTED TOKEN]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED ACCESS KEY]')
    .replace(
      /(\b(?:api[_-]?key|access[_-]?key|auth(?:orization)?|bearer|client[_-]?secret|credential|password|private[_-]?key|secret|token)\b\s*[:=]\s*)(['"])[^'"\r\n]+\2/gi,
      '$1$2[REDACTED]$2',
    )
    .replace(
      /(\b(?:authorization|proxy-authorization)\b\s*[:=]\s*)(['"]?)(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi,
      '$1$2[REDACTED]',
    );
}

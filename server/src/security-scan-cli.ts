import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Octokit } from '@octokit/rest';
import { SecurityScannerService } from './security/security-scanner.service.js';
import { ScanHistoryService } from './security/scan-history.service.js';

type CliError = {
  error: string;
  repository?: string;
  branch?: string;
};

function normalizeBranch(value: string | undefined): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function fail(error: unknown, repository?: string, branch?: string): never {
  const message = error instanceof Error ? error.message : String(error);
  const payload: CliError = { error: message };
  if (repository) payload.repository = repository;
  if (branch) payload.branch = branch;
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exit(1);
}

function main() {
  const owner = process.env.SCAN_TARGET_OWNER?.trim();
  const repository = process.env.SCAN_TARGET_REPO?.trim();
  const branch = normalizeBranch(process.env.SCAN_TARGET_BRANCH);

  if (!owner || !repository) {
    fail(new Error('SCAN_TARGET_OWNER and SCAN_TARGET_REPO environment variables are required.'));
  }

  const token = process.env.GITHUB_TOKEN?.trim();
  const github = new Octokit({
    ...(token ? { auth: token } : {}),
    userAgent: 'ai-security-agent-ci',
    request: { timeout: 15000, retries: 2 },
  });

  const historyPath = process.env.SCAN_HISTORY_PATH?.trim() || 'data/scan-history.json';
  const history = new ScanHistoryService(resolve(historyPath));
  const scanner = new SecurityScannerService(github, history);

  scanner
    .scan(owner, repository, branch)
    .then((report) => {
      const target = `${owner}/${repository}`;
      const failedScanners = Object.entries(report.scanners).filter(
        ([, status]) => status.status === 'failed',
      );
      if (failedScanners.length > 0) {
        fail(
          new Error(
            `Scanner(s) failed: ${failedScanners.map(([name]) => name).join(', ')}.`,
          ),
          report.repository,
          report.branch,
        );
      }

      const historyDir = resolve(historyPath).replace(/[^/\\]+$/, '');
      if (historyDir && !existsSync(historyDir)) {
        mkdirSync(historyDir, { recursive: true });
      }
      writeFileSync(
        resolve('scan-results', 'scan-report.json'),
        JSON.stringify(report, null, 2),
        'utf8',
      );
      process.stdout.write(JSON.stringify(report, null, 2));
      process.stdout.write(`\nScan completed for ${target} (${report.branch}).\n`);
    })
    .catch((error) => fail(error, `${owner}/${repository}`, branch));
}

main();
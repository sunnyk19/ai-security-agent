import {
  BadGatewayException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Octokit } from '@octokit/rest';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { GITHUB_CLIENT } from '../github/github.tokens.js';
import {
  findCommonMisconfigurations,
  findHardcodedSecrets,
} from './secret-scanner.js';
import type {
  FindingSeverity,
  SecurityFinding,
  SourceFile,
} from './security.types.js';

const MAX_SOURCE_FILES = 100;
const MAX_FILE_BYTES = 1024 * 1024;
const TOOL_TIMEOUT_MS = 120_000;
const SOURCE_PATTERN = /\.(?:[cm]?[jt]sx?)$/i;
const EXCLUDED_PATH = /(^|\/)(node_modules|dist|build|coverage|vendor|\.git)\//i;
const EXCLUDED_PROJECT_PATH =
  /(^|\/)(?:node_modules|dist|build|coverage|vendor|\.git|\.next|\.nuxt|\.output|\.turbo|\.cache|\.vercel|\.svelte-kit|\.angular|\.parcel-cache|\.serverless|out|target|tmp|temp|artifacts|generated|storybook-static|playwright-report|test-results|bower_components)(?:\/|$)/i;

type ToolStatus = 'completed' | 'partial' | 'unavailable' | 'skipped' | 'failed';
type ToolResult = {
  status: ToolStatus;
  findings: SecurityFinding[];
  message?: string;
  projects?: NpmAuditProjectStatus[];
};
type NpmProject = {
  directory: string;
  packagePath: string | null;
  lockPath: string | null;
};
type NpmAuditProjectStatus = {
  directory: string;
  status: ToolStatus;
  findings: number | null;
  message?: string;
};
type NpmAuditFileResult =
  | { status: 'completed'; content: string }
  | { status: 'skipped'; message: string }
  | { status: 'failed'; message: string };
type NpmFixAvailable =
  | boolean
  | { name?: string; version?: string; isSemVerMajor?: boolean };
type NpmAdvisory = {
  name?: string;
  dependency?: string;
  source?: number;
  title?: string;
  url?: string;
  range?: string;
  severity?: string;
  cwe?: string[];
  cvss?: { score?: number; vectorString?: string };
};
type NpmAuditVulnerability = {
  severity: string;
  range?: string;
  via?: Array<string | NpmAdvisory>;
  fixAvailable?: NpmFixAvailable;
};
type NpmAuditOutput = {
  error?: unknown;
  errors?: unknown[];
  vulnerabilities: Record<string, NpmAuditVulnerability>;
};
type SemgrepResult = {
  check_id: string;
  path: string;
  start?: { line?: number | null };
  extra: {
    message: string;
    severity?: string;
    lines?: string;
    metadata?: { impact?: string; references?: string[] };
  };
};
type SemgrepOutput = {
  errors?: Array<{ message?: string }>;
  results: SemgrepResult[];
};
type CommandResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNpmAuditOutput(value: unknown): value is NpmAuditOutput {
  if (!isRecord(value) || !isRecord(value.vulnerabilities)) return false;
  if (value.errors !== undefined && !Array.isArray(value.errors)) return false;

  return Object.values(value.vulnerabilities).every((vulnerability) => {
    if (!isRecord(vulnerability)) return false;
    if (!['critical', 'high', 'moderate', 'low'].includes(String(vulnerability.severity))) {
      return false;
    }
    if (vulnerability.range !== undefined && typeof vulnerability.range !== 'string') {
      return false;
    }
    if (
      vulnerability.via !== undefined &&
      (!Array.isArray(vulnerability.via) ||
        !vulnerability.via.every((item) => typeof item === 'string' || isRecord(item)))
    ) {
      return false;
    }
    if (
      vulnerability.fixAvailable !== undefined &&
      typeof vulnerability.fixAvailable !== 'boolean' &&
      !isRecord(vulnerability.fixAvailable)
    ) {
      return false;
    }
    return true;
  });
}

function isSemgrepOutput(value: unknown): value is SemgrepOutput {
  if (!isRecord(value) || !Array.isArray(value.results)) return false;
  if (
    value.errors !== undefined &&
    (!Array.isArray(value.errors) ||
      !value.errors.every(
        (error) =>
          isRecord(error) &&
          (error.message === undefined || typeof error.message === 'string'),
      ))
  ) {
    return false;
  }

  return value.results.every((result) => {
    if (
      !isRecord(result) ||
      typeof result.check_id !== 'string' ||
      typeof result.path !== 'string' ||
      !isRecord(result.extra) ||
      typeof result.extra.message !== 'string'
    ) {
      return false;
    }
    if (result.extra.severity !== undefined && typeof result.extra.severity !== 'string') {
      return false;
    }
    if (result.extra.lines !== undefined && typeof result.extra.lines !== 'string') {
      return false;
    }
    if (result.extra.metadata !== undefined) {
      if (!isRecord(result.extra.metadata)) return false;
      if (
        result.extra.metadata.impact !== undefined &&
        typeof result.extra.metadata.impact !== 'string'
      ) {
        return false;
      }
      if (
        result.extra.metadata.references !== undefined &&
        (!Array.isArray(result.extra.metadata.references) ||
          !result.extra.metadata.references.every((reference) => typeof reference === 'string'))
      ) {
        return false;
      }
    }
    if (result.start !== undefined) {
      if (!isRecord(result.start)) return false;
      const line = result.start.line;
      if (line !== undefined && line !== null && (!Number.isInteger(line) || Number(line) < 1)) {
        return false;
      }
    }
    return true;
  });
}

@Injectable()
export class SecurityScannerService {
  constructor(@Inject(GITHUB_CLIENT) private readonly github: Octokit) {}

  async scan(owner: string, repository: string, branch?: string) {
    let workspace: string | undefined;

    try {
      const repositoryResponse = await this.github.rest.repos.get({
        owner,
        repo: repository,
      });
      const defaultBranch = repositoryResponse.data.default_branch;
      const selectedBranch = typeof branch === 'string' && branch.trim()
        ? branch.trim()
        : defaultBranch;
      const branchResponse = await this.github.rest.repos.getBranch({
        owner,
        repo: repository,
        branch: selectedBranch,
      });
      const commitResponse = await this.github.rest.git.getCommit({
        owner,
        repo: repository,
        commit_sha: branchResponse.data.commit.sha,
      });
      const treeResponse = await this.github.rest.git.getTree({
        owner,
        repo: repository,
        tree_sha: commitResponse.data.tree.sha,
        recursive: '1',
      });
      const paths = treeResponse.data.tree
        .filter((entry) => entry.type === 'blob')
        .map((entry) => entry.path);
      const sourcePaths = paths
        .filter((path) => SOURCE_PATTERN.test(path) && !EXCLUDED_PATH.test(path))
        .sort(
          (left, right) =>
            this.rankSourcePath(left) - this.rankSourcePath(right) ||
            left.localeCompare(right),
        );
      const selectedSourcePaths = sourcePaths.slice(0, MAX_SOURCE_FILES);
      const npmProjects = this.discoverNpmProjects(paths);
      const sourceFiles = await this.fetchSourceFiles(
        owner,
        repository,
        selectedSourcePaths,
      );

      workspace = await mkdtemp(join(tmpdir(), 'ai-security-scan-'));
      await Promise.all(
        sourceFiles.map((file) => this.writeWorkspaceFile(workspace!, file)),
      );

      const [semgrep, npmAudit] = await Promise.all([
        this.runSemgrep(workspace),
        this.runNpmAudit(owner, repository, workspace, npmProjects),
      ]);
      const secrets = findHardcodedSecrets(sourceFiles);
      const misconfigurations = findCommonMisconfigurations(sourceFiles);
      const findings = this.dedupeFindings([
        ...semgrep.findings,
        ...npmAudit.findings,
        ...secrets,
        ...misconfigurations,
      ]).sort(
        (left, right) =>
          this.severityRank(left.severity) - this.severityRank(right.severity) ||
          left.file.localeCompare(right.file) ||
          (left.line ?? 0) - (right.line ?? 0),
      );

      return {
        repository: repositoryResponse.data.full_name,
        branch: selectedBranch,
        scannedAt: new Date().toISOString(),
        filesScanned: sourceFiles.length,
        sourceFileLimit: MAX_SOURCE_FILES,
        sourceFilesTruncated: sourcePaths.length > MAX_SOURCE_FILES,
        treeTruncated: treeResponse.data.truncated,
        scanners: {
          semgrep: {
            status: semgrep.status,
            findings: semgrep.status === 'completed' ? semgrep.findings.length : null,
            message: semgrep.message ?? null,
          },
          npmAudit: {
            status: npmAudit.status,
            findings: npmAudit.status === 'completed' ? npmAudit.findings.length : null,
            message: npmAudit.message ?? null,
            projects: npmAudit.projects ?? [],
          },
          secretDetection: {
            status: 'completed' as const,
            findings: secrets.length,
          },
        },
        summary: this.summarize(findings),
        findings,
      };
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        throw new NotFoundException(
          `Repository ${owner}/${repository} was not found or is not accessible.`,
        );
      }
      if (error instanceof NotFoundException) throw error;
      throw new BadGatewayException('Unable to scan repository data from GitHub.');
    } finally {
      if (workspace) await rm(workspace, { recursive: true, force: true });
    }
  }

  private rankSourcePath(path: string): number {
    if (/^packages\//i.test(path)) return 0;
    if (/(^|\/)src\//i.test(path)) return 1;
    if (/(^|\/)(integration|test|tests|examples?|samples?|fixtures?)\//i.test(path)) {
      return 3;
    }
    return 2;
  }

  // Pair manifests and npm lockfiles by directory; a manifest without a lockfile is not auditable.
  private discoverNpmProjects(paths: string[]): NpmProject[] {
    const packagePaths = new Set<string>();
    const lockPaths = new Set<string>();

    for (const path of paths) {
      const name = path.slice(path.lastIndexOf('/') + 1);
      const directory = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
      if (EXCLUDED_PROJECT_PATH.test(directory)) continue;
      if (name === 'package.json') packagePaths.add(path);
      if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
        lockPaths.add(path);
      }
    }

    const directories = new Set<string>();
    for (const path of [...packagePaths, ...lockPaths]) {
      directories.add(path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
    }

    return [...directories].sort().map((directory) => {
      const prefix = directory ? `${directory}/` : '';
      const packagePath = packagePaths.has(`${prefix}package.json`)
        ? `${prefix}package.json`
        : null;
      const shrinkwrapPath = `${prefix}npm-shrinkwrap.json`;
      const packageLockPath = `${prefix}package-lock.json`;
      const lockPath = lockPaths.has(shrinkwrapPath)
        ? shrinkwrapPath
        : lockPaths.has(packageLockPath)
          ? packageLockPath
          : null;

      return { directory, packagePath, lockPath };
    });
  }

  private async fetchSourceFiles(
    owner: string,
    repository: string,
    paths: string[],
  ): Promise<SourceFile[]> {
    const files: SourceFile[] = [];
    for (let index = 0; index < paths.length; index += 5) {
      const batch = paths.slice(index, index + 5);
      const results = await Promise.all(
        batch.map(async (path) => {
          const content = await this.fetchTextFile(owner, repository, path);
          return content === null ? null : { path, content };
        }),
      );
      files.push(...results.filter((file): file is SourceFile => file !== null));
    }
    return files;
  }

  private async fetchTextFile(
    owner: string,
    repository: string,
    path: string,
  ): Promise<string | null> {
    try {
      const response = await this.github.rest.repos.getContent({
        owner,
        repo: repository,
        path,
      });
      if (
        Array.isArray(response.data) ||
        response.data.type !== 'file' ||
        response.data.encoding !== 'base64' ||
        response.data.size > MAX_FILE_BYTES
      ) {
        return null;
      }
      return Buffer.from(response.data.content, 'base64').toString('utf8');
    } catch {
      return null;
    }
  }

  private async writeWorkspaceFile(workspace: string, file: SourceFile) {
    const target = resolve(workspace, ...file.path.split('/'));
    if (!target.startsWith(`${resolve(workspace)}${sep}`)) return;
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, file.content, { flag: 'w' });
  }

  private async runSemgrep(workspace: string): Promise<ToolResult> {
    const configPath = resolve(process.cwd(), '.semgrep.yml');
    try {
      await readFile(configPath);
    } catch {
      return { status: 'unavailable', findings: [], message: 'Semgrep rules are missing.' };
    }

    const result = await this.runCommand(
      'semgrep',
      ['scan', '--config', configPath, '--json', '--metrics=off', workspace],
      workspace,
    );
    if (this.isCommandUnavailable(result)) {
      return {
        status: 'unavailable',
        findings: [],
        message: 'Install the Semgrep CLI to enable this scanner.',
      };
    }
    if (result.error || !result.stdout) {
      return {
        status: 'failed',
        findings: [],
        message: result.error ?? result.stderr.slice(0, 300),
      };
    }
    if (result.code !== 0 && result.code !== 1) {
      return {
        status: 'failed',
        findings: [],
        message: result.stderr.slice(0, 300) || 'Semgrep exited with an error.',
      };
    }

    try {
      const parsedOutput: unknown = JSON.parse(result.stdout);
      if (!isSemgrepOutput(parsedOutput)) {
        return {
          status: 'failed',
          findings: [],
          message: 'Semgrep returned an unexpected JSON structure.',
        };
      }
      const output = parsedOutput;
      if (output.errors?.length) {
        return {
          status: 'failed',
          findings: [],
          message: output.errors[0].message ?? 'Semgrep reported a scan error.',
        };
      }

      const findings: SecurityFinding[] = [];
      for (const item of output.results) {
        const file = this.normalizeSemgrepPath(workspace, item.path);
        if (!file) {
          return {
            status: 'failed',
            findings: [],
            message: 'Semgrep returned a file path outside the scan workspace.',
          };
        }
        findings.push({
          id: item.check_id,
          scanner: 'semgrep',
          severity: this.normalizeSeverity(item.extra.severity),
          file,
          line: item.start?.line ?? null,
          vulnerability: item.extra.message,
          evidence: item.extra.lines?.trim() ?? '',
          possibleImpact:
            item.extra.metadata?.impact ?? 'The issue may expose the application to compromise.',
          reference: item.extra.metadata?.references?.[0],
        });
      }
      return { status: 'completed', findings };
    } catch {
      return {
        status: 'failed',
        findings: [],
        message: 'Semgrep returned invalid JSON output.',
      };
    }
  }

  private normalizeSemgrepPath(workspace: string, path: string): string | null {
    const root = resolve(workspace);
    const absolutePath = isAbsolute(path) ? resolve(path) : resolve(root, path);
    const file = relative(root, absolutePath);
    if (!file || file === '..' || file.startsWith(`..${sep}`) || isAbsolute(file)) {
      return null;
    }
    return file.split(sep).join('/');
  }

  // Audit only repository-provided manifest/lockfile pairs; never install dependencies or run scripts.
  private async runNpmAudit(
    owner: string,
    repository: string,
    workspace: string,
    projects: NpmProject[],
  ): Promise<ToolResult> {
    if (!projects.length) {
      return {
        status: 'skipped',
        findings: [],
        message: 'No npm projects were found in the repository tree.',
        projects: [],
      };
    }

    const auditArgs = [
      'audit',
      '--json',
      '--ignore-scripts',
      '--no-fund',
      '--no-progress',
    ];
    let command = 'npm';
    let args = auditArgs;
    if (process.platform === 'win32') {
      if (process.env.npm_execpath) {
        command = process.execPath;
        args = [process.env.npm_execpath, ...auditArgs];
      } else {
        command = 'cmd.exe';
        args = ['/d', '/s', '/c', `npm.cmd ${auditArgs.join(' ')}`];
      }
    }
    const findings: SecurityFinding[] = [];
    const projectStatuses: NpmAuditProjectStatus[] = [];

    for (const project of projects) {
      if (!project.packagePath || !project.lockPath) {
        const missingFiles = [
          !project.packagePath && 'package.json',
          !project.lockPath && 'package-lock.json or npm-shrinkwrap.json',
        ].filter(Boolean);
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'skipped',
          findings: null,
          message: `Missing ${missingFiles.join(' and ')}; npm audit requires a manifest and lockfile in the same directory.`,
        });
        continue;
      }

      const [manifestResult, lockResult] = await Promise.all([
        this.fetchNpmAuditFile(owner, repository, project.packagePath),
        this.fetchNpmAuditFile(owner, repository, project.lockPath),
      ]);
      if (manifestResult.status !== 'completed') {
        projectStatuses.push({
          directory: project.directory || '.',
          status: manifestResult.status,
          findings: null,
          message: manifestResult.message,
        });
        continue;
      }
      if (lockResult.status !== 'completed') {
        projectStatuses.push({
          directory: project.directory || '.',
          status: lockResult.status,
          findings: null,
          message: lockResult.message,
        });
        continue;
      }

      if (!this.isJsonObject(manifestResult.content) || !this.isJsonObject(lockResult.content)) {
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'failed',
          findings: null,
          message: 'The project manifest or npm lockfile contains invalid JSON.',
        });
        continue;
      }

      await Promise.all([
        this.writeWorkspaceFile(workspace, {
          path: project.packagePath,
          content: manifestResult.content,
        }),
        this.writeWorkspaceFile(workspace, {
          path: project.lockPath,
          content: lockResult.content,
        }),
      ]);
      const projectWorkspace = project.directory
        ? resolve(workspace, ...project.directory.split('/'))
        : workspace;
      const result = await this.runCommand(command, args, projectWorkspace);

      if (this.isCommandUnavailable(result)) {
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'unavailable',
          findings: null,
          message: 'npm was not found.',
        });
        continue;
      }
      if (result.error || !result.stdout || result.code === null) {
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'failed',
          findings: null,
          message: result.error === 'Scanner timed out.'
            ? 'npm audit timed out.'
            : 'npm audit did not return JSON output.',
        });
        continue;
      }

      try {
        const parsedOutput: unknown = JSON.parse(result.stdout);
        if (!isNpmAuditOutput(parsedOutput)) {
          projectStatuses.push({
            directory: project.directory || '.',
            status: 'failed',
            findings: null,
            message: 'npm audit returned an unexpected JSON structure.',
          });
          continue;
        }
        const output = parsedOutput;
        if (output.error || output.errors?.length || (result.code !== 0 && result.code !== 1)) {
          projectStatuses.push({
            directory: project.directory || '.',
            status: 'failed',
            findings: null,
            message: 'npm audit exited with an error.',
          });
          continue;
        }

        const projectFindings = Object.entries(output.vulnerabilities ?? {}).map(
          ([dependency, vulnerability]) => {
            const advisories = (vulnerability.via ?? []).filter(
              (item): item is NpmAdvisory => typeof item !== 'string',
            );
            const relatedDependencies = (vulnerability.via ?? []).filter(
              (item): item is string => typeof item === 'string',
            );
            const titles = advisories.flatMap((item) => item.title ? [item.title] : []);
            const vulnerabilityDetails = [
              ...titles,
              ...(relatedDependencies.length
                ? [`Related dependencies: ${relatedDependencies.join(', ')}`]
                : []),
            ];
            const fixAvailable = this.normalizeFixAvailable(vulnerability.fixAvailable);

            return {
              id: `npm-audit:${dependency}`,
              scanner: 'npm-audit' as const,
              severity: this.normalizeSeverity(vulnerability.severity),
              file: project.lockPath!,
              line: null,
              vulnerability:
                vulnerabilityDetails.join('; ') || `Vulnerable dependency: ${dependency}`,
              evidence: `${dependency}@${vulnerability.range ?? 'affected version range'}`,
              possibleImpact:
                'The vulnerable dependency may expose applications using it to the advisory-described attack.',
              dependency,
              project: project.directory || '.',
              reference: advisories.find((item) => item.url)?.url,
              advisories: advisories.map((item) => ({
                name: item.name,
                dependency: item.dependency,
                source: item.source,
                title: item.title,
                url: item.url,
                range: item.range,
                severity: item.severity,
                cwe: item.cwe,
                cvss: item.cvss,
              })),
              fixAvailable,
            };
          },
        );
        findings.push(...projectFindings);
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'completed',
          findings: projectFindings.length,
        });
      } catch {
        projectStatuses.push({
          directory: project.directory || '.',
          status: 'failed',
          findings: null,
          message: 'npm audit returned invalid JSON output.',
        });
      }
    }

    const statuses = projectStatuses.map((project) => project.status);
    const hasCompleted = statuses.includes('completed');
    const hasFailed = statuses.includes('failed');
    const hasNonCompleted = statuses.some((item) => item !== 'completed');
    const status: ToolStatus = hasCompleted && hasNonCompleted
      ? 'partial'
      : hasFailed
        ? 'failed'
        : hasCompleted
          ? 'completed'
          : statuses.every((item) => item === 'unavailable')
            ? 'unavailable'
            : statuses.every((item) => item === 'skipped')
              ? 'skipped'
              : 'partial';

    return {
      status,
      findings,
      message: hasFailed
        ? hasCompleted
          ? 'Some npm project audits failed; see per-project statuses.'
          : 'npm project audits failed; see per-project statuses.'
        : hasCompleted && hasNonCompleted
          ? 'Some npm project audits did not complete; see per-project statuses.'
          : undefined,
      projects: projectStatuses,
    };
  }

  private async fetchNpmAuditFile(
    owner: string,
    repository: string,
    path: string,
  ): Promise<NpmAuditFileResult> {
    try {
      const response = await this.github.rest.repos.getContent({
        owner,
        repo: repository,
        path,
      });
      if (
        Array.isArray(response.data) ||
        response.data.type !== 'file' ||
        response.data.encoding !== 'base64' ||
        response.data.size > MAX_FILE_BYTES
      ) {
        return {
          status: 'failed',
          message: 'A project manifest or npm lockfile could not be read.',
        };
      }
      return {
        status: 'completed',
        content: Buffer.from(response.data.content, 'base64').toString('utf8'),
      };
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        return { status: 'skipped', message: 'A project manifest or npm lockfile is missing.' };
      }
      return { status: 'failed', message: 'Unable to retrieve a project manifest or npm lockfile.' };
    }
  }

  private isJsonObject(value: string): boolean {
    try {
      const parsed: unknown = JSON.parse(value);
      return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
    } catch {
      return false;
    }
  }

  private normalizeFixAvailable(value: unknown): NpmFixAvailable | undefined {
    if (typeof value === 'boolean') return value;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;

    const fix = value as Record<string, unknown>;
    return {
      name: typeof fix.name === 'string' ? fix.name : undefined,
      version: typeof fix.version === 'string' ? fix.version : undefined,
      isSemVerMajor: typeof fix.isSemVerMajor === 'boolean' ? fix.isSemVerMajor : undefined,
    };
  }

  private runCommand(
    command: string,
    args: string[],
    cwd: string,
  ): Promise<CommandResult> {
    return new Promise((resolveResult) => {
      const child = spawn(command, args, {
        cwd,
        shell: false,
        windowsHide: true,
      });
      let stdout = '';
      let stderr = '';
      let settled = false;
      const finish = (result: CommandResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolveResult(result);
      };
      const timeout = setTimeout(() => {
        child.kill();
        finish({ code: null, stdout, stderr, error: 'Scanner timed out.' });
      }, TOOL_TIMEOUT_MS);

      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString();
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });
      child.on('error', (error: NodeJS.ErrnoException) => {
        finish({ code: null, stdout, stderr, error: error.code ?? error.message });
      });
      child.on('close', (code) => finish({ code, stdout, stderr }));
    });
  }

  private isCommandUnavailable(result: CommandResult): boolean {
    return (
      result.error === 'ENOENT' ||
      /not found|not recognized as an internal or external command/i.test(
        result.stderr,
      )
    );
  }

  private normalizeSeverity(severity?: string): FindingSeverity {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'error':
      case 'high':
        return 'high';
      case 'warning':
      case 'moderate':
      case 'medium':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'info';
    }
  }

  private severityRank(severity: FindingSeverity): number {
    return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
  }

  private dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
    const seen = new Set<string>();

    return findings.filter((finding) => {
      const key = `${finding.file}:${finding.line ?? 'line'}:${finding.scanner}:${finding.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private summarize(findings: SecurityFinding[]) {
    return findings.reduce(
      (summary, finding) => {
        summary.total += 1;
        summary[finding.severity] += 1;
        return summary;
      },
      { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    );
  }
}
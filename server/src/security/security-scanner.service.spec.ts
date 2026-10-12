import { Octokit } from '@octokit/rest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanHistoryService } from './scan-history.service.js';
import { SecurityScannerService } from './security-scanner.service.js';

type CommandResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
};

type ScannerInternals = {
  runCommand(command: string, args: string[], cwd: string): Promise<CommandResult>;
};

describe('SecurityScannerService npm audit', () => {
  const github = {
    rest: {
      repos: {
        get: vi.fn(),
        getBranch: vi.fn(),
        getContent: vi.fn(),
      },
      git: {
        getCommit: vi.fn(),
        getTree: vi.fn(),
      },
    },
  };
  let service: SecurityScannerService;
  let tree: Array<{ type: string; path: string }>;
  let repositoryFiles: Map<string, string>;
  let runCommand: ReturnType<typeof vi.spyOn>;
  const scanHistory = { save: vi.fn() };

  const addProject = (directory: string, lockName = 'package-lock.json') => {
    const prefix = directory ? `${directory}/` : '';
    const packagePath = `${prefix}package.json`;
    const lockPath = `${prefix}${lockName}`;
    tree.push(
      { type: 'blob', path: packagePath },
      { type: 'blob', path: lockPath },
    );
    repositoryFiles.set(packagePath, JSON.stringify({ name: directory || 'root' }));
    repositoryFiles.set(lockPath, JSON.stringify({ lockfileVersion: 3 }));
  };

  const auditCalls = () =>
    runCommand.mock.calls.filter(([, args]) => args.includes('audit'));
  const semgrepCalls = () =>
    runCommand.mock.calls.filter(([, args]) => args[0] === 'scan');

  beforeEach(() => {
    vi.clearAllMocks();
    scanHistory.save.mockImplementation(async (report) => ({
      ...report,
      id: 'test-history-id',
      findings: report.findings.map(({ evidence: _evidence, ...finding }) => finding),
    }));
    tree = [];
    repositoryFiles = new Map();
    github.rest.repos.get.mockResolvedValue({
      data: { full_name: 'owner/repository', default_branch: 'main' },
    });
    github.rest.repos.getBranch.mockResolvedValue({
      data: { commit: { sha: 'commit-sha' } },
    });
    github.rest.git.getCommit.mockResolvedValue({
      data: { tree: { sha: 'tree-sha' } },
    });
    github.rest.git.getTree.mockImplementation(async () => ({
      data: { tree, truncated: false },
    }));
    github.rest.repos.getContent.mockImplementation(async ({ path }: { path: string }) => {
      const content = repositoryFiles.get(path);
      if (content === undefined) throw { status: 404 };
      return {
        data: {
          type: 'file',
          encoding: 'base64',
          size: Buffer.byteLength(content),
          content: Buffer.from(content).toString('base64'),
        },
      };
    });

    service = new SecurityScannerService(
      github as unknown as Octokit,
      scanHistory as unknown as ScanHistoryService,
    );
    runCommand = vi.spyOn(service as unknown as ScannerInternals, 'runCommand');
    runCommand.mockImplementation(async (_command, args) =>
      args.includes('audit')
        ? { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' },
    );
  });

  it('scans the selected branch and reports it in the result', async () => {
    const result = await service.scan('owner', 'repository', 'feature/security-review');

    expect(github.rest.repos.getBranch).toHaveBeenCalledWith({
      owner: 'owner',
      repo: 'repository',
      branch: 'feature/security-review',
    });
    expect(result.branch).toBe('feature/security-review');
    expect(result.history).toEqual({ id: 'test-history-id', persisted: true });
  });

  it('returns scan data when persistence fails and marks history as unsaved', async () => {
    scanHistory.save.mockRejectedValue(new Error('disk unavailable'));

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.secretDetection.status).toBe('completed');
    expect(result.history).toEqual({
      id: null,
      persisted: false,
      message: 'Scan completed, but the report could not be added to scan history.',
    });
  });

  it('normalizes Semgrep rule, severity, relative path, and optional line details', async () => {
    tree.push({ type: 'blob', path: 'src/handler.ts' });
    repositoryFiles.set('src/handler.ts', 'const safe = true;');
    runCommand.mockImplementation(async (command, args, _cwd) => {
      if (command === 'semgrep') {
        return {
          code: 1,
          stdout: JSON.stringify({
            results: [
              {
                check_id: 'javascript.command-injection',
                path: 'src/handler.ts',
                start: { line: 7 },
                extra: {
                  message: 'Untrusted input reaches a command.',
                  severity: 'ERROR',
                  lines: 'exec(command);',
                  metadata: {
                    impact: 'An attacker may execute commands.',
                    references: ['https://example.test/rule'],
                  },
                },
              },
              {
                check_id: 'javascript.xss-innerhtml',
                path: 'src/handler.ts',
                extra: { message: 'Potential XSS.', severity: 'WARNING' },
              },
            ],
          }),
          stderr: '',
        };
      }
      return args.includes('audit')
        ? { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' };
    });

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.semgrep).toMatchObject({ status: 'completed', findings: 2 });
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'javascript.command-injection',
          scanner: 'semgrep',
          severity: 'high',
          file: 'src/handler.ts',
          line: 7,
          vulnerability: 'Untrusted input reaches a command.',
          reference: 'https://example.test/rule',
        }),
        expect.objectContaining({
          id: 'javascript.xss-innerhtml',
          severity: 'medium',
          file: 'src/handler.ts',
          line: null,
        }),
      ]),
    );
    expect(semgrepCalls()[0][1]).toEqual([
      'scan',
      '--config',
      expect.stringContaining('.semgrep.yml'),
      '--json',
      '--metrics=off',
      expect.any(String),
    ]);
  });

  it('uses the configured Semgrep executable path', async () => {
    const originalPath = process.env.SEMGREP_PATH;
    process.env.SEMGREP_PATH = process.execPath;

    try {
      await service.scan('owner', 'repository');

      expect(semgrepCalls()[0][0]).toBe(process.execPath);
    } finally {
      if (originalPath === undefined) delete process.env.SEMGREP_PATH;
      else process.env.SEMGREP_PATH = originalPath;
    }
  });

  it.each([
    ['JSON string', JSON.stringify('not a Semgrep report')],
    ['JSON number', JSON.stringify(3)],
    ['JSON null', 'null'],
    ['missing results', JSON.stringify({ errors: [] })],
    ['malformed JSON', '{invalid'],
  ])('fails when Semgrep returns %s', async (_case, stdout) => {
    runCommand.mockImplementation(async (command, _args) =>
      command === 'semgrep'
        ? { code: 0, stdout, stderr: '' }
        : { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.semgrep.status).toBe('failed');
    expect(result.scanners.semgrep.findings).toBeNull();
  });

  it('redacts credential evidence before returning Semgrep findings', async () => {
    tree.push({ type: 'blob', path: 'src/handler.ts' });
    repositoryFiles.set('src/handler.ts', 'const safe = true;');
    const token = 'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    runCommand.mockImplementation(async (command, _args) =>
      command === 'semgrep'
        ? {
            code: 1,
            stdout: JSON.stringify({
              results: [{
                check_id: 'javascript.test-secret',
                path: 'src/handler.ts',
                extra: {
                  message: `Credential exposed: ${token}`,
                  lines: `const token = '${token}';`,
                },
              }],
            }),
            stderr: '',
          }
        : { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(JSON.stringify(result)).not.toContain(token);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: 'semgrep',
          vulnerability: expect.not.stringContaining(token),
          evidence: expect.not.stringContaining(token),
        }),
      ]),
    );
  });

  it('counts source files that GitHub could not provide', async () => {
    tree.push({ type: 'blob', path: 'src/unavailable.ts' });

    const result = await service.scan('owner', 'repository');

    expect(result.filesScanned).toBe(0);
    expect(result.sourceFilesSkipped).toBe(1);
  });

  it('fails instead of reporting a finding outside the scan workspace', async () => {
    runCommand.mockImplementation(async (command, _args) =>
      command === 'semgrep'
        ? {
            code: 0,
            stdout: JSON.stringify({
              results: [
                {
                  check_id: 'javascript.test',
                  path: '../outside.ts',
                  extra: { message: 'Unexpected path.' },
                },
              ],
            }),
            stderr: '',
          }
        : { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.semgrep).toMatchObject({ status: 'failed', findings: null });
    expect(result.scanners.semgrep.message).toContain('outside the scan workspace');
  });

  it.each([
    ['missing CLI', { code: null, stdout: '', stderr: '', error: 'ENOENT' }, 'unavailable'],
    ['timeout', { code: null, stdout: '', stderr: '', error: 'Scanner timed out.' }, 'failed'],
    ['command failure', { code: 2, stdout: '', stderr: 'Semgrep failed.' }, 'failed'],
  ])('reports Semgrep %s without crashing the repository scan', async (_case, semgrepResult, status) => {
    runCommand.mockImplementation(async (command, _args) =>
      command === 'semgrep'
        ? semgrepResult
        : { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.semgrep.status).toBe(status);
    expect(result.scanners.semgrep.findings).toBeNull();
    expect(result.scanners.npmAudit.status).toBe('skipped');
    expect(result.summary.total).toBe(0);
  });

  it('audits nested npm projects once and excludes generated directories', async () => {
    addProject('client');
    addProject('client/mobile-store');
    addProject('server');
    tree.push({ type: 'blob', path: 'client/package.json' });
    addProject('server/node_modules/dependency');
    addProject('dist/generated');
    addProject('vendor/library');
    addProject('coverage/output');
    addProject('.git/worktree');

    const result = await service.scan('owner', 'repository');
    const calls = auditCalls();
    const auditDirectories = calls.map(([, , cwd]) => cwd.replaceAll('\\', '/'));

    expect(calls).toHaveLength(3);
    expect(calls.every(([, args]) => args.includes('--ignore-scripts'))).toBe(true);
    expect(auditDirectories.some((cwd) => cwd.endsWith('/client'))).toBe(true);
    expect(auditDirectories.some((cwd) => cwd.endsWith('/client/mobile-store'))).toBe(true);
    expect(auditDirectories.some((cwd) => cwd.endsWith('/server'))).toBe(true);
    const fetchedPaths = github.rest.repos.getContent.mock.calls.map(([request]) => request.path);
    expect(fetchedPaths).not.toContain('server/node_modules/dependency/package.json');
    expect(fetchedPaths).not.toContain('dist/generated/package.json');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({ directory: 'client', status: 'completed' }),
      expect.objectContaining({ directory: 'client/mobile-store', status: 'completed' }),
      expect.objectContaining({ directory: 'server', status: 'completed' }),
    ]);
  });

  it('skips an npm project when its lockfile is missing', async () => {
    tree.push({ type: 'blob', path: 'client/package.json' });
    repositoryFiles.set('client/package.json', '{"name":"client"}');

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('skipped');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({
        directory: 'client',
        status: 'skipped',
        findings: null,
        message: expect.stringContaining('package-lock.json'),
      }),
    ]);
    expect(auditCalls()).toHaveLength(0);
  });

  it('fails safely on a malformed project lockfile without invoking npm', async () => {
    addProject('server');
    repositoryFiles.set('server/package-lock.json', '{invalid');

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('failed');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({ directory: 'server', status: 'failed', findings: null }),
    ]);
    expect(auditCalls()).toHaveLength(0);
  });

  it('aggregates findings with project, advisory, and fix details', async () => {
    addProject('client');
    addProject('server');
    runCommand.mockImplementation(async (_command, args, cwd) => {
      if (!args.includes('audit')) {
        return { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' };
      }
      const output = cwd.replaceAll('\\', '/').endsWith('/client')
        ? {
            vulnerabilities: {
              lodash: {
                severity: 'high',
                range: '<4.17.21',
                via: [
                  {
                    name: 'Prototype Pollution in lodash',
                    dependency: 'lodash',
                    source: 1106913,
                    title: 'Prototype pollution',
                    url: 'https://example.test/advisory',
                    range: '<4.17.21',
                    severity: 'high',
                    cwe: ['CWE-1321'],
                    cvss: { score: 7.2, vectorString: 'CVSS:3.1/AV:N/AC:L' },
                  },
                  { title: 'Command injection', url: 'https://example.test/second-advisory', severity: 'high' },
                ],
                fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
              },
            },
          }
        : {
            vulnerabilities: {
              minimist: {
                severity: 'moderate',
                range: '<1.2.6',
                via: [{ title: 'Prototype pollution', url: 'https://example.test/minimist' }],
                fixAvailable: false,
              },
            },
          };
      return { code: 1, stdout: JSON.stringify(output), stderr: '' };
    });

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('completed');
    expect(result.scanners.npmAudit.findings).toBe(2);
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          dependency: 'lodash',
          project: 'client',
          file: 'client/package-lock.json',
          severity: 'high',
          vulnerability: expect.stringContaining('Command injection'),
          reference: 'https://example.test/advisory',
          advisories: expect.arrayContaining([
            expect.objectContaining({
              source: 1106913,
              cwe: ['CWE-1321'],
              cvss: { score: 7.2, vectorString: 'CVSS:3.1/AV:N/AC:L' },
            }),
          ]),
          fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
        }),
        expect.objectContaining({
          dependency: 'minimist',
          project: 'server',
          file: 'server/package-lock.json',
          severity: 'medium',
          fixAvailable: false,
        }),
      ]),
    );
    expect(result.summary).toMatchObject({ total: 2, high: 1, medium: 1 });
  });

  it('completes with zero findings when vulnerabilities is an empty object', async () => {
    addProject('server');

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit).toMatchObject({
      status: 'completed',
      findings: 0,
      projects: [expect.objectContaining({ directory: 'server', status: 'completed', findings: 0 })],
    });
  });

  it.each([
    ['JSON string', JSON.stringify('not an audit report')],
    ['JSON number', JSON.stringify(42)],
    ['JSON null', 'null'],
    ['missing vulnerabilities', JSON.stringify({ auditReportVersion: 2 })],
    ['malformed JSON', '{invalid'],
  ])('fails when npm audit returns %s', async (_case, stdout) => {
    addProject('server');
    runCommand.mockImplementation(async (_command, args) =>
      args.includes('audit')
        ? { code: 0, stdout, stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('failed');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({ directory: 'server', status: 'failed' }),
    ]);
    expect(result.findings).toEqual([]);
  });

  it('reports command failures per project without returning command output', async () => {
    addProject('client');
    addProject('server');
    runCommand.mockImplementation(async (_command, args) =>
      args.includes('audit') && auditCalls().length === 1
        ? { code: 2, stdout: '{"error":true}', stderr: 'private registry details' }
        : args.includes('audit')
          ? { code: 0, stdout: JSON.stringify({ vulnerabilities: {} }), stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('partial');
    expect(result.scanners.npmAudit.findings).toBeNull();
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({ directory: 'client', status: 'failed', findings: null }),
      expect.objectContaining({ directory: 'server', status: 'completed', findings: 0 }),
    ]);
    expect(JSON.stringify(result)).not.toContain('private registry details');
  });

  it('reports lockfile absence separately and does not count skipped findings as zero', async () => {
    tree.push(
      { type: 'blob', path: 'client/package.json' },
      { type: 'blob', path: 'server/package-lock.json' },
    );
    repositoryFiles.set('client/package.json', '{"name":"client"}');
    repositoryFiles.set('server/package-lock.json', '{"lockfileVersion":3}');

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({
        directory: 'client',
        status: 'skipped',
        findings: null,
        message: expect.stringContaining('lockfile'),
      }),
      expect.objectContaining({
        directory: 'server',
        status: 'skipped',
        findings: null,
        message: expect.stringContaining('package.json'),
      }),
    ]);
    expect(result.scanners.npmAudit.status).toBe('skipped');
    expect(result.scanners.npmAudit.findings).toBeNull();
    expect(auditCalls()).toHaveLength(0);
  });

  it('reports npm as unavailable when the executable cannot be found', async () => {
    addProject('server');
    runCommand.mockImplementation(async (_command, args) =>
      args.includes('audit')
        ? { code: null, stdout: '', stderr: '', error: 'ENOENT' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('unavailable');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({ directory: 'server', status: 'unavailable' }),
    ]);
  });

  it('reports audit timeouts as failed without leaking command output', async () => {
    addProject('server');
    runCommand.mockImplementation(async (_command, args) =>
      args.includes('audit')
        ? { code: null, stdout: '', stderr: 'partial private output', error: 'Scanner timed out.' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' },
    );

    const result = await service.scan('owner', 'repository');

    expect(result.scanners.npmAudit.status).toBe('failed');
    expect(result.scanners.npmAudit.projects).toEqual([
      expect.objectContaining({
        directory: 'server',
        status: 'failed',
        message: 'npm audit timed out.',
      }),
    ]);
    expect(JSON.stringify(result)).not.toContain('partial private output');
  });
});

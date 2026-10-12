import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

const repositoriesPage = {
  repositories: [
    {
      id: 1,
      name: 'public-ui',
      fullName: 'octocat/public-ui',
      description: 'Public client application',
      visibility: 'public',
      primaryLanguage: 'TypeScript',
      defaultBranch: 'main',
      htmlUrl: 'https://github.com/octocat/public-ui',
      isPrivate: false,
    },
    {
      id: 2,
      name: 'private-api',
      fullName: 'octocat/private-api',
      description: 'Private service',
      visibility: 'private',
      primaryLanguage: 'TypeScript',
      defaultBranch: 'main',
      htmlUrl: 'https://github.com/octocat/private-api',
      isPrivate: true,
    },
  ],
  pagination: { page: 1, perPage: 100, hasNextPage: false, hasPreviousPage: false },
};

const scanReport = {
  repository: 'octocat/private-api',
  branch: 'release',
  scannedAt: '2026-10-11T12:00:00.000Z',
  filesScanned: 12,
  sourceFilesSkipped: 0,
  sourceFileLimit: 100,
  sourceFilesTruncated: false,
  treeTruncated: false,
  scanners: {
    semgrep: { status: 'unavailable', findings: null, message: 'Semgrep CLI is missing.' },
    npmAudit: {
      status: 'completed',
      findings: 1,
      message: null,
      projects: [{ directory: 'server', status: 'completed', findings: 1 }],
    },
    secretDetection: { status: 'completed', findings: 0 },
  },
  summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
  findings: [
    {
      id: 'npm-audit:proxy-addr',
      scanner: 'npm-audit',
      severity: 'critical',
      file: 'server/package-lock.json',
      line: null,
      vulnerability: 'IP spoofing vulnerability',
      evidence: 'proxy-addr@1.1.0 - 2.0.7',
      possibleImpact: 'May allow spoofed client addresses.',
      dependency: 'proxy-addr',
      project: 'server',
      reference: 'https://github.com/advisories/example',
      fixAvailable: { name: 'proxy-addr', version: '2.0.8', isSemVerMajor: false },
    },
  ],
};

function response(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

describe('Security dashboard', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/repositories?')) return response(repositoriesPage);
      if (url.includes('/scan-history?')) return response({ records: [], count: 0 });
      if (url.endsWith('/branches')) {
        return response([
          { name: 'main', default: true, protected: true, commitSha: 'sha-main' },
          { name: 'release', default: false, protected: false, commitSha: 'sha-release' },
        ]);
      }
      if (url.endsWith('/scan')) return response(scanReport);
      return response({}, 404);
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('filters repositories, selects a branch, and displays real scan findings', async () => {
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole('option', { name: 'octocat/public-ui · public' });
    await user.click(screen.getByRole('button', { name: 'Private' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Repository' }), 'octocat/private-api');
    await screen.findByRole('option', { name: 'release' });
    await user.selectOptions(screen.getByRole('combobox', { name: 'Branch' }), 'release');
    await user.click(screen.getByRole('button', { name: 'Scan repository' }));

    expect(await screen.findByText('IP spoofing vulnerability')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Critical' })).toBeInTheDocument();
    expect(screen.getByText('Semgrep: unavailable')).toBeInTheDocument();
    expect(screen.getByText('Suggested fix: proxy-addr 2.0.8')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/repositories/octocat/private-api/scan',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ branch: 'release' }),
      }),
    );
  });

  it('shows an empty scan and unavailable scanner state without inventing findings', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/repositories?')) return response(repositoriesPage);
      if (url.includes('/scan-history?')) return response({ records: [], count: 0 });
      if (url.endsWith('/branches')) {
        return response([{ name: 'main', default: true, protected: false, commitSha: null }]);
      }
      if (url.endsWith('/scan')) {
        return response({
          ...scanReport,
          findings: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanners: {
            ...scanReport.scanners,
              npmAudit: {
              status: 'partial',
              findings: null,
                message: 'Some npm project audits did not run.',
                projects: [
                  { directory: 'client', status: 'skipped', findings: null, message: 'No lockfile.' },
                  { directory: 'server', status: 'skipped', findings: null, message: 'No lockfile.' },
                ],
              },
          },
        });
      }
      return response({}, 404);
    });
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole('option', { name: 'octocat/public-ui · public' });
    await user.click(screen.getByRole('button', { name: 'Scan repository' }));

    expect(await screen.findByText('No findings in this scan')).toBeInTheDocument();
    expect(screen.getByText('Semgrep: unavailable')).toBeInTheDocument();
    expect(screen.getByText('npm audit: partial')).toBeInTheDocument();
    expect(screen.getByText('Partial scan')).toBeInTheDocument();
    expect(screen.getByText('client: skipped · not counted')).toBeInTheDocument();
    expect(screen.getByText('Partial coverage: Semgrep unavailable · 2 npm project audits did not complete.')).toBeInTheDocument();
    expect(screen.getByText('No findings were reported by completed scanners.')).toBeInTheDocument();
  });

  it('marks truncated repository scans as partial even when scanners complete', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/repositories?')) return response(repositoriesPage);
      if (url.includes('/scan-history?')) return response({ records: [], count: 0 });
      if (url.endsWith('/branches')) {
        return response([{ name: 'main', default: true, protected: false, commitSha: null }]);
      }
      if (url.endsWith('/scan')) {
        return response({
          ...scanReport,
          treeTruncated: true,
          findings: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          scanners: {
            semgrep: { status: 'completed', findings: 0, message: null },
            npmAudit: { status: 'completed', findings: 0, message: null, projects: [] },
            secretDetection: { status: 'completed', findings: 0 },
          },
        });
      }
      return response({}, 404);
    });
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole('option', { name: 'octocat/public-ui · public' });
    await user.click(screen.getByRole('button', { name: 'Scan repository' }));

    expect(await screen.findByText('Partial scan')).toBeInTheDocument();
    expect(screen.getByText('Partial coverage: GitHub truncated the repository tree.')).toBeInTheDocument();
    expect(screen.getByText('No findings in this scan')).toBeInTheDocument();
  });

  it('explains the server-side GitHub token dependency when repository listing is unauthorized', async () => {
    fetchMock.mockResolvedValue(response({ message: 'Unauthorized' }, 401));
    render(<App />);

    expect(await screen.findByRole('alert')).toHaveTextContent('server-side GITHUB_TOKEN');
    expect(screen.getByText('API unavailable')).toBeInTheDocument();
  });

  it('loads a persisted scan from backend history without source evidence', async () => {
    const { evidence: _evidence, ...safeFinding } = scanReport.findings[0];
    const savedRecord = {
      ...scanReport,
      id: 'saved-scan-1',
      findings: [safeFinding],
    };
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/repositories?')) return response(repositoriesPage);
      if (url.includes('/scan-history?')) return response({ records: [savedRecord], count: 1 });
      if (url.endsWith('/branches')) {
        return response([{ name: 'main', default: true, protected: false, commitSha: null }]);
      }
      return response({}, 404);
    });
    const user = userEvent.setup();
    render(<App />);

    await user.selectOptions(await screen.findByRole('combobox', { name: 'Recent scan history' }), 'saved-scan-1');

    expect(await screen.findByText('IP spoofing vulnerability')).toBeInTheDocument();
    expect(screen.getByText('Partial scan')).toBeInTheDocument();
    expect(screen.getByText('Semgrep: unavailable')).toBeInTheDocument();
  });

  it('shows scan API failures instead of a success state', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/repositories?')) return response(repositoriesPage);
      if (url.includes('/scan-history?')) return response({ records: [], count: 0 });
      if (url.endsWith('/branches')) {
        return response([{ name: 'main', default: true, protected: false, commitSha: null }]);
      }
      if (url.endsWith('/scan')) return response({}, 502);
      return response({}, 404);
    });
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole('option', { name: 'octocat/public-ui · public' });
    await user.click(screen.getByRole('button', { name: 'Scan repository' }));

    expect(await screen.findByText('Scan request failed')).toBeInTheDocument();
    expect(screen.getByText('Request failed with HTTP 502.')).toBeInTheDocument();
    expect(screen.queryByText('No findings in this scan')).not.toBeInTheDocument();
  });

  it('loads another repository page when load more is selected', async () => {
    fetchMock.mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('/scan-history?')) return response({ records: [], count: 0 });
      if (url.includes('page=1')) {
        return response({
          ...repositoriesPage,
          repositories: repositoriesPage.repositories.slice(0, 1),
          pagination: { ...repositoriesPage.pagination, hasNextPage: true },
        });
      }
      if (url.includes('page=2')) {
        return response({
          ...repositoriesPage,
          repositories: [repositoriesPage.repositories[1]],
          pagination: { ...repositoriesPage.pagination, page: 2, hasNextPage: false },
        });
      }
      if (url.endsWith('/branches')) {
        return response([{ name: 'main', default: true, protected: false, commitSha: null }]);
      }
      return response({}, 404);
    });
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole('option', { name: 'octocat/public-ui · public' });
    await user.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByRole('option', { name: 'octocat/private-api · private' })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/repositories?page=2&perPage=100', expect.anything());
  });
});

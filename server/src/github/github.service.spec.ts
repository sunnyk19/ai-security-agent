import { Octokit } from '@octokit/rest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { GitHubService } from './github.service.js';

describe('GitHubService', () => {
  const github = {
    paginate: vi.fn(),
    rest: {
      repos: {
        get: vi.fn(),
        getBranch: vi.fn(),
        listLanguages: vi.fn(),
        getContent: vi.fn(),
        listForAuthenticatedUser: vi.fn(),
        listBranches: vi.fn(),
      },
      git: {
        getCommit: vi.fn(),
        getTree: vi.fn(),
      },
    },
  };
  let service: GitHubService;

  beforeEach(() => {
    vi.clearAllMocks();
    github.rest.repos.get.mockResolvedValue({
      data: {
        full_name: 'nestjs/nest',
        html_url: 'https://github.com/nestjs/nest',
        name: 'nest',
        description: 'A progressive Node.js framework',
        default_branch: 'master',
        private: false,
        stargazers_count: 70000,
        forks_count: 12000,
        language: 'TypeScript',
        license: { spdx_id: 'MIT' },
        topics: ['nodejs'],
        updated_at: '2026-01-01T00:00:00Z',
      },
    });
    github.rest.repos.getBranch.mockResolvedValue({
      data: { commit: { sha: 'commit-sha' } },
    });
    github.rest.repos.listLanguages.mockResolvedValue({
      data: { TypeScript: 5000 },
    });
    github.paginate.mockResolvedValue([{ name: 'main' }]);
    github.rest.git.getCommit.mockResolvedValue({
      data: { tree: { sha: 'tree-sha' } },
    });
    github.rest.git.getTree.mockResolvedValue({
      data: {
        truncated: false,
        tree: [
          { type: 'blob', path: 'package.json' },
          { type: 'blob', path: 'pnpm-lock.yaml' },
          { type: 'blob', path: 'README.md' },
          { type: 'tree', path: 'integration' },
          { type: 'blob', path: 'integration/main.ts' },
          { type: 'tree', path: 'sample' },
          { type: 'blob', path: 'sample/main.ts' },
          { type: 'tree', path: 'src' },
          { type: 'blob', path: 'src/main.ts' },
          { type: 'tree', path: 'src/modules' },
          { type: 'blob', path: 'src/modules/github.service.ts' },
          { type: 'tree', path: 'packages/core/src' },
          { type: 'blob', path: 'packages/core/src/index.ts' },
        ],
      },
    });
    github.rest.repos.getContent.mockImplementation(
      () =>
        Promise.resolve({
          data: {
            type: 'file',
            encoding: 'base64',
            content: Buffer.from(
              JSON.stringify({
                name: '@nestjs/core',
                version: '12.0.0',
                dependencies: { '@octokit/rest': '^22.0.0' },
                devDependencies: { typescript: '^6.0.0' },
                peerDependencies: { express: '^5.0.0' },
                optionalDependencies: { fsevents: '^2.0.0' },
              }),
            ).toString('base64'),
          },
        }),
    );
    service = new GitHubService(github as unknown as Octokit);
  });

  it('reads repository files and detects basic project information', async () => {
    const result = await service.analyze('nestjs', 'nest');

    expect(result.repository.fullName).toBe('nestjs/nest');
    expect(result.files).toContain('src/modules/github.service.ts');
    expect(result.folderStructure).toEqual([
      'integration',
      'packages/core/src',
      'sample',
      'src',
      'src/modules',
    ]);
    expect(result.importantSourceFiles[0]).toBe('packages/core/src/index.ts');
    expect(result.packageJson).toMatchObject({
      name: '@nestjs/core',
      version: '12.0.0',
    });
    expect(result.dependencies).toEqual({
      production: { '@octokit/rest': '^22.0.0' },
      development: { typescript: '^6.0.0' },
      peer: { express: '^5.0.0' },
      optional: { fsevents: '^2.0.0' },
    });
    expect(result.project).toMatchObject({
      name: '@nestjs/core',
      version: '12.0.0',
      languages: ['TypeScript'],
      frameworks: ['NestJS'],
      packageManager: 'pnpm',
      manifests: ['package.json'],
    });
    expect(github.rest.repos.getContent).toHaveBeenCalledWith({
      owner: 'nestjs',
      repo: 'nest',
      path: 'package.json',
    });
  });

  it('lists repositories for the authenticated user with repository metadata', async () => {
    github.rest.repos.listForAuthenticatedUser.mockResolvedValue({
      data: [
        {
          full_name: 'octocat/hello-world',
          name: 'hello-world',
          description: 'A demo repository',
          private: false,
          visibility: 'public',
          language: 'TypeScript',
          default_branch: 'main',
          html_url: 'https://github.com/octocat/hello-world',
        },
        {
          full_name: 'octocat/secret-tooling',
          name: 'secret-tooling',
          description: 'Private tooling',
          private: true,
          visibility: 'private',
          language: 'Go',
          default_branch: 'develop',
          html_url: 'https://github.com/octocat/secret-tooling',
        },
      ],
      headers: { link: '<https://api.github.com/user/repos?page=2>; rel="next"' },
    });

    const result = await service.listRepositories({ page: 1, perPage: 30 });

    expect(result.repositories).toHaveLength(2);
    expect(result.repositories[0]).toMatchObject({
      fullName: 'octocat/hello-world',
      visibility: 'public',
      primaryLanguage: 'TypeScript',
      defaultBranch: 'main',
    });
    expect(result.pagination).toMatchObject({
      page: 1,
      perPage: 30,
      hasNextPage: true,
    });
    expect(github.rest.repos.listForAuthenticatedUser).toHaveBeenCalledWith(
      expect.objectContaining({
        visibility: 'all',
        affiliation: 'owner,collaborator,organization_member',
      }),
    );
  });

  it('fetches available branches and a branch-specific tree for the selected repository', async () => {
    github.rest.repos.get.mockResolvedValue({
      data: {
        full_name: 'octocat/hello-world',
        name: 'hello-world',
        html_url: 'https://github.com/octocat/hello-world',
        default_branch: 'main',
        private: false,
      },
    });
    github.paginate.mockResolvedValue([
      { name: 'main', protected: true, commit: { sha: 'main-sha' } },
      { name: 'feature/branch-selection', protected: false, commit: { sha: 'branch-sha' } },
    ]);
    github.rest.repos.getBranch.mockResolvedValue({
      data: { name: 'feature/branch-selection', commit: { sha: 'branch-sha' } },
    });
    github.rest.git.getCommit.mockResolvedValue({
      data: { tree: { sha: 'tree-sha-branch' } },
    });
    github.rest.git.getTree.mockResolvedValue({
      data: {
        truncated: false,
        tree: [
          { type: 'blob', path: 'README.md' },
          { type: 'tree', path: 'src' },
          { type: 'blob', path: 'src/index.ts' },
        ],
      },
    });

    const branches = await service.getBranches('octocat', 'hello-world');
    const tree = await service.getRepositoryTree('octocat', 'hello-world', 'feature/branch-selection');

    expect(branches).toMatchObject([
      { name: 'main', default: true },
      { name: 'feature/branch-selection', default: false },
    ]);
    expect(tree.branch).toBe('feature/branch-selection');
    expect(tree.files).toEqual(['README.md', 'src/index.ts']);
    expect(github.rest.repos.getBranch).toHaveBeenCalledWith({
      owner: 'octocat',
      repo: 'hello-world',
      branch: 'feature/branch-selection',
    });
    expect(github.paginate).toHaveBeenCalledWith(
      github.rest.repos.listBranches,
      { owner: 'octocat', repo: 'hello-world', per_page: 100 },
    );
  });

  it('reports repositories that GitHub cannot find', async () => {
    github.rest.repos.get.mockRejectedValue({ status: 404 });
    github.rest.repos.getBranch.mockRejectedValue({ status: 404 });
    github.rest.repos.getContent.mockRejectedValue({ status: 404 });

    await expect(service.analyze('missing', 'repository')).rejects.toMatchObject({
      status: 404,
    });
  });
});
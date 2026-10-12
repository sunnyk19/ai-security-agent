import {
  BadGatewayException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Octokit } from '@octokit/rest';
import { GITHUB_CLIENT } from './github.tokens.js';

type RepositoryListItem = {
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

type BranchSummary = {
  name: string;
  default: boolean;
  protected: boolean;
  commitSha: string | null;
};

type PackageManifest = {
  name?: string;
  description?: string;
  version?: string;
  packageManager?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

const KNOWN_MANIFESTS = new Set([
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'setup.py',
  'go.mod',
  'Cargo.toml',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'composer.json',
  'Gemfile',
]);
const SOURCE_FILE_PATTERN = /\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|php|rb|cs|c|h|cpp|hpp|swift|scala)$/i;
const ENTRYPOINT_PATTERN = /(^|\/)(main|index|app|server|manage|cli)\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|php|rb|cs)$/i;

@Injectable()
export class GitHubService {
  constructor(@Inject(GITHUB_CLIENT) private readonly github: Octokit) {}

  async listRepositories(options: {
    page?: number;
    perPage?: number;
    query?: string;
  } = {}) {
    const page = this.normalizePositiveInteger(options.page, 1);
    const perPage = this.clampPositiveInteger(options.perPage, 30, 100);
    const query = options.query?.trim().toLowerCase();

    try {
      const response = await this.github.rest.repos.listForAuthenticatedUser({
        page,
        per_page: perPage,
        sort: 'updated',
        direction: 'desc',
        visibility: 'all',
        affiliation: 'owner,collaborator,organization_member',
      });

      const repositories = (response.data ?? [])
        .filter((repository) => {
          if (!query) return true;
          const haystack = [
            repository.full_name,
            repository.name,
            repository.description ?? '',
            repository.language ?? '',
          ]
            .join(' ')
            .toLowerCase();
          return haystack.includes(query);
        })
        .map((repository) => ({
          id: repository.id ?? null,
          name: repository.name,
          fullName: repository.full_name,
          description: repository.description ?? null,
          visibility: this.normalizeVisibility(repository.visibility),
          primaryLanguage: repository.language ?? null,
          defaultBranch: repository.default_branch,
          htmlUrl: repository.html_url,
          isPrivate: repository.private,
        } satisfies RepositoryListItem));

      return {
        repositories,
        pagination: {
          page,
          perPage,
          hasNextPage: this.hasNextPage(response.headers?.link ?? ''),
          hasPreviousPage: page > 1,
        },
      };
    } catch (error) {
      const status = (error as { status?: number }).status;
      if (status === 401 || status === 403) {
        throw new UnauthorizedException(
          'GitHub authentication is required to list repositories for the authenticated user.',
        );
      }
      throw new BadGatewayException('Unable to list repositories from GitHub.');
    }
  }

  async getRepositoryMetadata(owner: string, repository: string) {
    try {
      const repositoryResponse = await this.github.rest.repos.get({
        owner,
        repo: repository,
      });
      const repositoryData = repositoryResponse.data;

      return {
        fullName: repositoryData.full_name,
        name: repositoryData.name,
        description: repositoryData.description,
        defaultBranch: repositoryData.default_branch,
        isPrivate: repositoryData.private,
        htmlUrl: repositoryData.html_url,
        visibility: this.normalizeVisibility(repositoryData.visibility),
        primaryLanguage: repositoryData.language ?? null,
        owner,
        repository,
      };
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        throw new NotFoundException(
          `Repository ${owner}/${repository} was not found or is not accessible.`,
        );
      }
      throw new BadGatewayException('Unable to read repository data from GitHub.');
    }
  }

  async getBranches(owner: string, repository: string) {
    try {
      const repositoryData = await this.getRepositoryMetadata(owner, repository);
      const branchesResponse = await this.github.rest.repos.listBranches({
        owner,
        repo: repository,
        per_page: 100,
      });

      return (branchesResponse.data ?? []).map((branch) => ({
        name: branch.name,
        default: branch.name === repositoryData.defaultBranch,
        protected: Boolean(branch.protected),
        commitSha: branch.commit?.sha ?? null,
      })) satisfies BranchSummary[];
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        throw new NotFoundException(
          `Repository ${owner}/${repository} was not found or is not accessible.`,
        );
      }
      throw new BadGatewayException('Unable to read repository branches from GitHub.');
    }
  }

  async getRepositoryTree(owner: string, repository: string, branch?: string, path = '') {
    try {
      const repositoryData = await this.getRepositoryMetadata(owner, repository);
      const branchName = branch?.trim() || repositoryData.defaultBranch;
      const branchResponse = await this.github.rest.repos.getBranch({
        owner,
        repo: repository,
        branch: branchName,
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

      const normalizedPath = path.trim().replace(/^\/+|\/+$/g, '');
      const entries = treeResponse.data.tree ?? [];
      const filteredEntries = normalizedPath
        ? entries.filter(
            (entry) =>
              entry.path === normalizedPath ||
              entry.path.startsWith(`${normalizedPath}/`),
          )
        : entries;

      const files = filteredEntries
        .filter((entry) => entry.type === 'blob')
        .map((entry) => entry.path)
        .sort();
      const folders = filteredEntries
        .filter((entry) => entry.type === 'tree')
        .map((entry) => entry.path)
        .sort();

      return {
        repository: repositoryData.fullName,
        branch: branchName,
        defaultBranch: repositoryData.defaultBranch,
        path: normalizedPath || null,
        files,
        folders,
        treeTruncated: treeResponse.data.truncated,
      };
    } catch (error) {
      const status = (error as { status?: number }).status;
      if (status === 404) {
        throw new NotFoundException(
          `Repository ${owner}/${repository} was not found or is not accessible.`,
        );
      }
      throw new BadGatewayException('Unable to read the repository tree from GitHub.');
    }
  }

  async analyze(owner: string, repository: string) {
    try {
      const repositoryResponse = await this.github.rest.repos.get({
        owner,
        repo: repository,
      });
      const repositoryData = repositoryResponse.data;
      const [languagesResponse, branchResponse] = await Promise.all([
        this.github.rest.repos.listLanguages({ owner, repo: repository }),
        this.github.rest.repos.getBranch({
          owner,
          repo: repository,
          branch: repositoryData.default_branch,
        }),
      ]);
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
      const treeEntries = treeResponse.data.tree;
      const files = treeEntries
        .filter((entry) => entry.type === 'blob')
        .map((entry) => entry.path)
        .sort();
      const folders = treeEntries
        .filter((entry) => entry.type === 'tree')
        .map((entry) => entry.path)
        .sort();
      const manifest = await this.readPackageManifest(owner, repository, files);
      const allFiles = new Set(files);
      const manifests = this.detectManifests(files);
      const manifestNames = new Set(
        manifests.map((file) => file.split('/').pop() ?? file),
      );
      const languages = new Set(Object.keys(languagesResponse.data));

      if (allFiles.has('package.json') && !languages.has('TypeScript')) {
        languages.add('JavaScript');
      }
      if (
        ['requirements.txt', 'pyproject.toml', 'setup.py'].some((file) =>
          manifestNames.has(file),
        )
      ) {
        languages.add('Python');
      }
      if (manifestNames.has('go.mod')) languages.add('Go');
      if (manifestNames.has('Cargo.toml')) languages.add('Rust');
      if (manifestNames.has('pom.xml') || manifestNames.has('build.gradle')) {
        languages.add('Java');
      }
      if (allFiles.has('build.gradle.kts')) languages.add('Kotlin');
      if (manifestNames.has('composer.json')) languages.add('PHP');
      if (manifestNames.has('Gemfile')) languages.add('Ruby');
      if (files.some((file) => file.endsWith('.sln') || file.endsWith('.csproj'))) {
        languages.add('C#');
      }

      return {
        repository: {
          fullName: repositoryData.full_name,
          url: repositoryData.html_url,
          description: repositoryData.description,
          defaultBranch: repositoryData.default_branch,
          isPrivate: repositoryData.private,
          stars: repositoryData.stargazers_count,
          forks: repositoryData.forks_count,
          license: repositoryData.license?.spdx_id ?? null,
          topics: repositoryData.topics,
          updatedAt: repositoryData.updated_at,
        },
        folderStructure: folders,
        files,
        importantSourceFiles: this.detectImportantSourceFiles(files),
        packageJson: manifest,
        dependencies: {
          production: manifest?.dependencies ?? {},
          development: manifest?.devDependencies ?? {},
          peer: manifest?.peerDependencies ?? {},
          optional: manifest?.optionalDependencies ?? {},
        },
        treeTruncated: treeResponse.data.truncated,
        project: {
          name: manifest?.name ?? repositoryData.name,
          description: manifest?.description ?? repositoryData.description,
          version: manifest?.version ?? null,
          languages: [...languages],
          frameworks: this.detectFrameworks(manifest),
          packageManager: this.detectPackageManager(manifest, allFiles),
          manifests,
        },
      };
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        throw new NotFoundException(
          `Repository ${owner}/${repository} was not found or is not accessible.`,
        );
      }
      throw new BadGatewayException('Unable to read repository data from GitHub.');
    }
  }

  private normalizeVisibility(
    visibility?: string | null,
  ): 'public' | 'private' | 'internal' {
    if (visibility === 'private') return 'private';
    if (visibility === 'internal') return 'internal';
    return 'public';
  }

  private normalizePositiveInteger(
    value: number | undefined,
    fallback: number,
  ): number {
    if (value === undefined || !Number.isInteger(value) || value <= 0) {
      return fallback;
    }
    return value;
  }

  private clampPositiveInteger(
    value: number | undefined,
    fallback: number,
    maxValue: number,
  ): number {
    const normalized = this.normalizePositiveInteger(value, fallback);
    return Math.min(normalized, maxValue);
  }

  private hasNextPage(linkHeader: string) {
    return /rel="next"/i.test(linkHeader);
  }

  private async readPackageManifest(
    owner: string,
    repository: string,
    files: string[],
  ): Promise<PackageManifest | null> {
    if (!files.includes('package.json')) return null;

    try {
      const response = await this.github.rest.repos.getContent({
        owner,
        repo: repository,
        path: 'package.json',
      });
      if (
        Array.isArray(response.data) ||
        response.data.type !== 'file' ||
        response.data.encoding !== 'base64'
      ) {
        return null;
      }
      return JSON.parse(
        Buffer.from(response.data.content, 'base64').toString('utf8'),
      ) as PackageManifest;
    } catch {
      return null;
    }
  }

  private detectFrameworks(manifest: PackageManifest | null): string[] {
    const dependencies = {
      ...manifest?.dependencies,
      ...manifest?.devDependencies,
    };
    const frameworkPackages: Record<string, string> = {
      '@nestjs/core': 'NestJS',
      '@angular/core': 'Angular',
      next: 'Next.js',
      react: 'React',
      vue: 'Vue',
      express: 'Express',
      fastify: 'Fastify',
      svelte: 'Svelte',
    };

    const frameworks = new Set(
      Object.entries(frameworkPackages)
      .filter(([dependency]) => dependency in dependencies)
      .map(([, framework]) => framework),
    );
    if (manifest?.name?.startsWith('@nestjs/')) frameworks.add('NestJS');
    return [...frameworks];
  }

  private detectPackageManager(
    manifest: PackageManifest | null,
    files: Set<string>,
  ): string | null {
    if (manifest?.packageManager) {
      return manifest.packageManager.split('@')[0];
    }
    if (files.has('pnpm-lock.yaml')) return 'pnpm';
    if (files.has('yarn.lock')) return 'yarn';
    if (files.has('bun.lockb') || files.has('bun.lock')) return 'bun';
    if (files.has('package-lock.json')) return 'npm';
    return null;
  }

  private detectManifests(files: string[]): string[] {
    return files.filter((file) => {
      const basename = file.split('/').pop() ?? file;
      return (
        KNOWN_MANIFESTS.has(basename) ||
        basename.endsWith('.sln') ||
        basename.endsWith('.csproj')
      );
    });
  }

  private detectImportantSourceFiles(files: string[]): string[] {
    return files
      .filter((file) => SOURCE_FILE_PATTERN.test(file))
      .sort((left, right) => {
        const rank = (file: string) => {
          const excluded = /(^|\/)(integration|test|tests|__tests__|examples?|samples?|fixtures?)\//i.test(
            file,
          );
          if (excluded) return 3;
          const packageSource = /^packages\//i.test(file);
          if (packageSource && ENTRYPOINT_PATTERN.test(file)) return 0;
          if (packageSource) return 1;
          const inSourceDirectory = /(^|\/)src\//i.test(file);
          if (inSourceDirectory && ENTRYPOINT_PATTERN.test(file)) return 2;
          if (inSourceDirectory) return 3;
          if (ENTRYPOINT_PATTERN.test(file)) return 4;
          return 5;
        };
        return rank(left) - rank(right) || left.localeCompare(right);
      })
      .slice(0, 30);
  }
}
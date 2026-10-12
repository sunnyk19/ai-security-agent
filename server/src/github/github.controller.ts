import { Controller, Get, Param, Query } from '@nestjs/common';
import { GitHubService } from './github.service.js';

@Controller('repositories')
export class GitHubController {
  constructor(private readonly githubService: GitHubService) {}

  @Get()
  listAuthenticatedRepositories(
    @Query('page') page?: string,
    @Query('perPage') perPage?: string,
    @Query('query') query?: string,
  ) {
    return this.githubService.listRepositories({
      page: page ? Number(page) : undefined,
      perPage: perPage ? Number(perPage) : undefined,
      query,
    });
  }

  @Get('test')
  analyzeTestRepository() {
    const owner = process.env.TEST_REPOSITORY_OWNER ?? 'nestjs';
    const repository = process.env.TEST_REPOSITORY_NAME ?? 'nest';
    return this.githubService.analyze(owner, repository);
  }

  @Get(':owner/:repository')
  getRepositoryMetadata(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
  ) {
    return this.githubService.getRepositoryMetadata(owner, repository);
  }

  @Get(':owner/:repository/branches')
  getRepositoryBranches(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
  ) {
    return this.githubService.getBranches(owner, repository);
  }

  @Get(':owner/:repository/tree')
  getRepositoryTree(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
    @Query('branch') branch?: string,
    @Query('path') path?: string,
  ) {
    return this.githubService.getRepositoryTree(owner, repository, branch, path);
  }

  @Get(':owner/:repository/analyze')
  analyzeRepository(
    @Param('owner') owner: string,
    @Param('repository') repository: string,
  ) {
    return this.githubService.analyze(owner, repository);
  }
}
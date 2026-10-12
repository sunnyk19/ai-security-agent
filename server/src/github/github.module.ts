import { Module } from '@nestjs/common';
import { Octokit } from '@octokit/rest';
import { GitHubController } from './github.controller.js';
import { GITHUB_CLIENT } from './github.tokens.js';
import { GitHubService } from './github.service.js';

@Module({
  controllers: [GitHubController],
  providers: [
    {
      provide: GITHUB_CLIENT,
      useFactory: () => {
        const githubToken = process.env.GITHUB_TOKEN?.trim();

        return new Octokit({
          ...(githubToken ? { auth: githubToken } : {}),
          userAgent: 'ai-security-agent',
          request: {
            timeout: 15000,
            retries: 2,
          },
        });
      },
    },
    GitHubService,
  ],
  exports: [GITHUB_CLIENT],
})
export class GitHubModule {}

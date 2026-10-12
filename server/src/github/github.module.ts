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

        if (!githubToken) {
          throw new Error(
            'GITHUB_TOKEN is required. Configure it in your environment or .env without committing the secret value.',
          );
        }

        return new Octokit({
          auth: githubToken,
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
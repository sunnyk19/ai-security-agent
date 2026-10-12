import { ServiceUnavailableException } from '@nestjs/common';
import { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiAnalysisService } from './ai-analysis.service.js';
import type { SecurityFinding } from '../security/security.types.js';

describe('AiAnalysisService', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it('requires an AI provider key without contacting GitHub', async () => {
    vi.stubEnv('OPENAI_API_KEY', '');
    const github = {
      rest: { repos: { get: vi.fn(), getContent: vi.fn() } },
    };
    const service = new AiAnalysisService(github as unknown as Octokit);
    const finding: SecurityFinding = {
      id: 'test-finding',
      scanner: 'semgrep',
      severity: 'high',
      file: 'src/user.service.ts',
      line: 10,
      vulnerability: 'SQL injection',
      evidence: 'query concatenates input',
      possibleImpact: 'An attacker could read protected records.',
    };

    await expect(
      service.analyze('owner', 'repository', finding),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(github.rest.repos.get).not.toHaveBeenCalled();
  });

  it('redacts secrets and returns structured analysis from the configured provider', async () => {
    vi.stubEnv('OPENAI_API_KEY', 'unit-test-key');
    const github = {
      rest: {
        repos: {
          get: vi.fn().mockResolvedValue({
            data: {
              full_name: 'owner/repository',
              description: 'Test project',
              language: 'TypeScript',
            },
          }),
          getContent: vi.fn().mockImplementation(({ path }: { path: string }) =>
            Promise.resolve({
              data: {
                type: 'file',
                encoding: 'base64',
                size: path === 'src/auth.ts' ? 100 : 40,
                content: Buffer.from(
                  path === 'src/auth.ts'
                    ? "const token = 'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';"
                    : JSON.stringify({
                        name: 'test-project',
                        dependencies: { express: 'https://example.test/token=private' },
                      }),
                ).toString('base64'),
              },
            }),
          ),
        },
      },
    };
    const responseBody = {
      choices: [
        {
          message: {
            content: JSON.stringify({
              whatIsWrong: 'User input is trusted.',
              whyVulnerable: 'It is inserted into a sensitive operation.',
              rootCause: 'Missing validation.',
              risk: 'high',
              recommendedFix: 'Use a safe API.',
              filesToModify: ['src/auth.ts'],
              testsToAdd: ['Reject malicious input.'],
              confidence: 0.9,
            }),
          },
        },
      ],
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    });
    vi.stubGlobal('fetch', fetchMock);
    const service = new AiAnalysisService(github as unknown as Octokit);

    const result = await service.analyze('owner', 'repository', {
      id: 'finding-1',
      scanner: 'semgrep',
      severity: 'high',
      file: 'src/auth.ts',
      line: 1,
      vulnerability: 'Unsafe token handling',
      evidence: 'token contains github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
      possibleImpact: 'Unauthorized access.',
    });
    const request = JSON.parse(fetchMock.mock.calls[0][1].body as string);

    expect(result.rootCause).toBe('Missing validation.');
    expect(JSON.stringify(request)).not.toContain(
      'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    );
    expect(JSON.stringify(request)).not.toContain('example.test/token=private');
  });

  it('returns an unverified candidate without mutating the repository', async () => {
    vi.stubEnv('OPENAI_API_KEY', 'unit-test-key');
    const rawToken = 'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const github = {
      rest: {
        repos: {
          getContent: vi.fn().mockResolvedValue({
            data: {
              type: 'file',
              encoding: 'base64',
              size: 100,
              content: Buffer.from(`const token = '${rawToken}';`).toString('base64'),
            },
          }),
        },
      },
    };
    const responseBody = {
      choices: [
        {
          message: {
            content: JSON.stringify({
              candidateCode: 'export const safe = true;\n',
              explanation: 'Uses a safe fixed query.',
            }),
          },
        },
      ],
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    });
    vi.stubGlobal('fetch', fetchMock);
    const service = new AiAnalysisService(github as unknown as Octokit);
    const finding: SecurityFinding = {
      id: 'finding-2',
      scanner: 'semgrep',
      severity: 'high',
      file: 'src/auth.ts',
      line: 1,
      vulnerability: 'Unsafe query',
      evidence: 'unsafe query',
      possibleImpact: 'Unauthorized data access.',
    };
    const analysis = {
      whatIsWrong: 'Input is concatenated.',
      whyVulnerable: 'The database parses it as SQL.',
      rootCause: 'The query is built dynamically.',
      risk: 'high' as const,
      recommendedFix: 'Use parameters.',
      filesToModify: ['src/auth.ts'],
      testsToAdd: ['Reject injection payloads.'],
      confidence: 0.9,
    };

    const result = await service.generateFix(
      'owner',
      'repository',
      finding,
      analysis,
    );
    const request = JSON.parse(fetchMock.mock.calls[0][1].body as string);

    expect(result).toMatchObject({
      status: 'candidate',
      verified: false,
      file: 'src/auth.ts',
      proposedCode: 'export const safe = true;\n',
    });
    expect(result.originalCode).not.toContain(rawToken);
    expect(JSON.stringify(request)).not.toContain(rawToken);
    expect(github.rest.repos).not.toHaveProperty('createOrUpdateFileContents');
  });
});
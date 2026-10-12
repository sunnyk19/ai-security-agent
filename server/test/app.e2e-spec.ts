import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { vi } from 'vitest';
import { AppModule } from './../src/app.module.js';
import { GitHubService } from './../src/github/github.service.js';
import { GITHUB_CLIENT } from './../src/github/github.tokens.js';
import { SecurityScannerService } from './../src/security/security-scanner.service.js';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;
  const listRepositories = vi.fn().mockResolvedValue({
    repositories: [],
    pagination: {
      page: 1,
      perPage: 30,
      hasNextPage: false,
      hasPreviousPage: false,
    },
  });
  const scanRepository = vi.fn().mockResolvedValue({
    repository: 'owner/repository',
    findings: [],
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(GitHubService)
      .useValue({
        listRepositories,
        analyze: vi.fn(),
        getRepositoryMetadata: vi.fn(),
        getBranches: vi.fn(),
        getRepositoryTree: vi.fn(),
      })
      .overrideProvider(GITHUB_CLIENT)
      .useValue({})
      .overrideProvider(SecurityScannerService)
      .useValue({
        scan: scanRepository,
      })
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  it('/repositories (GET)', async () => {
    await request(app.getHttpServer())
      .get('/repositories')
      .expect(200)
      .expect({
        repositories: [],
        pagination: {
          page: 1,
          perPage: 30,
          hasNextPage: false,
          hasPreviousPage: false,
        },
      });

    expect(listRepositories).toHaveBeenCalledWith({
      page: undefined,
      perPage: undefined,
      query: undefined,
    });
  });

  it('/repositories/test/scan (POST)', async () => {
    await request(app.getHttpServer())
      .post('/repositories/test/scan')
      .expect(201)
      .expect({
        repository: 'owner/repository',
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      });

    expect(scanRepository).toHaveBeenCalledWith('nestjs', 'nest');
  });

  it('/repositories/:owner/:repository/scan accepts a selected branch', async () => {
    await request(app.getHttpServer())
      .post('/repositories/octocat/hello-world/scan')
      .send({ branch: 'feature/security-review' })
      .expect(201);

    expect(scanRepository).toHaveBeenCalledWith(
      'octocat',
      'hello-world',
      'feature/security-review',
    );
  });

  afterEach(async () => {
    vi.clearAllMocks();
    await app.close();
  });
});

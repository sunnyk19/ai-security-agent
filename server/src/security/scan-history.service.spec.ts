import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { SecurityScanReport } from './security.types.js';
import { ScanHistoryService } from './scan-history.service.js';

describe('ScanHistoryService', () => {
  let directory: string | undefined;

  afterEach(async () => {
    if (directory) await rm(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it('persists recent scan metadata and omits source evidence', async () => {
    directory = await mkdtemp(join(tmpdir(), 'scan-history-test-'));
    const filePath = join(directory, 'history.json');
    const report: SecurityScanReport = {
      repository: 'owner/repository',
      branch: 'main',
      scannedAt: '2026-10-12T12:00:00.000Z',
      filesScanned: 1,
      sourceFilesSkipped: 0,
      sourceFileLimit: 100,
      sourceFilesTruncated: false,
      treeTruncated: false,
      scanners: {
        semgrep: { status: 'unavailable', findings: null, message: 'CLI missing.' },
        npmAudit: { status: 'completed', findings: 1, message: null, projects: [] },
        secretDetection: { status: 'completed', findings: 0 },
      },
      summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      findings: [{
        id: 'javascript.test-rule',
        scanner: 'semgrep',
        severity: 'high',
        file: 'src/app.ts',
        line: 4,
        vulnerability: 'Unsafe command usage.',
        evidence: 'source with potentially sensitive text',
        possibleImpact: 'An attacker may execute commands.',
      }],
    };

    const writer = new ScanHistoryService(filePath);
    const saved = await writer.save(report);
    const reloaded = await new ScanHistoryService(filePath).list(5);
    const persistedFile = await readFile(filePath, 'utf8');

    expect(saved.id).toBeTruthy();
    expect(saved.findings[0]).not.toHaveProperty('evidence');
    expect(reloaded).toEqual([saved]);
    expect(persistedFile).not.toContain('source with potentially sensitive text');
  });

  it('fails closed on a corrupt history file instead of replacing it', async () => {
    directory = await mkdtemp(join(tmpdir(), 'scan-history-corrupt-'));
    const filePath = join(directory, 'history.json');
    await writeFile(filePath, '{invalid', 'utf8');

    await expect(new ScanHistoryService(filePath).list()).rejects.toThrow(
      'Scan history could not be read.',
    );
    await expect(readFile(filePath, 'utf8')).resolves.toBe('{invalid');
  });
});

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { SecurityFinding, SecurityScanReport } from './security.types.js';

const MAX_HISTORY_RECORDS = 100;
const DEFAULT_HISTORY_LIMIT = 20;
const MAX_HISTORY_LIMIT = 50;

type StoredFinding = Omit<SecurityFinding, 'evidence'>;

export type ScanHistoryRecord = Omit<SecurityScanReport, 'findings' | 'history'> & {
  id: string;
  findings: StoredFinding[];
};

type HistoryFile = {
  version: 1;
  records: ScanHistoryRecord[];
};

@Injectable()
export class ScanHistoryService {
  private records: ScanHistoryRecord[] | undefined;
  private writeQueue: Promise<void> = Promise.resolve();
  private readonly filePath: string;

  constructor(filePath = process.env.SCAN_HISTORY_PATH || 'data/scan-history.json') {
    this.filePath = resolve(filePath);
  }

  async save(report: SecurityScanReport): Promise<ScanHistoryRecord> {
    const { history: _history, ...reportWithoutHistory } = report;
    const record: ScanHistoryRecord = {
      ...reportWithoutHistory,
      id: randomUUID(),
      findings: report.findings.map(({ evidence: _evidence, ...finding }) => finding),
    };

    const write = this.writeQueue.then(async () => {
      await this.load();
      this.records = [record, ...(this.records ?? [])].slice(0, MAX_HISTORY_RECORDS);
      const file: HistoryFile = { version: 1, records: this.records };
      const temporaryPath = `${this.filePath}.${randomUUID()}.tmp`;

      await mkdir(dirname(this.filePath), { recursive: true });
      try {
        await writeFile(temporaryPath, JSON.stringify(file), { encoding: 'utf8', mode: 0o600 });
        await rename(temporaryPath, this.filePath);
      } catch {
        await rm(temporaryPath, { force: true });
        throw new Error('Scan history could not be written.');
      }
    });
    this.writeQueue = write.catch(() => undefined);
    await write;
    return record;
  }

  async list(limit = DEFAULT_HISTORY_LIMIT): Promise<ScanHistoryRecord[]> {
    await this.writeQueue;
    await this.load();
    const normalizedLimit = Number.isFinite(limit)
      ? Math.min(MAX_HISTORY_LIMIT, Math.max(1, Math.floor(limit)))
      : DEFAULT_HISTORY_LIMIT;
    return (this.records ?? []).slice(0, normalizedLimit);
  }

  private async load() {
    if (this.records) return;

    try {
      const content = await readFile(this.filePath, 'utf8');
      const parsed: unknown = JSON.parse(content);
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('version' in parsed) ||
        parsed.version !== 1 ||
        !('records' in parsed) ||
        !Array.isArray(parsed.records)
      ) {
        throw new Error('Invalid scan history file.');
      }
      this.records = parsed.records as ScanHistoryRecord[];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        this.records = [];
        return;
      }
      throw new Error('Scan history could not be read.');
    }
  }
}

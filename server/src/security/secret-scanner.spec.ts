import { describe, expect, it } from 'vitest';
import {
  findCommonMisconfigurations,
  findHardcodedSecrets,
  redactSecrets,
} from './secret-scanner.js';

describe('findHardcodedSecrets', () => {
  it('reports credential patterns with the value redacted', () => {
    const findings = findHardcodedSecrets([
      {
        path: 'src/config.ts',
        content:
          "const token = 'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';\nconst password = 'this-is-a-long-test-password';",
      },
    ]);

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      scanner: 'secret-detection',
      severity: 'critical',
      file: 'src/config.ts',
      line: 1,
      evidence: 'Credential-like value detected; value redacted.',
    });
    expect(JSON.stringify(findings)).not.toContain(
      'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    );
  });

  it('does not flag environment variable lookups or placeholders', () => {
    expect(
      findHardcodedSecrets([
        {
          path: 'src/config.ts',
          content:
            "const token = process.env.GITHUB_TOKEN;\nconst apiKey = 'replace-with-a-real-key';",
        },
      ]),
    ).toEqual([]);
  });

  it('detects unsafe dynamic execution and shell command patterns', () => {
    const findings = findCommonMisconfigurations([
      {
        path: 'src/app.ts',
        content: "const runtime = eval(userInput);\nconst child = exec('rm -rf /tmp', { shell: true });",
      },
    ]);

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: 'static-analysis',
          file: 'src/app.ts',
          severity: 'high',
          vulnerability: expect.stringMatching(/Unsafe|Unsafe command execution/),
        }),
      ]),
    );
  });

  it('redacts secrets before source context is sent to an AI provider', () => {
    const source = "const token = 'github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';";

    expect(redactSecrets(source)).not.toContain('github_pat_');
    expect(redactSecrets(source)).toContain('[REDACTED]');
  });
});
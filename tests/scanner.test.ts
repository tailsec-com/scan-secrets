import { scanDirectory, formatResults } from '../src/scanner.js';
import { writeFileSync, mkdirSync, rmSync, readdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('Scanner', () => {
  const testDir = join(tmpdir(), 'tailsec-test-' + Date.now());

  beforeAll(() => {
    rmSync(testDir, { recursive: true, force: true });
    mkdirSync(testDir, { recursive: true });
  });

  beforeEach(() => {
    // Clean directory before each test to avoid cross-test contamination
    const files = readdirSync(testDir);
    for (const file of files) {
      rmSync(join(testDir, file), { recursive: true, force: true });
    }
  });

  afterAll(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {}
  });

  describe('file scanning', () => {
    test('scans .env files', async () => {
      writeFileSync(join(testDir, '.env'), 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET_TOKEN=ghp_test123456789abcdefghijk');
      const summary = await scanDirectory(testDir, { verify: false });
      expect(summary.filesScanned).toBe(1);
      expect(summary.secretsFound).toBeGreaterThan(0);
    });

    test('scans .ts files', async () => {
      writeFileSync(join(testDir, 'config.ts'), `const awsKey = "AKIAIOSFODNN7EXAMPLE";`);
      const summary = await scanDirectory(testDir, { verify: false });
      expect(summary.filesScanned).toBeGreaterThanOrEqual(1);
    });

    test('skips node_modules', async () => {
      const nodeModulesDir = join(testDir, 'node_modules');
      mkdirSync(nodeModulesDir, { recursive: true });
      writeFileSync(join(nodeModulesDir, 'secret.txt'), 'AKIAIOSFODNN7EXAMPLE');
      const summary = await scanDirectory(testDir, { verify: false });
      const hasNodeModulesSecrets = summary.results.some(r => r.file?.includes('node_modules'));
      expect(hasNodeModulesSecrets).toBe(false);
    });
  });

  describe('formatResults', () => {
test('formats as text', async () => {
      writeFileSync(join(testDir, '.env'), 'AKIAIOSFODNN7EXAMPLE');
      const summary = await scanDirectory(testDir, { verify: false });
      expect(summary.secretsFound).toBeGreaterThan(0);
      const output = formatResults(summary, 'text');
      expect(output).toContain('Secrets Scan Results');
      expect(output).toContain('Files scanned:');
      expect(output).toContain('AKIAIOSFODNN7EXAMPLE');
    });

    test('formats as JSON', async () => {
      writeFileSync(join(testDir, 'test.txt'), 'AKIAIOSFODNN7EXAMPLE');
      const summary = await scanDirectory(testDir, { verify: false });
      const output = formatResults(summary, 'json');
      const parsed = JSON.parse(output);
      expect(parsed.filesScanned).toBeDefined();
      expect(parsed.secretsFound).toBeDefined();
      expect(parsed.results).toBeInstanceOf(Array);
    });

    test('formats as SARIF', async () => {
      writeFileSync(join(testDir, 'test.txt'), 'AKIAIOSFODNN7EXAMPLE');
      const summary = await scanDirectory(testDir, { verify: false });
      const output = formatResults(summary, 'sarif');
      const parsed = JSON.parse(output);
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs).toBeDefined();
      expect(parsed.runs[0].results).toBeInstanceOf(Array);
    });
  });

  describe('no secrets found', () => {
    test('returns empty results for clean code', async () => {
      writeFileSync(join(testDir, 'clean.ts'), `const x = 42; console.log("hello");`);
      const summary = await scanDirectory(testDir, { verify: false });
      expect(summary.secretsFound).toBe(0);
      expect(summary.results).toHaveLength(0);
    });
  });
});
import { detectAWS } from '../src/detectors/aws.js';

describe('AWS Detector', () => {
  describe('AKIA pattern', () => {
    test('detects standard AKIA access key', async () => {
      const content = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
      const results = await detectAWS(content, { verify: false });
      expect(results.length).toBeGreaterThan(0);
      const akia = results.find(r => r.raw.includes('AKIA'));
      expect(akia).toBeDefined();
      expect(akia?.raw).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(akia?.redacted).toContain('AKIA');
    });

    test('detects AKIA in code', async () => {
      const content = 'const awsKey = "AKIAIOSFODNN7EXAMPLE"';
      const results = await detectAWS(content, { verify: false });
      expect(results.some(r => r.raw === 'AKIAIOSFODNN7EXAMPLE')).toBe(true);
    });

    test('does not detect AKIA in comments', async () => {
      const content = '// AKIA comment should not be detected as real key';
      const results = await detectAWS(content, { verify: false });
      expect(results.filter(r => r.raw === 'AKIA comment should not be detected as real key')).toHaveLength(0);
    });
  });

describe('verification', () => {
    test('returns results without verification when verify=false', async () => {
      const content = 'AKIAIOSFODNN7EXAMPLE';
      const results = await detectAWS(content, { verify: false });
      const akia = results.find(r => r.raw.includes('AKIA'));
      expect(akia).toBeDefined();
      expect(akia?.verified).toBe(false);
    });
  });

  describe('extra data', () => {
    test('extracts account ID from AKIA keys', async () => {
      const content = 'AKIAIOSFODNN7EXAMPLE';
      const results = await detectAWS(content, { verify: false });
      const akia = results.find(r => r.raw.includes('AKIA'));
      expect(akia?.extraData?.account).toBe('007344170432');
    });

    test('includes rotation URL', async () => {
      const content = 'AKIAIOSFODNN7EXAMPLE';
      const results = await detectAWS(content, { verify: false });
      const akia = results.find(r => r.raw.includes('AKIA'));
      expect(akia?.extraData?.rotation_guide).toContain('howtorotate.com');
    });
  });
});
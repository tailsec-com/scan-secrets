import { detectJWT } from '../src/detectors/jwt.js';

describe('JWT Detector', () => {
  test('detects JWT token', async () => {
    const content = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const results = await detectJWT(content, {});
    expect(results.length).toBe(1);
    expect(results[0].type).toBe('JWT Token');
    expect(results[0].extraData?.algorithm).toBe('HS256');
  });

  test('decodes JWT payload', async () => {
    const content = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dzGvW8qKXJ1eDv9s5xLk';
    const results = await detectJWT(content, {});
    expect(results[0].extraData?.subject).toBe('1234567890');
  });

  test('detects JWT in code context', async () => {
    const content = 'const token = "eyJhbGciOiJIUzI1NiJ9.eyJsubI6IjEyMyJ9.abc123"';
    const results = await detectJWT(content, {});
    expect(results.some(r => r.raw.includes('eyJ'))).toBe(true);
  });

  test('redacts JWT properly', async () => {
    const content = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const results = await detectJWT(content, {});
    expect(results[0].redacted.length).toBeLessThan(content.length);
    expect(results[0].redacted).toContain('...');
  });
});
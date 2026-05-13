/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { detectGitHub } from '../src/detectors/github.js';

describe('GitHub Detector', () => {
  const VALID_TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'; // exactly 40 chars

  describe('classic PAT (ghp_)', () => {
    test('detects classic personal access token', async () => {
      const results = await detectGitHub(VALID_TOKEN, { verify: false });
      expect(results.length).toBeGreaterThan(0);
      const pat = results.find(r => r.type === 'github_ghp');
      expect(pat).toBeDefined();
      expect(pat?.raw).toBe(VALID_TOKEN);
    });
  });

  describe('oauth (gho_)', () => {
    test('detects OAuth token', async () => {
      const content = 'gho_' + VALID_TOKEN.slice(4);
      const results = await detectGitHub(content, { verify: false });
      expect(results.some(r => r.type === 'github_gho')).toBe(true);
    });
  });

  describe('user-to-server (ghu_)', () => {
    test('detects user-to-server token', async () => {
      const content = 'ghu_' + VALID_TOKEN.slice(4);
      const results = await detectGitHub(content, { verify: false });
      expect(results.some(r => r.type === 'github_ghu')).toBe(true);
    });
  });

  describe('server-to-server (ghs_)', () => {
    test('detects server-to-server token', async () => {
      const content = 'ghs_' + VALID_TOKEN.slice(4);
      const results = await detectGitHub(content, { verify: false });
      expect(results.some(r => r.type === 'github_ghs')).toBe(true);
    });
  });

  describe('refresh (ghr_)', () => {
    test('detects refresh token', async () => {
      const content = 'ghr_' + VALID_TOKEN.slice(4);
      const results = await detectGitHub(content, { verify: false });
      expect(results.some(r => r.type === 'github_ghr')).toBe(true);
    });
  });

  describe('false positives', () => {
    test('does not detect invalid prefix', async () => {
      const content = 'ghx_' + VALID_TOKEN.slice(4);
      const results = await detectGitHub(content, { verify: false });
      expect(results.some(r => r.raw === content)).toBe(false);
    });

    test('does not detect too-short token', async () => {
      const content = 'ghp_' + 'abcdefghijklmnopqrstuvwxyz123456'; // only 32 chars after prefix
      const results = await detectGitHub(content, { verify: false });
      expect(results.length).toBe(0);
    });
  });

  describe('verification', () => {
    test('includes verification config when verify=true', async () => {
      const results = await detectGitHub(VALID_TOKEN, { verify: true });
      const pat = results.find(r => r.type === 'github_ghp');
      expect(pat?.verification).toBeDefined();
      expect(pat?.verification?.url).toContain('api.github.com');
    });
  });
});
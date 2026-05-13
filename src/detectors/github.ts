/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanResult } from '../types.js';
import { shannonEntropy } from '../lib/entropy.js';

const GITHUB_PATTERNS = {
  classic: /\b(ghp_[A-Za-z0-9]{36})\b/g,
  oauth: /\b(gho_[A-Za-z0-9]{36})\b/g,
  userToServer: /\b(ghu_[A-Za-z0-9]{36})\b/g,
  serverToServer: /\b(ghs_[A-Za-z0-9]{36})\b/g,
  refresh: /\b(ghr_[A-Za-z0-9]{36})\b/g,
};

const TOKEN_TYPES: Record<string, string> = {
  ghp: 'Personal Access Token (classic)',
  gho: 'OAuth Access Token',
  ghu: 'User-to-Server OAuth Token',
  ghs: 'Server-to-Server OAuth Token',
  ghr: 'Refresh Token',
};

const VERIFICATION_URL = 'https://api.github.com/user';

export async function detectGitHub(
  content: string,
  options: { verify?: boolean; file?: string; line?: number } = {}
): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  const seen = new Set<string>();

  const patterns = [
    { regex: GITHUB_PATTERNS.classic, type: 'ghp' },
    { regex: GITHUB_PATTERNS.oauth, type: 'gho' },
    { regex: GITHUB_PATTERNS.userToServer, type: 'ghu' },
    { regex: GITHUB_PATTERNS.serverToServer, type: 'ghs' },
    { regex: GITHUB_PATTERNS.refresh, type: 'ghr' },
  ];

  for (const { regex, type } of patterns) {
    regex.lastIndex = 0;
    for (const match of content.matchAll(regex)) {
      const token = match[1];
      const key = `${type}:${token}`;
      if (seen.has(key)) continue;
      seen.add(key);

      if (shannonEntropy(token) < 4.0) continue;

      const extraData: Record<string, string> = {
        token_type: TOKEN_TYPES[type] || 'Unknown',
        rotation_guide: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-authentication-methods',
      };

      results.push({
        type: `github_${type}`,
        detectorId: 'github',
        raw: token,
        redacted: token.slice(0, 8) + '****',
        verified: false,
        file: options.file,
        line: options.line,
        extraData,
        verification: options.verify ? {
          type: 'http',
          method: 'GET',
          url: VERIFICATION_URL,
          authType: 'bearer',
          redactAuth: true,
        } : undefined,
      });
    }
  }

  return results;
}
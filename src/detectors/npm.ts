/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { ScanOptions, ScanResult } from '../types.js';

interface NPMPattern {
  type: string;
  regex: string;
  entropy: number;
  verify?: {
    type: string;
    method: string;
    url: string;
    authType: string;
    redactAuth?: boolean;
  };
}

interface NPMData {
  id: string;
  name: string;
  patterns: NPMPattern[];
}

function loadPatterns(): NPMData {
  const data = readFileSync(join(process.cwd(), 'data', 'npm.json'), 'utf-8');
  return JSON.parse(data);
}

export async function detectNPM(
  content: string,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const data = loadPatterns();
  const results: ScanResult[] = [];

  for (const pattern of data.patterns) {
    const regex = new RegExp(pattern.regex);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const secret = match[0];
      const verification = pattern.verify ? {
        type: 'http',
        method: pattern.verify.method,
        url: pattern.verify.url,
        authType: pattern.verify.authType as 'bearer' | 'api_key' | 'basic',
        redactAuth: pattern.verify.redactAuth ?? true,
      } : undefined;

      results.push({
        type: pattern.type,
        raw: secret,
        redacted: secret.slice(0, 4) + '...' + secret.slice(-4),
        verified: false,
        detectorId: 'npm',
        extraData: {
          rotatonUrl: 'https://www.npmjs.com/settings/tokens',
        },
        verification,
      });
    }
  }

  return results;
}
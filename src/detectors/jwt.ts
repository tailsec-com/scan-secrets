/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { ScanOptions, ScanResult } from '../types.js';

interface JWTPattern {
  type: string;
  regex: string;
  entropy: number;
  verify?: {
    type: string;
    redactAuth?: boolean;
  };
}

interface JWTData {
  id: string;
  name: string;
  patterns: JWTPattern[];
}

let patternsCache: JWTData | null = null;

function loadPatterns(): JWTData {
  if (patternsCache !== null) {
    return patternsCache;
  }
  const data = readFileSync(join(process.cwd(), 'data', 'jwt.json'), 'utf-8');
  const parsed = JSON.parse(data) as JWTData;
  patternsCache = parsed;
  return parsed;
}

export function clearPatternsCache(): void {
  patternsCache = null;
}

function decodeJWT(token: string): { header: any; payload: any; signature: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const decodeBase64Url = (str: string) => {
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const padding = '='.repeat((4 - base64.length % 4) % 4);
      return Buffer.from(base64 + padding, 'base64').toString('utf-8');
    };

    return {
      header: JSON.parse(decodeBase64Url(parts[0])),
      payload: JSON.parse(decodeBase64Url(parts[1])),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

export async function detectJWT(
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
      const decoded = decodeJWT(secret);

      results.push({
        type: pattern.type,
        raw: secret,
        redacted: secret.slice(0, 20) + '...',
        verified: false,
        detectorId: 'jwt',
        extraData: decoded ? {
          algorithm: decoded.header.alg,
          issuer: decoded.payload.iss || undefined,
          subject: decoded.payload.sub || undefined,
          expiration: decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toISOString() : undefined,
        } : undefined,
        verification: pattern.verify ? {
          type: pattern.verify.type,
          redactAuth: pattern.verify.redactAuth ?? false,
        } : undefined,
      });
    }
  }

  return results;
}
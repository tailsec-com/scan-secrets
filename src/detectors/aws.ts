/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanResult } from '../types.js';
import { shannonEntropy } from '../lib/entropy.js';
import { verifyAWS } from '../lib/verifier.js';

const AWS_ID_PATTERN = /\b((?:AKIA|ABIA|ACCA|AIPA|ANPA|AROA|ASCA)[A-Z0-9]{16})\b/g;
const AWS_SECRET_PATTERN = /(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)/g;
const REQUIRED_ID_ENTROPY = 3.0;
const REQUIRED_SECRET_ENTROPY = 4.25;

export interface AWSResult extends ScanResult {
  secretParts?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
  extraData: {
    account?: string;
    user_id?: string;
    arn?: string;
    resource_type?: string;
    rotation_guide?: string;
  };
}

function getResourceType(idPrefix: string): string {
  const types: Record<string, string> = {
    ABIA: 'AWS STS service bearer token',
    ACCA: 'Context-specific credential',
    AGPA: 'User group',
    AIDA: 'IAM user',
    AIPA: 'Amazon EC2 instance profile',
    AKIA: 'Access key',
    ANPA: 'Managed policy',
    ANVA: 'Version in a managed policy',
    APKA: 'Public key',
    AROA: 'Role',
    ASCA: 'Certificate',
    ASIA: 'Temporary (STS) access key IDs',
  };
  return types[idPrefix] || 'Unknown';
}

function decodeAccountNumber(id: string): string | null {
  if (id.length < 4) return null;
  const prefix = id.slice(0, 4);
  if (prefix === 'AKIA' || prefix === 'ASIA') {
    const trimmed = id.slice(4);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const char of trimmed.toUpperCase()) {
      const idx = chars.indexOf(char);
      if (idx === -1) return null;
      bits += idx.toString(2).padStart(5, '0');
    }
    const accountNum = parseInt(bits.slice(25, 61), 2);
    return String(accountNum).padStart(12, '0');
  }
  return null;
}

export async function detectAWS(
  content: string,
  options: { verify?: boolean; file?: string; line?: number } = {}
): Promise<AWSResult[]> {
  const results: AWSResult[] = [];

  const idMatches = [...content.matchAll(AWS_ID_PATTERN)].map(m => m[1]);
  const secretMatches = [...content.matchAll(AWS_SECRET_PATTERN)].map(m => m[1]);

  const uniqueIds = [...new Set(idMatches.filter(id => shannonEntropy(id) >= REQUIRED_ID_ENTROPY))];
  const uniqueSecrets = [...new Set(secretMatches.filter(s => shannonEntropy(s) >= REQUIRED_SECRET_ENTROPY))];

  for (const idMatch of uniqueIds) {
    const accountNum = decodeAccountNumber(idMatch);
    const resourceType = getResourceType(idMatch.slice(0, 4));
    let verified = false;
    let extraData: Record<string, string> = {
      resource_type: resourceType,
      rotation_guide: 'https://howtorotate.com/docs/tutorials/aws/',
    };
    if (accountNum) {
      extraData.account = accountNum;
    }

    const secretMatch = uniqueSecrets.length > 0 ? uniqueSecrets[0] : null;

    if (options.verify && secretMatch) {
      const verifyResult = await verifyAWS(idMatch, secretMatch);
      verified = verifyResult.verified;
      if (verifyResult.extraData) {
        extraData = { ...extraData, ...verifyResult.extraData };
      }
    }

    results.push({
      type: 'aws_access_key',
      detectorId: 'aws',
      raw: secretMatch ? `${idMatch}:${secretMatch}` : idMatch,
      redacted: secretMatch ? `${idMatch.slice(0, 4)}****:${secretMatch.slice(0, 8)}****` : `${idMatch.slice(0, 4)}****`,
      verified,
      file: options.file,
      line: options.line,
      secretParts: secretMatch ? {
        accessKeyId: idMatch,
        secretAccessKey: secretMatch,
      } : undefined as { accessKeyId: string; secretAccessKey: string } | undefined,
      extraData,
    });
  }

  return results;
}
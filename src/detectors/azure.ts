/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import axios from 'axios';
import { ScanResult } from '../types.js';
import { shannonEntropy } from '../lib/entropy.js';

const AZURE_SUB_KEY_PATTERN = /\b([0-9a-f]{32})\b/g;
const AZURE_CLIENT_SECRET_PATTERN = /\b([a-zA-Z0-9._~-]{40,200})\b/g;
const AZURE_TOKEN_PATTERN = /\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSMjQifQ\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g;

export interface AzureResult extends ScanResult {
  extraData: {
    credential_type?: string;
    tenant_id?: string;
    rotation_guide?: string;
  };
}

async function verifyAzureSubscription(key: string): Promise<boolean> {
  try {
    const response = await axios.get(
      'https://management.azure.com/subscriptions?api-version=2020-01-01',
      {
        headers: { 'Ocp-Apim-Subscription-Key': key },
        timeout: 5000,
      }
    );
    return response.status === 200;
  } catch {
    return false;
  }
}

export async function detectAzure(
  content: string,
  options: { verify?: boolean; file?: string; line?: number } = {}
): Promise<AzureResult[]> {
  const results: AzureResult[] = [];
  const seen = new Set<string>();

  AZURE_SUB_KEY_PATTERN.lastIndex = 0;
  for (const match of content.matchAll(AZURE_SUB_KEY_PATTERN)) {
    const key = match[1];
    if (seen.has(key)) continue;
    seen.add(key);

    let verified = false;
    if (options.verify) {
      verified = await verifyAzureSubscription(key);
    }

    results.push({
      type: 'azure_subscription_key',
      detectorId: 'azure',
      raw: key,
      redacted: key.slice(0, 8) + '****',
      verified,
      file: options.file,
      line: options.line,
      extraData: {
        credential_type: 'Subscription Key',
        rotation_guide: 'https://docs.microsoft.com/en-us/azure/api-management/api-management-subscriptions',
      },
    });
  }

  AZURE_CLIENT_SECRET_PATTERN.lastIndex = 0;
  for (const match of content.matchAll(AZURE_CLIENT_SECRET_PATTERN)) {
    const secret = match[1];
    if (seen.has(secret)) continue;
    if (shannonEntropy(secret) < 4.5) continue;
    seen.add(secret);

    results.push({
      type: 'azure_client_secret',
      detectorId: 'azure',
      raw: secret,
      redacted: secret.slice(0, 8) + '****',
      verified: false,
      file: options.file,
      line: options.line,
      extraData: {
        credential_type: 'Client Secret',
        rotation_guide: 'https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app',
      },
    });
  }

  AZURE_TOKEN_PATTERN.lastIndex = 0;
  for (const match of content.matchAll(AZURE_TOKEN_PATTERN)) {
    const token = match[1];
    if (seen.has(token)) continue;
    seen.add(token);

    results.push({
      type: 'azure_access_token',
      detectorId: 'azure',
      raw: token,
      redacted: token.slice(0, 20) + '****',
      verified: false,
      file: options.file,
      line: options.line,
      extraData: {
        credential_type: 'OAuth Access Token',
      },
    });
  }

  return results;
}
/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import axios from 'axios';
import { ScanResult } from '../types.js';

export interface VerifyResult {
  verified: boolean;
  extraData?: Record<string, string>;
  error?: string;
}

export async function verifyAWS(accessKeyId: string, secretKey: string): Promise<VerifyResult> {
  try {
    const response = await axios.post(
      'https://sts.amazonaws.com/',
      {
        Action: 'GetCallerIdentity',
        Version: '2011-06-15',
      },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        },
        auth: {
          username: accessKeyId,
          password: secretKey,
        },
        timeout: 5000,
      }
    );

    return {
      verified: true,
      extraData: {
        verified: 'true',
        verified_at: new Date().toISOString(),
      },
    };
  } catch (err: any) {
    const message = err.response?.data || err.message;
    if (message.includes('SignatureDoesNotMatch') || message.includes('InvalidClientTokenId')) {
      return { verified: false, error: 'Invalid credentials' };
    }
    return { verified: false, error: String(message) };
  }
}

export async function verifyGitHub(token: string): Promise<VerifyResult> {
  try {
    const response = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
      timeout: 5000,
    });

    return {
      verified: true,
      extraData: {
        username: response.data.login,
        user_id: String(response.data.id),
      },
    };
  } catch (err: any) {
    if (err.response?.status === 401) {
      return { verified: false, error: 'Invalid token' };
    }
    return { verified: false, error: err.message };
  }
}

export async function verifyGeneric(url: string, headers: Record<string, string>): Promise<VerifyResult> {
  try {
    const response = await axios.get(url, { headers, timeout: 5000 });
    return { verified: true, extraData: { status: String(response.status) } };
  } catch (err: any) {
    return { verified: false, error: err.message };
  }
}
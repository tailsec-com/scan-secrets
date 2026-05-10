import axios from 'axios';
import { shannonEntropy } from '../lib/entropy.js';
const GCP_API_KEY_PATTERN = /\b(AIza[0-9A-Za-z_-]{35})\b/g;
const GCP_ACCESS_TOKEN_PATTERN = /\b(ya29\.[A-Za-z0-9_-]{100,200})\b/g;
const SERVICE_ACCOUNT_PATTERN = /"type"\s*:\s*"service_account"/g;
async function verifyGCPApiKey(key) {
    try {
        const response = await axios.get('https://www.googleapis.com/discovery/v1/apis', {
            headers: { 'X-Goog-Api-Key': key },
            timeout: 5000,
        });
        return response.status === 200;
    }
    catch {
        return false;
    }
}
export async function detectGCP(content, options = {}) {
    const results = [];
    const seen = new Set();
    GCP_API_KEY_PATTERN.lastIndex = 0;
    for (const match of content.matchAll(GCP_API_KEY_PATTERN)) {
        const key = match[1];
        if (seen.has(key))
            continue;
        seen.add(key);
        let verified = false;
        if (options.verify) {
            verified = await verifyGCPApiKey(key);
        }
        results.push({
            type: 'gcp_api_key',
            detectorId: 'gcp',
            raw: key,
            redacted: key.slice(0, 8) + '****',
            verified,
            file: options.file,
            line: options.line,
            extraData: {
                credential_type: 'API Key',
                rotation_guide: 'https://cloud.google.com/docs/authentication/api-keys',
            },
        });
    }
    GCP_ACCESS_TOKEN_PATTERN.lastIndex = 0;
    for (const match of content.matchAll(GCP_ACCESS_TOKEN_PATTERN)) {
        const token = match[1];
        if (seen.has(token))
            continue;
        seen.add(token);
        if (shannonEntropy(token) < 4.5)
            continue;
        results.push({
            type: 'gcp_access_token',
            detectorId: 'gcp',
            raw: token,
            redacted: token.slice(0, 10) + '****',
            verified: false,
            file: options.file,
            line: options.line,
            extraData: {
                credential_type: 'OAuth Access Token',
                rotation_guide: 'https://cloud.google.com/docs/authentication',
            },
        });
    }
    SERVICE_ACCOUNT_PATTERN.lastIndex = 0;
    const hasServiceAccount = SERVICE_ACCOUNT_PATTERN.test(content);
    if (hasServiceAccount) {
        results.push({
            type: 'gcp_service_account',
            detectorId: 'gcp',
            raw: '[SERVICE_ACCOUNT_JSON]',
            redacted: '[SERVICE_ACCOUNT_JSON]',
            verified: false,
            file: options.file,
            line: options.line,
            extraData: {
                credential_type: 'Service Account JSON',
                rotation_guide: 'https://cloud.google.com/iam/docs/creating-managing-service-account-keys',
            },
        });
    }
    return results;
}

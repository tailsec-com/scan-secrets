/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import axios from 'axios';
import { shannonEntropy } from '../lib/entropy.js';
const SLACK_PATTERNS = {
    bot: /xoxb-[A-Za-z0-9-]{10,48}/g,
    user: /xoxp-[A-Za-z0-9-]{10,48}/g,
    app: /xoxa-[A-Za-z0-9-]{10,48}/g,
    refresh: /xoxr-[A-Za-z0-9-]{10,48}/g,
    webhook: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
};
const TOKEN_TYPES = {
    bot: 'Bot User OAuth Token',
    user: 'User Token',
    app: 'App-Level Token',
    refresh: 'Refresh Token',
    webhook: 'Incoming Webhook URL',
};
async function verifySlack(token) {
    try {
        const response = await axios.post('https://slack.com/api/auth.test', {}, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
            timeout: 5000,
        });
        return response.data?.ok === true;
    }
    catch {
        return false;
    }
}
export async function detectSlack(content, options = {}) {
    const results = [];
    const seen = new Set();
    const patterns = [
        { regex: SLACK_PATTERNS.bot, type: 'bot' },
        { regex: SLACK_PATTERNS.user, type: 'user' },
        { regex: SLACK_PATTERNS.app, type: 'app' },
        { regex: SLACK_PATTERNS.refresh, type: 'refresh' },
    ];
    for (const { regex, type } of patterns) {
        regex.lastIndex = 0;
        for (const match of content.matchAll(regex)) {
            const token = match[0];
            if (seen.has(token))
                continue;
            seen.add(token);
            if (shannonEntropy(token) < 4.0)
                continue;
            let verified = false;
            const extraData = {
                token_type: TOKEN_TYPES[type] || 'Unknown',
                rotation_guide: 'https://api.slack.com/authentication/token-types',
            };
            if (options.verify) {
                verified = await verifySlack(token);
            }
            results.push({
                type: `slack_${type}_token`,
                detectorId: 'slack',
                raw: token,
                redacted: token.slice(0, 10) + '****',
                verified,
                file: options.file,
                line: options.line,
                extraData,
            });
        }
    }
    SLACK_PATTERNS.webhook.lastIndex = 0;
    for (const match of content.matchAll(SLACK_PATTERNS.webhook)) {
        const webhook = match[0];
        if (seen.has(webhook))
            continue;
        seen.add(webhook);
        results.push({
            type: 'slack_webhook',
            detectorId: 'slack',
            raw: webhook,
            redacted: webhook.replace(/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+/, 'T***/B***'),
            verified: false,
            file: options.file,
            line: options.line,
            extraData: {
                token_type: 'Incoming Webhook URL',
            },
        });
    }
    return results;
}

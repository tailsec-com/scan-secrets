import { readFileSync } from 'fs';
import { join } from 'path';
function loadPatterns() {
    const data = readFileSync(join(process.cwd(), 'data', 'sendgrid.json'), 'utf-8');
    return JSON.parse(data);
}
export async function detectSendGrid(content, options = {}) {
    const data = loadPatterns();
    const results = [];
    for (const pattern of data.patterns) {
        const regex = new RegExp(pattern.regex);
        let match;
        while ((match = regex.exec(content)) !== null) {
            const secret = match[0];
            const verification = pattern.verify ? {
                type: 'http',
                method: pattern.verify.method,
                url: pattern.verify.url,
                authType: pattern.verify.authType,
                redactAuth: pattern.verify.redactAuth ?? true,
            } : undefined;
            results.push({
                type: pattern.type,
                raw: secret,
                redacted: secret.slice(0, 7) + '...' + secret.slice(-4),
                verified: false,
                detectorId: 'sendgrid',
                extraData: {
                    rotatonUrl: pattern.rotatonUrl,
                },
                verification,
            });
        }
    }
    return results;
}

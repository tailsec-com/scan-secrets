import { readFileSync } from 'fs';
import { join } from 'path';
function loadPatterns() {
    const data = readFileSync(join(process.cwd(), 'data', 'ssh.json'), 'utf-8');
    return JSON.parse(data);
}
export async function detectSSH(content, options = {}) {
    const data = loadPatterns();
    const results = [];
    for (const pattern of data.patterns) {
        const regex = new RegExp(pattern.regex, 'gm');
        let match;
        while ((match = regex.exec(content)) !== null) {
            const secret = match[0];
            const verification = pattern.verify ? {
                type: pattern.verify.type,
                redactAuth: pattern.verify.redactAuth ?? true,
            } : undefined;
            results.push({
                type: pattern.type,
                raw: secret,
                redacted: '[SSH PRIVATE KEY]',
                verified: false,
                detectorId: 'ssh',
                extraData: {
                    rotatonUrl: pattern.rotatonUrl,
                    keyType: secret.includes('RSA') ? 'RSA' :
                        secret.includes('DSA') ? 'DSA' :
                            secret.includes('EC') ? 'EC' :
                                secret.includes('OPENSSH') ? 'OpenSSH' : 'Unknown',
                },
                verification,
            });
        }
    }
    return results;
}

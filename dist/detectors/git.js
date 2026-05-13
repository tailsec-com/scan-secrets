/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { execSync } from 'child_process';
import { detectAWS } from './aws.js';
import { detectGitHub } from './github.js';
import { detectSlack } from './slack.js';
import { detectGCP } from './gcp.js';
import { detectAzure } from './azure.js';
function getCommitDiff(commitHash) {
    try {
        return execSync(`git log -1 -p ${commitHash}`, {
            encoding: 'utf-8',
            maxBuffer: 50 * 1024 * 1024,
        });
    }
    catch {
        return '';
    }
}
function getCommitInfo(commitHash) {
    try {
        const info = execSync(`git log -1 --format="%an|%ai|%s" ${commitHash}`, {
            encoding: 'utf-8',
        });
        const [author, date, ...msgParts] = info.trim().split('|');
        return { author, date, message: msgParts.join('|') };
    }
    catch {
        return { author: 'unknown', date: 'unknown', message: '' };
    }
}
export async function scanGitHistory(dirPath, options = {}) {
    const results = [];
    const maxCommits = options.maxCommits || 1000;
    try {
        const logOutput = execSync(`git log --format="%H" -n ${maxCommits}`, { cwd: dirPath, encoding: 'utf-8' });
        const commitHashes = logOutput.trim().split('\n').filter(Boolean);
        for (const hash of commitHashes) {
            const diff = getCommitDiff(hash);
            if (!diff)
                continue;
            const commitInfo = getCommitInfo(hash);
            const awsResults = await detectAWS(diff, { verify: options.verify });
            for (const secret of awsResults) {
                results.push({
                    secret,
                    commit: { hash, ...commitInfo },
                    diff: diff.slice(0, 500),
                });
            }
            const githubResults = await detectGitHub(diff, { verify: options.verify });
            for (const secret of githubResults) {
                results.push({
                    secret,
                    commit: { hash, ...commitInfo },
                    diff: diff.slice(0, 500),
                });
            }
            const slackResults = await detectSlack(diff, { verify: options.verify });
            for (const secret of slackResults) {
                results.push({
                    secret,
                    commit: { hash, ...commitInfo },
                    diff: diff.slice(0, 500),
                });
            }
            const gcpResults = await detectGCP(diff, { verify: options.verify });
            for (const secret of gcpResults) {
                results.push({
                    secret,
                    commit: { hash, ...commitInfo },
                    diff: diff.slice(0, 500),
                });
            }
            const azureResults = await detectAzure(diff, { verify: options.verify });
            for (const secret of azureResults) {
                results.push({
                    secret,
                    commit: { hash, ...commitInfo },
                    diff: diff.slice(0, 500),
                });
            }
        }
    }
    catch (err) {
        console.error(`Error scanning git history: ${err}`);
    }
    return results;
}
export function formatGitResults(results) {
    if (results.length === 0)
        return 'No secrets found in git history.';
    const lines = [];
    lines.push(`\nSecrets Found in Git History`);
    lines.push('='.repeat(50));
    lines.push(`Total secrets: ${results.length}`);
    lines.push('-'.repeat(50));
    for (const { secret, commit, diff } of results) {
        lines.push(`\n[${secret.type}] in commit ${commit.hash.slice(0, 8)}`);
        lines.push(`  Author: ${commit.author}`);
        lines.push(`  Date: ${commit.date}`);
        lines.push(`  Message: ${commit.message}`);
        lines.push(`  Secret: ${secret.redacted}`);
        if (secret.verified)
            lines.push(`  ✓ Verified`);
    }
    return lines.join('\n');
}

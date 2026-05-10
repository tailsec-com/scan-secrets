import { readFileSync, statSync } from 'fs';
import { relative } from 'path';
import { glob } from 'glob';
import { detectAWS } from './detectors/aws.js';
import { detectGitHub } from './detectors/github.js';
import { detectSlack } from './detectors/slack.js';
import { detectGCP } from './detectors/gcp.js';
import { detectAzure } from './detectors/azure.js';
import { detectStripe } from './detectors/stripe.js';
import { detectSendGrid } from './detectors/sendgrid.js';
import { detectNPM } from './detectors/npm.js';
import { detectSSH } from './detectors/ssh.js';
import { detectJWT } from './detectors/jwt.js';
import { ScanOptions, ScanResult } from './types.js';

export interface ScanSummary {
  filesScanned: number;
  secretsFound: number;
  verifiedCount: number;
  results: ScanResult[];
}

const EXCLUDE_PATTERNS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/package-lock.json',
  '**/yarn.lock',
];

const SCANNABLE_EXTENSIONS = [
  '.ts', '.js', '.jsx', '.tsx', '.vue', '.svelte',
  '.py', '.rb', '.go', '.java', '.php', '.cs',
  '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg',
  '.sh', '.bash', '.zsh', '.fish',
  '.env', '.env.*', '.gitignore', '.dockerignore',
  '.tf', '.tfvars', '.pachyderm',
];

function shouldExclude(path: string): boolean {
  return EXCLUDE_PATTERNS.some(pattern => {
    if (pattern.includes('**')) {
      const regex = new RegExp('^' + pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*') + '$');
      return regex.test(path);
    }
    return path.includes(pattern);
  });
}

function isScannable(path: string): boolean {
  if (!SCANNABLE_EXTENSIONS.some(ext => path.endsWith(ext))) return false;
  return !shouldExclude(path);
}

async function scanFile(content: string, filePath: string, verify: boolean): Promise<ScanResult[]> {
  const results: ScanResult[] = [];

  const [aws, github, slack, gcp, azure, stripe, sendgrid, npm, ssh, jwt] = await Promise.all([
    detectAWS(content, { verify, file: filePath }),
    detectGitHub(content, { verify, file: filePath }),
    detectSlack(content, { verify, file: filePath }),
    detectGCP(content, { verify, file: filePath }),
    detectAzure(content, { verify, file: filePath }),
    detectStripe(content, { verify, file: filePath }),
    detectSendGrid(content, { verify, file: filePath }),
    detectNPM(content, { verify, file: filePath }),
    detectSSH(content, { verify, file: filePath }),
    detectJWT(content, { verify, file: filePath }),
  ]);

  results.push(...aws, ...github, ...slack, ...gcp, ...azure, ...stripe, ...sendgrid, ...npm, ...ssh, ...jwt);
  return results;
}

export async function scanDirectory(
  dirPath: string,
  options: ScanOptions = {}
): Promise<ScanSummary> {
  const results: ScanResult[] = [];
  let filesScanned = 0;

  const allFiles = await glob('**/*', {
    cwd: dirPath,
    ignore: EXCLUDE_PATTERNS,
    absolute: true,
    dot: true,
  });

  for (const file of allFiles) {
    if (!isScannable(file)) continue;

    try {
      const stat = statSync(file);
      if (!stat.isFile()) continue;

      const content = readFileSync(file, 'utf-8');
      filesScanned++;

      const fileResults = await scanFile(content, relative(dirPath, file), options.verify || false);
      results.push(...fileResults);
    } catch {
      // Skip unreadable files
    }
  }

  const verifiedCount = results.filter(r => r.verified).length;

  return {
    filesScanned,
    secretsFound: results.length,
    verifiedCount,
    results,
  };
}

export function formatResults(
  summary: ScanSummary,
  format: 'json' | 'text' | 'sarif' = 'text'
): string {
  switch (format) {
    case 'json':
      return JSON.stringify(summary, null, 2);

    case 'sarif':
      return formatSARIF(summary);

    case 'text':
    default:
      return formatText(summary);
  }
}

function formatText(summary: ScanSummary): string {
  const lines: string[] = [];
  lines.push(`\nSecrets Scan Results`);
  lines.push('='.repeat(50));
  lines.push(`Files scanned:    ${summary.filesScanned}`);
  lines.push(`Secrets found:   ${summary.secretsFound}`);
  lines.push(`Verified:        ${summary.verifiedCount}`);
  lines.push('-'.repeat(50));

  for (const result of summary.results) {
    lines.push(`\n[${result.type}]`);
    if (result.file) lines.push(`  File: ${result.file}${result.line ? `:${result.line}` : ''}`);
    if (result.verified) lines.push(`  ✓ Verified`);
    lines.push(`  Raw: ${result.raw}`);
    lines.push(`  Redacted: ${result.redacted}`);
    if (result.extraData) {
      for (const [key, value] of Object.entries(result.extraData)) {
        lines.push(`  ${key}: ${value}`);
      }
    }
  }

  return lines.join('\n');
}

function formatSARIF(summary: ScanSummary): string {
  const sarif = {
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Tailsec Secrets Scanner',
          version: '0.1.0',
          informationUri: 'https://tailsec.dev',
        },
      },
      results: summary.results.map(r => ({
        ruleId: r.detectorId,
        message: { text: `Secret detected: ${r.type}` },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: r.file || 'unknown',
            },
            region: r.line ? { startLine: r.line } : undefined,
          },
        }],
        properties: {
          verified: r.verified,
          redacted: r.redacted,
        },
      })),
    }],
  };
  return JSON.stringify(sarif, null, 2);
}
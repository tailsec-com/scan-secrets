/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { execSync } from 'child_process';
import { pipeline } from 'stream/promises';
import { createWriteStream, existsSync, mkdirSync, readFileSync, rmSync } from 'fs';
import { createHash } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';
import { ScanResult } from '../types.js';
import { detectAWS } from './aws.js';
import { detectGitHub } from './github.js';
import { detectSlack } from './slack.js';
import { detectGCP } from './gcp.js';
import { detectAzure } from './azure.js';

export interface ContainerScanOptions {
  image?: string;
  verify?: boolean;
  extractDir?: string;
}

export interface ContainerScanResult {
  image: string;
  imageId: string;
  layerCount: number;
  secrets: ScanResult[];
  configFiles: string[];
  summary: {
    filesScanned: number;
    secretsFound: number;
  };
}

const SUSPICIOUS_PATTERNS = [
  /\b(aws_access_key|aws_secret_key|aws_security_token)/i,
  /\b(secret|token|password|api_key|apikey)\s*=/i,
  /ENV\s+\w+=(.+)/,
  /LABEL\s+\w+="?(.+)"?/,
];

function extractDockerConfig(image: string): { config: any; history: any[] } | null {
  try {
    const config = execSync(`docker inspect ${image} --format '{{json .Config}}'`, {
      encoding: 'utf-8',
    });
    const history = execSync(`docker history ${image} --format '{{json .CreatedBy}}' --no-trunc`, {
      encoding: 'utf-8',
    });

    return {
      config: JSON.parse(config),
      history: history.trim().split('\n').map(line => JSON.parse(line)),
    };
  } catch {
    return null;
  }
}

async function extractImageLayers(image: string, destDir: string): Promise<string[]> {
  try {
    execSync(`docker save ${image} -o /tmp/${image.replace('/', '_')}.tar`, {
      stdio: 'pipe',
    });

    execSync(`mkdir -p ${destDir} && tar -xf /tmp/${image.replace('/', '_')}.tar -C ${destDir}`, {
      stdio: 'pipe',
    });

    execSync(`rm -f /tmp/${image.replace('/', '_')}.tar`, { stdio: 'pipe' });

    const layers: string[] = [];
    const manifestPath = join(destDir, 'manifest.json');
    if (existsSync(manifestPath)) {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
      for (const item of manifest) {
        for (const layer of item.Layers || []) {
          const layerPath = join(destDir, layer.replace(/\/$/, ''));
          if (existsSync(layerPath)) {
            layers.push(layerPath);
          }
        }
      }
    }

    return layers;
  } catch {
    return [];
  }
}

async function scanFileContent(filePath: string, verify: boolean): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  try {
    const content = readFileSync(filePath, 'utf-8');

    const awsResults = await detectAWS(content, { verify, file: filePath });
    results.push(...awsResults);

    const githubResults = await detectGitHub(content, { verify, file: filePath });
    results.push(...githubResults);

    const slackResults = await detectSlack(content, { verify, file: filePath });
    results.push(...slackResults);

    const gcpResults = await detectGCP(content, { verify, file: filePath });
    results.push(...gcpResults);

    const azureResults = await detectAzure(content, { verify, file: filePath });
    results.push(...azureResults);
  } catch {
    // Skip unreadable files
  }
  return results;
}

async function getImageInfo(image: string): Promise<{ imageId: string; layerCount: number }> {
  try {
    const inspect = execSync(`docker inspect ${image} --format '{{.Id}}:{{len .RootFS.Layers}}'`, {
      encoding: 'utf-8',
    });
    const [imageId, layerCountStr] = inspect.trim().split(':');
    return {
      imageId,
      layerCount: parseInt(layerCountStr, 10) || 0,
    };
  } catch {
    return { imageId: 'unknown', layerCount: 0 };
  }
}

export async function scanContainerImage(
  image: string,
  options: ContainerScanOptions = { verify: false }
): Promise<ContainerScanResult> {
  const results: ScanResult[] = [];
  const configFiles: string[] = [];
  const extractDir = options.extractDir || join(tmpdir(), `tailsec-${Date.now()}`);

  let filesScanned = 0;
  let imageId = 'unknown';
  let layerCount = 0;

  try {
    mkdirSync(extractDir, { recursive: true });

    const imageInfo = await getImageInfo(image);
    imageId = imageInfo.imageId;
    layerCount = imageInfo.layerCount;

    const dockerConfig = extractDockerConfig(image);
    if (dockerConfig) {
      const configContent = JSON.stringify(dockerConfig.config);
      const envVars = dockerConfig.config.Env || [];
      const combined = configContent + '\n' + envVars.join('\n');

      const awsResults = await detectAWS(combined, { verify: options.verify, file: 'Dockerfile' });
      results.push(...awsResults);

      const githubResults = await detectGitHub(combined, { verify: options.verify, file: 'Dockerfile' });
      results.push(...githubResults);

      const slackResults = await detectSlack(combined, { verify: options.verify, file: 'Dockerfile' });
      results.push(...slackResults);

      const gcpResults = await detectGCP(combined, { verify: options.verify, file: 'Dockerfile' });
      results.push(...gcpResults);

      const azureResults = await detectAzure(combined, { verify: options.verify, file: 'Dockerfile' });
      results.push(...azureResults);

      configFiles.push('Dockerfile', 'dockerconfig.json');
    }

    const layers = await extractImageLayers(image, extractDir);

    const fileTypesToScan = ['.env', '.json', '.yaml', '.yml', '.sh', '.bash', '.conf', '.cfg', '.txt', '.toml'];

    for (const layerDir of layers) {
      try {
        const files = execSync(`find ${layerDir} -type f 2>/dev/null | head -100`, {
          encoding: 'utf-8',
        });

        for (const file of files.trim().split('\n').filter(Boolean)) {
          if (!fileTypesToScan.some(ext => file.endsWith(ext))) continue;

          const fileResults = await scanFileContent(file, options.verify || false);
          results.push(...fileResults);
          filesScanned++;
        }
      } catch {
        // Skip layer if unreadable
      }
    }
  } finally {
    try {
      rmSync(extractDir, { recursive: true, force: true });
    } catch {
      // Cleanup failed, that's ok
    }
  }

  return {
    image,
    imageId,
    layerCount,
    secrets: results,
    configFiles,
    summary: {
      filesScanned,
      secretsFound: results.length,
    },
  };
}

export function formatContainerResults(result: ContainerScanResult): string {
  const lines: string[] = [];
  lines.push(`\nContainer Scan Results`);
  lines.push('='.repeat(50));
  lines.push(`Image:       ${result.image}`);
  lines.push(`Image ID:    ${result.imageId}`);
  lines.push(`Layers:      ${result.layerCount}`);
  lines.push(`Files Scanned: ${result.summary.filesScanned}`);
  lines.push(`Secrets Found: ${result.summary.secretsFound}`);
  lines.push('-'.repeat(50));

  if (result.secrets.length === 0) {
    lines.push('\n✓ No secrets found in container');
  } else {
    for (const secret of result.secrets) {
      lines.push(`\n[${secret.type}]`);
      lines.push(`  Redacted: ${secret.redacted}`);
      lines.push(`  File: ${secret.file || 'unknown'}`);
      if (secret.verified) lines.push(`  ✓ Verified`);
    }
  }

  return lines.join('\n');
}
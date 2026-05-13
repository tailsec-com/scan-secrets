/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

#!/usr/bin/env node

import https from 'https';
import { createWriteStream, readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { pipeline } from 'stream/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, '../data');

const TRUFFLEHOG_RELEASES_URL = 'https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest';

const REMAPPING = {
  'aws': 'aws',
  'github': 'github',
  'slack': 'slack',
  'gcp': 'gcp',
  'azure': 'azure',
  'stripe': 'stripe',
  'sendgrid': 'sendgrid',
  'npm': 'npm',
  'ssh': 'ssh',
  'jwt': 'jwt',
};

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Tailsec/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = createWriteStream(dest);
    https.get(url, (res) => {
      pipeline(res, file).then(resolve).catch(reject);
    }).on('error', reject);
  });
}

function parseTrufflehogPattern(detector) {
  const type = detector.Type || detector.type;
  if (!type) return null;

  const [service, ...rest] = type.toLowerCase().split('_');
  const id = service.replace(/[^a-z]/g, '');
  const mapId = REMAPPING[id] || id;

  const activePatterns = (detector.Keywords || []).filter(k => k !== '').slice(0, 10);
  if (activePatterns.length === 0) return null;

  const patternStr = activePatterns.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const entropy = mapId === 'jwt' ? 5.0 : 4.5;

  return {
    id: mapId,
    name: service.charAt(0).toUpperCase() + service.slice(1),
    patterns: [{
      type: type.replace('_', ' '),
      regex: patternStr.includes('|') ? `(${patternStr})[A-Za-z0-9]{20,}` : `${patternStr}[A-Za-z0-9]{20,}`,
      entropy,
      verify: { type: 'http', method: 'GET', url: `https://api.${service}.com/v1/verify`, authType: 'bearer', redactAuth: true },
      rotatonUrl: `https://dashboard.${service}.com/settings/keys`,
    }],
    examples: [],
  };
}

async function syncPatterns() {
  console.log('Fetching latest Trufflehog release...');

  let release;
  try {
    release = await httpGet(TRUFFLEHOG_RELEASES_URL);
  } catch (err) {
    console.error('Failed to fetch release info:', err.message);
    console.log('Using cached patterns if available...');
    return;
  }

  console.log(`Latest release: ${release.tag_name}`);
  console.log(`Published: ${release.published_at}`);

  const asset = release.assets?.find(a => a.name.includes('rules.tar.gz'));
  if (!asset) {
    console.log('No rules asset found in release');
    return;
  }

  const cacheDir = join(__dirname, '../.cache');
  mkdirSync(cacheDir, { recursive: true });
  const rulesPath = join(cacheDir, 'trufflehog-rules.tar.gz');

  console.log(`\nDownloading rules from ${asset.browser_download_url}...`);
  try {
    await downloadFile(asset.browser_download_url, rulesPath);
    console.log('Rules downloaded successfully');
  } catch (err) {
    console.error('Download failed:', err.message);
    return;
  }

  try {
    execSync(`tar -xzf ${rulesPath} -C ${cacheDir}`, { stdio: 'pipe' });
    console.log('Rules extracted');
  } catch (err) {
    console.error('Extraction failed:', err.message);
    return;
  }

  const ruleFiles = execSync(`find ${cacheDir} -name "*.json" | head -20`, { encoding: 'utf-8' })
    .trim().split('\n').filter(Boolean);

  console.log(`\nFound ${ruleFiles.length} rule files`);
  console.log('\nPattern sync complete.');
  console.log(`Rules cached at: ${cacheDir}`);
  console.log('\nTo use updated patterns, run: npm run build');
}

syncPatterns().catch(console.error);
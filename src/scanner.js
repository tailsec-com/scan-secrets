/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

#!/usr/bin/env node
import { readFileSync } from 'fs';
import { basename } from 'path';

const SCANNER_NAME = '@tailsec/scan-secrets';
const SCANNER_VERSION = '0.1.0';

function findFindings(content) {
  const findings = [];

  const secretPatterns = [
    { pattern: /password\s*[:=]\s*["'][^"']{6,}["']/gi, ruleId: 'SECRET-PASSWORD', severity: 'critical' },
    { pattern: /api[_-]?key\s*[:=]\s*["'][^"']{10,}["']/gi, ruleId: 'SECRET-API-KEY', severity: 'critical' },
    { pattern: /secret\s*[:=]\s*["'][^"']{8,}["']/gi, ruleId: 'SECRET-HARDCODED', severity: 'critical' },
    { pattern: /token\s*[:=]\s*["'][^"']{10,}["']/gi, ruleId: 'SECRET-TOKEN', severity: 'critical' },
    { pattern: /sk-live-[a-zA-Z0-9]{20,}/g, ruleId: 'SECRET-API-KEY', severity: 'critical' },
    { pattern: /tok_live_[a-zA-Z0-9]{20,}/g, ruleId: 'SECRET-TOKEN', severity: 'critical' },
    { pattern: /aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["'][A-Z0-9]{16,}["']/gi, ruleId: 'SECRET-AWS-KEY', severity: 'critical' }
  ];

  for (const { pattern, ruleId, severity } of secretPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      for (const match of matches) {
        const lineNum = content.substring(0, content.indexOf(match)).split('\n').length;
        findings.push({
          ruleId,
          severity,
          description: `Potential hardcoded secret detected: ${match.substring(0, 20)}...`,
          resource: basename('config'),
          line: lineNum
        });
      }
    }
  }

  return findings;
}

const args = process.argv.slice(2);
let filePath = args.find(a => !a.startsWith('--')) || '/dev/stdin';
const format = args.includes('--format=sarif') ? 'sarif' : 'json';
const severityFilter = args.find(a => a.startsWith('--severity='))?.split('=')[1];

if (filePath === '/dev/stdin' || filePath === '-') {
  filePath = '/dev/stdin';
}

let content;
try {
  content = filePath === '/dev/stdin' ? readFileSync(0, 'utf-8') : readFileSync(filePath, 'utf-8');
} catch (e) {
  console.error(JSON.stringify({ error: `Cannot read file: ${filePath}` }));
  process.exit(1);
}

const findings = findFindings(content);

const critical = findings.filter(f => f.severity === 'critical').length;
const high = findings.filter(f => f.severity === 'high').length;
const medium = findings.filter(f => f.severity === 'medium').length;
const low = findings.filter(f => f.severity === 'low').length;

if (format === 'sarif') {
  const sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": SCANNER_NAME,
          "version": SCANNER_VERSION,
          "informationUri": "https://tailsec.com"
        }
      },
      "results": findings.map(f => ({
        "ruleId": f.ruleId,
        "level": f.severity === 'critical' ? 'error' : f.severity === 'high' ? 'warning' : 'note',
        "message": { "text": f.description },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": filePath },
            "region": { "startLine": f.line }
          }
        }]
      }))
    }]
  };
  console.log(JSON.stringify(sarif, null, 2));
} else {
  const output = {
    summary: { total: findings.length, critical, high, medium, low },
    secrets: findings
  };
  console.log(JSON.stringify(output, null, 2));
}

if (critical > 0) {
  process.exit(1);
}
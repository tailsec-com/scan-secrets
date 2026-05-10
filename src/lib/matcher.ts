import { PatternRule, ScanResult } from '../types.js';
import { shannonEntropy, cleanString } from './entropy.js';

export interface MatchContext {
  file?: string;
  line?: number;
}

export class PatternMatcher {
  private rules: PatternRule[];

  constructor(rules: PatternRule[]) {
    this.rules = rules;
  }

  scan(content: string, ctx: MatchContext = {}): ScanResult[] {
    const results: ScanResult[] = [];
    const cleanedContent = cleanString(content);

    for (const rule of this.rules) {
      const regex = new RegExp(rule.regex, 'g');

      for (const match of cleanedContent.matchAll(regex)) {
        const secret = match[1] || match[0];
        const secretLower = secret.toLowerCase();

        const hasKeywords = !rule.keywords ||
          rule.keywords.some(kw => secretLower.includes(kw.toLowerCase()));

        const passesEntropy = !rule.entropy ||
          shannonEntropy(secret) >= rule.entropy;

        if (hasKeywords && passesEntropy) {
          results.push({
            type: rule.type,
            detectorId: 'generic',
            raw: secret,
            redacted: this.redact(secret),
            verified: false,
            line: ctx.line,
            file: ctx.file,
          });
        }
      }
    }

    return this.deduplicateResults(results);
  }

  private redact(secret: string): string {
    if (secret.length <= 8) return '****';
    const visible = Math.min(4, Math.floor(secret.length * 0.1));
    return secret.slice(0, visible) + '****' + secret.slice(-visible);
  }

  private deduplicateResults(results: ScanResult[]): ScanResult[] {
    const seen = new Set<string>();
    return results.filter(r => {
      const key = `${r.type}:${r.raw}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

export function matchPatterns(
  content: string,
  rules: PatternRule[],
  ctx: MatchContext = {}
): ScanResult[] {
  const matcher = new PatternMatcher(rules);
  return matcher.scan(content, ctx);
}
/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { PatternRule, ScanResult } from '../types.js';
export interface MatchContext {
    file?: string;
    line?: number;
}
export declare class PatternMatcher {
    private rules;
    constructor(rules: PatternRule[]);
    scan(content: string, ctx?: MatchContext): ScanResult[];
    private redact;
    private deduplicateResults;
}
export declare function matchPatterns(content: string, rules: PatternRule[], ctx?: MatchContext): ScanResult[];

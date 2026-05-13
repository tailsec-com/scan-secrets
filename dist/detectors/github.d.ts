/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanResult } from '../types.js';
export declare function detectGitHub(content: string, options?: {
    verify?: boolean;
    file?: string;
    line?: number;
}): Promise<ScanResult[]>;

/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanOptions, ScanResult } from '../types.js';
export declare function detectJWT(content: string, options?: ScanOptions): Promise<ScanResult[]>;

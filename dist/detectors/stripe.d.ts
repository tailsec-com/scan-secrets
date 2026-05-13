/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanOptions, ScanResult } from '../types.js';
export declare function detectStripe(content: string, options?: ScanOptions): Promise<ScanResult[]>;

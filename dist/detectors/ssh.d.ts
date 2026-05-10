import { ScanOptions, ScanResult } from '../types.js';
export declare function detectSSH(content: string, options?: ScanOptions): Promise<ScanResult[]>;

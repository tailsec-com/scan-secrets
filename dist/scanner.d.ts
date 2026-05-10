import { ScanOptions, ScanResult } from './types.js';
export interface ScanSummary {
    filesScanned: number;
    secretsFound: number;
    verifiedCount: number;
    results: ScanResult[];
}
export declare function scanDirectory(dirPath: string, options?: ScanOptions): Promise<ScanSummary>;
export declare function formatResults(summary: ScanSummary, format?: 'json' | 'text' | 'sarif'): string;

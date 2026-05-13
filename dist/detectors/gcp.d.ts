/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

import { ScanResult } from '../types.js';
export interface GCPResult extends ScanResult {
    extraData: {
        credential_type?: string;
        project_id?: string;
        rotation_guide?: string;
    };
}
export declare function detectGCP(content: string, options?: {
    verify?: boolean;
    file?: string;
    line?: number;
}): Promise<GCPResult[]>;

import { ScanResult } from '../types.js';
export interface AzureResult extends ScanResult {
    extraData: {
        credential_type?: string;
        tenant_id?: string;
        rotation_guide?: string;
    };
}
export declare function detectAzure(content: string, options?: {
    verify?: boolean;
    file?: string;
    line?: number;
}): Promise<AzureResult[]>;

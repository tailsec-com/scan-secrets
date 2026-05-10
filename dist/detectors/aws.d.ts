import { ScanResult } from '../types.js';
export interface AWSResult extends ScanResult {
    secretParts?: {
        accessKeyId: string;
        secretAccessKey: string;
    };
    extraData: {
        account?: string;
        user_id?: string;
        arn?: string;
        resource_type?: string;
        rotation_guide?: string;
    };
}
export declare function detectAWS(content: string, options?: {
    verify?: boolean;
    file?: string;
    line?: number;
}): Promise<AWSResult[]>;

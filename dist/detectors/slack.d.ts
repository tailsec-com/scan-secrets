import { ScanResult } from '../types.js';
export interface SlackResult extends ScanResult {
    extraData: {
        token_type?: string;
        rotation_guide?: string;
    };
}
export declare function detectSlack(content: string, options?: {
    verify?: boolean;
    file?: string;
    line?: number;
}): Promise<SlackResult[]>;

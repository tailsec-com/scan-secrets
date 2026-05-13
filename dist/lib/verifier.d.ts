/**
 * @license MIT
 * Copyright (c) 2024 Tailsec
 */

export interface VerifyResult {
    verified: boolean;
    extraData?: Record<string, string>;
    error?: string;
}
export declare function verifyAWS(accessKeyId: string, secretKey: string): Promise<VerifyResult>;
export declare function verifyGitHub(token: string): Promise<VerifyResult>;
export declare function verifyGeneric(url: string, headers: Record<string, string>): Promise<VerifyResult>;

import { ScanResult } from '../types.js';
export interface GitCommit {
    hash: string;
    author: string;
    date: string;
    message: string;
}
export interface SecretInCommit {
    secret: ScanResult;
    commit: GitCommit;
    diff: string;
}
export declare function scanGitHistory(dirPath: string, options?: {
    verify?: boolean;
    maxCommits?: number;
}): Promise<SecretInCommit[]>;
export declare function formatGitResults(results: SecretInCommit[]): string;

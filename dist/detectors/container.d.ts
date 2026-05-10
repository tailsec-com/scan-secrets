import { ScanResult } from '../types.js';
export interface ContainerScanOptions {
    image?: string;
    verify?: boolean;
    extractDir?: string;
}
export interface ContainerScanResult {
    image: string;
    imageId: string;
    layerCount: number;
    secrets: ScanResult[];
    configFiles: string[];
    summary: {
        filesScanned: number;
        secretsFound: number;
    };
}
export declare function scanContainerImage(image: string, options?: ContainerScanOptions): Promise<ContainerScanResult>;
export declare function formatContainerResults(result: ContainerScanResult): string;

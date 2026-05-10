export interface PatternRule {
  type: string;
  regex: string;
  entropy?: number;
  keywords?: string[];
  verify?: VerifierConfig;
}

export interface VerifierConfig {
  type: 'aws-sts' | 'http' | 'none';
  endpoint?: string;
  method?: string;
  headers?: Record<string, string>;
}

export interface DetectorDefinition {
  id: string;
  name: string;
  patterns: PatternRule[];
  keywords: string[];
  description: string;
  documentation?: string;
}

export interface ScanResult {
  type: string;
  detectorId: string;
  raw: string;
  redacted: string;
  verified: boolean;
  extraData?: Record<string, string | undefined>;
  line?: number;
  file?: string;
  verification?: {
    type: string;
    method?: string;
    url?: string;
    authType?: 'bearer' | 'api_key' | 'basic';
    redactAuth?: boolean;
  };
  secretParts?: {
    accessKeyId?: string;
    secretKey?: string;
  };
}

export interface ScanOptions {
  verify?: boolean;
  includeHistory?: boolean;
  excludePatterns?: string[];
  outputFormat?: 'json' | 'text' | 'sarif';
  file?: string;
  line?: number;
}
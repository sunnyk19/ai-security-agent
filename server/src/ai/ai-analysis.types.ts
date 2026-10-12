import type { FindingSeverity } from '../security/security.types.js';

export type VulnerabilityAnalysis = {
  whatIsWrong: string;
  whyVulnerable: string;
  rootCause: string;
  risk: FindingSeverity;
  recommendedFix: string;
  filesToModify: string[];
  testsToAdd: string[];
  confidence: number;
};

export type FixCandidate = {
  status: 'candidate';
  verified: false;
  file: string;
  originalCode: string;
  proposedCode: string;
  explanation: string;
  testsToAdd: string[];
};
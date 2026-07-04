import * as vscode from 'vscode';

export interface SecurityIssue {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: 'critical' | 'warning' | 'info';
  owaspCategory: string;
  line: number;
  column: number;
  matchedText: string;
  source: 'sast' | 'llm' | 'secret-shield';
  fix?: string;
}

export interface SecurityGrade {
  letter: 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  description: string;
  criticalCount: number;
  warningCount: number;
  infoCount: number;
}

export interface OwaspCoverage {
  id: string;
  name: string;
  status: 'checked' | 'found' | 'scanning';
  issueCount: number;
}

export interface ScanResult {
  documentUri: string;
  timestamp: number;
  grade: SecurityGrade;
  issues: SecurityIssue[];
  owaspCoverage: OwaspCoverage[];
  language: string;
  linesScanned: number;
}

export interface FixSuggestion {
  id: string;
  issueId: string;
  description: string;
  replacement: string;
  explanation: string;
  range: vscode.Range;
}

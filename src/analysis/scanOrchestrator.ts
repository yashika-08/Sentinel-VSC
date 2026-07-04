import * as vscode from 'vscode';
import { SASTEngine } from './sastEngine';
import { LLMSecurityCritic } from './llmCritic';
import { SecretShieldWorker } from './secretShield';
import { SentinelDiagnosticsProvider } from '../providers/diagnosticsProvider';
import {
  ScanResult, SecurityIssue, SecurityGrade,
  OwaspCoverage, FixSuggestion
} from '../utils/types';

export class ScanOrchestrator {
  private sastEngine: SASTEngine;
  private llmCritic: LLMSecurityCritic;
  private secretShield: SecretShieldWorker;
  private diagnostics: SentinelDiagnosticsProvider;
  private scanCache = new Map<string, { result: ScanResult; hash: string }>();
  private listeners: ((result: ScanResult) => void)[] = [];

  constructor(diagnostics: SentinelDiagnosticsProvider, secretShield: SecretShieldWorker) {
    this.diagnostics = diagnostics;
    this.secretShield = secretShield;
    this.sastEngine = new SASTEngine();
    this.llmCritic = new LLMSecurityCritic();
  }

  async scanDocument(doc: vscode.TextDocument): Promise<ScanResult> {
    const code = doc.getText();
    const hash = this.hashCode(code);
    const cached = this.scanCache.get(doc.uri.toString());
    if (cached?.hash === hash) return cached.result;

    // Step 1: Secret Shield (synchronous, pre-render)
    const secretIssues = await this.secretShield.scan(doc);

    // Step 2: SAST Engine
    const config = vscode.workspace.getConfiguration('sentinel');
    let sastIssues: SecurityIssue[] = [];
    if (config.get('enableSAST')) {
      sastIssues = await this.sastEngine.analyze(code, doc.languageId);
    }

    // Step 3: LLM Security Critic (async enrichment)
    let llmIssues: SecurityIssue[] = [];
    if (config.get('enableLLMCritic')) {
      try {
        llmIssues = await this.llmCritic.analyze(code, doc.languageId, sastIssues);
      } catch (e) {
        console.warn('Sentinel: LLM critic unavailable, using SAST only:', e);
      }
    }

    // Merge + deduplicate
    const allIssues = this.mergeIssues([...secretIssues, ...sastIssues, ...llmIssues]);

    // Compute grade
    const grade = this.computeGrade(allIssues);

    // OWASP coverage
    const owaspCoverage = this.computeOwaspCoverage(allIssues);

    const result: ScanResult = {
      documentUri: doc.uri.toString(),
      timestamp: Date.now(),
      grade,
      issues: allIssues,
      owaspCoverage,
      language: doc.languageId,
      linesScanned: doc.lineCount
    };

    // Update diagnostics
    this.diagnostics.update(doc.uri, allIssues);

    // Cache
    this.scanCache.set(doc.uri.toString(), { result, hash });

    // Notify listeners
    this.listeners.forEach(fn => fn(result));

    return result;
  }

  async generateFix(doc: vscode.TextDocument, issueId: string): Promise<FixSuggestion | null> {
    const cached = this.scanCache.get(doc.uri.toString());
    if (!cached) return null;

    const issue = cached.result.issues.find(i => i.id === issueId);
    if (!issue) return null;

    // Use LLM critic to generate a targeted fix
    return this.llmCritic.generateFix(doc.getText(), issue, doc.languageId);
  }

  onScanComplete(listener: (result: ScanResult) => void) {
    this.listeners.push(listener);
    return { dispose: () => { this.listeners = this.listeners.filter(l => l !== listener); } };
  }

  private mergeIssues(issues: SecurityIssue[]): SecurityIssue[] {
    const seen = new Set<string>();
    return issues.filter(issue => {
      const key = `${issue.line}-${issue.ruleId}-${issue.owaspCategory}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).sort((a, b) => {
      const sev = { critical: 0, warning: 1, info: 2 };
      return (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3);
    });
  }

  private computeGrade(issues: SecurityIssue[]): SecurityGrade {
    let score = 100;
    const criticals = issues.filter(i => i.severity === 'critical').length;
    const warnings = issues.filter(i => i.severity === 'warning').length;
    const infos = issues.filter(i => i.severity === 'info').length;

    score -= criticals * 25;
    score -= warnings * 10;
    score -= infos * 3;
    score = Math.max(0, Math.min(100, score));

    let letter: 'A' | 'B' | 'C' | 'D' | 'F';
    if (score >= 90) letter = 'A';
    else if (score >= 75) letter = 'B';
    else if (score >= 60) letter = 'C';
    else if (score >= 40) letter = 'D';
    else letter = 'F';

    const descriptions: Record<string, string> = {
      A: 'Excellent — no significant issues',
      B: 'Good — minor issues only',
      C: 'Fair — some vulnerabilities need attention',
      D: 'Poor — significant security risks',
      F: 'Critical — immediate action required'
    };

    return {
      letter,
      score,
      description: descriptions[letter],
      criticalCount: criticals,
      warningCount: warnings,
      infoCount: infos
    };
  }

  private computeOwaspCoverage(issues: SecurityIssue[]): OwaspCoverage[] {
    const owaspItems = [
      { id: 'A01', name: 'Broken Access Control' },
      { id: 'A02', name: 'Cryptographic Failures' },
      { id: 'A03', name: 'Injection' },
      { id: 'A04', name: 'Insecure Design' },
      { id: 'A05', name: 'Security Misconfiguration' },
      { id: 'A06', name: 'Vulnerable Components' },
      { id: 'A07', name: 'Identification & Auth Failures' },
      { id: 'A08', name: 'Software & Data Integrity' },
      { id: 'A09', name: 'Security Logging Failures' },
      { id: 'A10', name: 'Server-Side Request Forgery' },
    ];

    return owaspItems.map(item => {
      const related = issues.filter(i => i.owaspCategory === item.id);
      return {
        id: item.id,
        name: item.name,
        status: related.length > 0 ? 'found' : 'checked',
        issueCount: related.length
      };
    });
  }

  private hashCode(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  dispose() {
    this.scanCache.clear();
    this.listeners = [];
  }
}

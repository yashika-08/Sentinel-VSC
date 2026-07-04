import * as vscode from 'vscode';
import { ScanOrchestrator } from '../analysis/scanOrchestrator';
import { ScanResult, SecurityIssue } from '../utils/types';

export class SentinelCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  public readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
  private scanResults = new Map<string, ScanResult>();

  constructor(private orchestrator: ScanOrchestrator) {
    this.orchestrator.onScanComplete((result) => {
      this.scanResults.set(result.documentUri, result);
      this._onDidChangeCodeLenses.fire();
    });
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken
  ): vscode.CodeLens[] {
    const result = this.scanResults.get(document.uri.toString());
    if (!result || result.issues.length === 0) return [];

    const lenses: vscode.CodeLens[] = [];

    // Group issues by line
    const issuesByLine = new Map<number, SecurityIssue[]>();
    for (const issue of result.issues) {
      const lineIssues = issuesByLine.get(issue.line) ?? [];
      lineIssues.push(issue);
      issuesByLine.set(issue.line, lineIssues);
    }

    for (const [lineNum, issues] of issuesByLine) {
      const line = Math.max(0, lineNum - 1);
      const range = new vscode.Range(line, 0, line, 0);
      const topIssue = issues[0];

      const gradeEmoji = topIssue.severity === 'critical' ? '🔴' : topIssue.severity === 'warning' ? '🟡' : '🔵';
      const severityLabel = topIssue.severity.toUpperCase();

      // Main CodeLens: security grade + description
      lenses.push(new vscode.CodeLens(range, {
        title: `${gradeEmoji} Sentinel [${severityLabel}] ${topIssue.title} — ${topIssue.owaspCategory}`,
        command: 'sentinel.openPanel',
        tooltip: topIssue.description
      }));

      // Fix action lens
      lenses.push(new vscode.CodeLens(range, {
        title: '🔧 Fix with Sentinel',
        command: 'sentinel.fixIssue',
        arguments: [topIssue.id],
        tooltip: `AI-powered fix: ${topIssue.fix ?? 'Click to generate fix'}`
      }));

      // If multiple issues on same line
      if (issues.length > 1) {
        lenses.push(new vscode.CodeLens(range, {
          title: `+${issues.length - 1} more issue${issues.length > 2 ? 's' : ''}`,
          command: 'sentinel.openPanel',
          tooltip: issues.slice(1).map(i => i.title).join('\n')
        }));
      }
    }

    // Summary lens at top of file
    const topRange = new vscode.Range(0, 0, 0, 0);
    const criticals = result.issues.filter(i => i.severity === 'critical').length;
    const warnings = result.issues.filter(i => i.severity === 'warning').length;

    lenses.unshift(new vscode.CodeLens(topRange, {
      title: `🛡 Sentinel: Grade ${result.grade.letter} (${result.grade.score}/100) · ${criticals} critical · ${warnings} warning`,
      command: 'sentinel.openPanel',
      tooltip: result.grade.description
    }));

    return lenses;
  }

  refresh() {
    this._onDidChangeCodeLenses.fire();
  }
}

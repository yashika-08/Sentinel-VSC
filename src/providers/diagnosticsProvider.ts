import * as vscode from 'vscode';
import { SecurityIssue } from '../utils/types';

export class SentinelDiagnosticsProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel');
  }

  update(uri: vscode.Uri, issues: SecurityIssue[]) {
    const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
      const line = Math.max(0, issue.line - 1);
      const col = issue.column ?? 0;
      const range = new vscode.Range(
        new vscode.Position(line, col),
        new vscode.Position(line, col + (issue.matchedText?.length ?? 10))
      );

      const severity = issue.severity === 'critical'
        ? vscode.DiagnosticSeverity.Error
        : issue.severity === 'warning'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

      const diag = new vscode.Diagnostic(
        range,
        `[Sentinel] ${issue.title}: ${issue.description}`,
        severity
      );

      diag.source = `Sentinel (${issue.source.toUpperCase()})`;
      diag.code = {
        value: issue.owaspCategory,
        target: vscode.Uri.parse(`https://owasp.org/Top10/${issue.owaspCategory}`)
      };

      if (issue.fix) {
        diag.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(vscode.Uri.parse('sentinel:fix'), range),
            `Fix: ${issue.fix}`
          )
        ];
      }

      return diag;
    });

    this.diagnosticCollection.set(uri, diagnostics);
  }

  clear(uri: vscode.Uri) {
    this.diagnosticCollection.delete(uri);
  }

  clearAll() {
    this.diagnosticCollection.clear();
  }

  dispose() {
    this.diagnosticCollection.dispose();
  }
}

import * as vscode from 'vscode';
import { ScanOrchestrator } from '../analysis/scanOrchestrator';
import { OwaspCoverage } from '../utils/types';

class OwaspTreeItem extends vscode.TreeItem {
  constructor(public readonly coverage: OwaspCoverage) {
    super(`${coverage.id}: ${coverage.name}`, vscode.TreeItemCollapsibleState.None);
    this.description = coverage.status === 'found'
      ? `⚠ ${coverage.issueCount} issue${coverage.issueCount !== 1 ? 's' : ''}`
      : '✓ Clear';

    this.iconPath = new vscode.ThemeIcon(
      coverage.status === 'found' ? 'warning' : 'pass',
      new vscode.ThemeColor(
        coverage.status === 'found' ? 'editorWarning.foreground' : 'testing.iconPassed'
      )
    );
    this.contextValue = 'owaspItem';
  }
}

export class SentinelOwaspTreeProvider implements vscode.TreeDataProvider<OwaspTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private coverage: OwaspCoverage[] = [];

  constructor(private orchestrator: ScanOrchestrator) {}

  refresh(coverage: OwaspCoverage[]) {
    this.coverage = coverage;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: OwaspTreeItem): vscode.TreeItem { return element; }

  getChildren(): OwaspTreeItem[] {
    return this.coverage.map(c => new OwaspTreeItem(c));
  }
}

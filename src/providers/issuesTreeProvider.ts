import * as vscode from 'vscode';
import { ScanOrchestrator } from '../analysis/scanOrchestrator';
import { SecurityIssue } from '../utils/types';

class IssueTreeItem extends vscode.TreeItem {
  constructor(
    public readonly issue: SecurityIssue,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(issue.title, collapsibleState);
    this.tooltip = issue.description;
    this.description = `L${issue.line} · ${issue.owaspCategory}`;

    this.iconPath = new vscode.ThemeIcon(
      issue.severity === 'critical' ? 'error' :
      issue.severity === 'warning' ? 'warning' : 'info',
      new vscode.ThemeColor(
        issue.severity === 'critical' ? 'errorForeground' :
        issue.severity === 'warning' ? 'editorWarning.foreground' : 'editorInfo.foreground'
      )
    );

    this.command = {
      command: 'sentinel.fixIssue',
      title: 'Fix Issue',
      arguments: [issue.id]
    };

    this.contextValue = 'sentinelIssue';
  }
}

export class SentinelIssuesTreeProvider implements vscode.TreeDataProvider<IssueTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<IssueTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private issues: SecurityIssue[] = [];

  constructor(private orchestrator: ScanOrchestrator) {}

  refresh(issues: SecurityIssue[]) {
    this.issues = issues;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: IssueTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: IssueTreeItem): IssueTreeItem[] {
    if (element) return [];
    return this.issues.map(issue =>
      new IssueTreeItem(issue, vscode.TreeItemCollapsibleState.None)
    );
  }
}

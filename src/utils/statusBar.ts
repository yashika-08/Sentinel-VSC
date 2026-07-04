import * as vscode from 'vscode';
import { SecurityGrade } from './types';

export class StatusBarManager {
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = 'sentinel.openPanel';
    this.statusBarItem.show();
  }

  setReady() {
    this.statusBarItem.text = '$(shield) Sentinel Ready';
    this.statusBarItem.tooltip = 'Sentinel-VSC: Click to open security panel';
    this.statusBarItem.backgroundColor = undefined;
    this.statusBarItem.color = undefined;
  }

  setScanning() {
    this.statusBarItem.text = '$(loading~spin) Sentinel Scanning...';
    this.statusBarItem.tooltip = 'Sentinel is analyzing your code for vulnerabilities';
    this.statusBarItem.backgroundColor = undefined;
  }

  setGrade(grade: SecurityGrade) {
    const icons: Record<string, string> = {
      A: '$(pass-filled)',
      B: '$(pass)',
      C: '$(warning)',
      D: '$(error)',
      F: '$(error)'
    };

    this.statusBarItem.text = `${icons[grade.letter] ?? '$(shield)'} Sentinel: ${grade.letter} (${grade.score}/100)`;
    this.statusBarItem.tooltip = `Sentinel Security Grade: ${grade.letter}\n${grade.description}\nCritical: ${grade.criticalCount} | Warnings: ${grade.warningCount}`;

    if (['D', 'F'].includes(grade.letter)) {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (grade.letter === 'C') {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      this.statusBarItem.backgroundColor = undefined;
      this.statusBarItem.color = new vscode.ThemeColor('statusBarItem.prominentForeground');
    }
  }

  setError() {
    this.statusBarItem.text = '$(shield) Sentinel Error';
    this.statusBarItem.tooltip = 'Sentinel scan failed. Check Output panel for details.';
    this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }

  dispose() {
    this.statusBarItem.dispose();
  }
}

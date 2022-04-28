import * as vscode from 'vscode';

export class Code4ArmDebugConfigurationProvider implements vscode.DebugConfigurationProvider {
    public provideDebugConfigurations(folder: vscode.WorkspaceFolder | undefined, token?: vscode.CancellationToken): vscode.ProviderResult<vscode.DebugConfiguration[]> {
        // TODO
        return [];
    }
}
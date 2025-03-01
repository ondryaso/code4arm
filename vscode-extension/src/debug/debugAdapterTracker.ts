import * as vscode from "vscode";
import { DebugProtocol } from '@vscode/debugprotocol';
import { SessionService } from "./sessionService";
import { Disposable } from "vscode-languageclient";


export class Code4ArmDebugAdapterTracker implements vscode.DebugAdapterTracker {

    private _onDidChangeApsrEmitter = new vscode.EventEmitter<number>();
    public readonly onDidChangeApsr: vscode.Event<number> = this._onDidChangeApsrEmitter.event;

    private _onDidChangeApsrAvailableEmitter = new vscode.EventEmitter<boolean>();
    public readonly onDidChangeApsrAvailable: vscode.Event<boolean> = this._onDidChangeApsrAvailableEmitter.event;

    private _lastApsrAvailableValue: boolean = false;

    private _session?: vscode.DebugSession;
    private _lastEventDisposable?: Disposable;

    constructor(private _sessionService: SessionService) {
    }

    setSession(session: vscode.DebugSession) {
        this._session = session;
    }

    onWillStartSession(): void {
        if (this._session) {
            const session = this._session!;

            this._lastEventDisposable?.dispose();
            this._lastEventDisposable = this._sessionService.onDidAttachToSession(
                (e) => this._sessionService.syncRemoteFiles(session), this);
        }

        this.emitApsrAvailableIfChanged(false);
    }

    onWillStopSession(): void {
        this.emitApsrAvailableIfChanged(false);
    }

    onDidSendMessage(message: any): void {
        const dapMessage = message as DebugProtocol.Response;

        if (dapMessage.command === 'scopes' && dapMessage.success && this.setSession !== null) {
            const scopesMessage = message as DebugProtocol.ScopesResponse;
            const scopes = scopesMessage.body.scopes;

            this.checkScopeAndRequest(scopes);
            return;
        }

        if (dapMessage.command !== 'variables' || !dapMessage.success) {
            return;
        }

        const variablesMessage = message as DebugProtocol.VariablesResponse;
        const variables = variablesMessage.body.variables;

        this.checkVariables(variables);
    }

    private checkVariables(variables: DebugProtocol.Variable[]) {
        for (const variable of variables) {
            if (variable == null) continue;

            if (variable.name === 'APSR') {
                const value = parseInt(variable.value, 16);
                this._onDidChangeApsrEmitter.fire(value);
                this.emitApsrAvailableIfChanged(true);
            }
        }
    }

    // Checks if the 'CPU state' variables scope is available. If it is, explicitly requests its variables.
    private checkScopeAndRequest(scopes: DebugProtocol.Scope[]) {
        for (const scope of scopes) {
            if (scope == null) continue;

            if (scope.name === 'CPU state') {
                var req: DebugProtocol.VariablesArguments = {
                    variablesReference: scope.variablesReference
                };

                this._session!.customRequest('variables', req);
                this.emitApsrAvailableIfChanged(true);

                return;
            }
        }

        // Scope not found, emit the 'available' event with 'false' value
        this.emitApsrAvailableIfChanged(false);
    }

    private emitApsrAvailableIfChanged(available: boolean) {
        if (this._lastApsrAvailableValue != available) {
            this._lastApsrAvailableValue = available;
            this._onDidChangeApsrAvailableEmitter.fire(available);
        }
    }
}

export class Code4ArmDebugAdapterTrackerFactory implements vscode.DebugAdapterTrackerFactory {
    public readonly instance: Code4ArmDebugAdapterTracker;

    constructor(sessionService: SessionService) {
        this.instance = new Code4ArmDebugAdapterTracker(sessionService);
    }

    createDebugAdapterTracker(session: vscode.DebugSession): vscode.ProviderResult<vscode.DebugAdapterTracker> {
        this.instance.setSession(session);
        return this.instance;
    }
}
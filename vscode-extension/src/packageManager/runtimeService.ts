import * as net from 'net';
import * as vscode from 'vscode';
import { ChildProcess, spawn } from 'child_process';

import * as portfinder from 'portfinder';
import { Disposable } from 'vscode-languageclient';
import { ServerOptions, StreamInfo } from 'vscode-languageclient/node';
import { MainConfigurationService } from '../configuration/mainConfigurationService';
import { activateDebugAdapter, deactivateDebugAdapter } from '../debug/debugActivator';
import { activateLanguageSupport, deactivateLanguageSupport } from '../lang/langSupportActivator';
import * as dev from '../dev_consts';
import { getDotnetPath } from './dotnetAcquire';

export class RuntimeService implements Disposable {
    private _dotnetPath?: string;
    private _languageServicesInitialized: boolean = false;
    private _debuggerServicesInitialized: boolean = false;
    private _currentProcess?: ChildProcess;
    private _debuggerOutputChannel?: vscode.OutputChannel;

    constructor(private _configService: MainConfigurationService, private _extensionContext: vscode.ExtensionContext) {
        _configService.onDidUpdateDebuggerServices(this.initRuntime, this);
        _configService.onDidUpdateLanguageServices(this.initRuntime, this);
        _configService.onDidChangeRuntimeMode(this.onRuntimeModeChange, this);
        _configService.onDidChangeRemoteAddress(this.onRemoteAddressChange, this);
    }

    public async initRuntime() {
        const state = this._configService.get();

        if (state.enableLanguageServices || (state.enableDebuggerServices && state.useLocalRuntimeInstallation)) {
            this._dotnetPath = await getDotnetPath(this._extensionContext.extension.id);
            if (!this._dotnetPath)
                return;

            await this.setLanguageSupport(state.enableLanguageServices);
            await this.setDebuggerSupport(state.enableDebuggerServices);
        } else {
            this._dotnetPath = undefined;

            await this.setLanguageSupport(state.enableLanguageServices);
            if (state.enableDebuggerServices && !state.useLocalRuntimeInstallation) {
                await this.setDebuggerSupport(true);
            }
        }
    }

    private async setLanguageSupport(enableLanguageServices: boolean) {
        if (enableLanguageServices) {
            if (!this._languageServicesInitialized)
                await activateLanguageSupport(this._extensionContext, this);

            this._languageServicesInitialized = true;
        } else {
            if (this._languageServicesInitialized)
                await deactivateLanguageSupport();

            this._languageServicesInitialized = false;
        }
    }

    private async setDebuggerSupport(enableDebuggerServices: boolean) {
        if (enableDebuggerServices) {
            if (!this._debuggerServicesInitialized)
                await activateDebugAdapter(this._extensionContext, this._configService, this);

            this._debuggerServicesInitialized = true;
        } else {
            if (this._debuggerServicesInitialized)
                deactivateDebugAdapter();

            this._debuggerServicesInitialized = false;
        }
    }

    private async onRuntimeModeChange(useLocal: boolean) {
        if (this._debuggerServicesInitialized) {
            deactivateDebugAdapter();
            this._debuggerServicesInitialized = false;
        }

        await this.initRuntime();
    }

    private async onRemoteAddressChange(address: string) {
        await this.onRuntimeModeChange(this._configService.get().useLocalRuntimeInstallation);
    }

    public async makeLanguageServerOptions(): Promise<ServerOptions> {
        if (dev.DevMode) {
            const serverOptions = () => {
                const stream = net.connect({ host: dev.LanguageServerHost, port: dev.LanguageServerPort });

                let result: StreamInfo = {
                    writer: stream,
                    reader: stream
                };

                return Promise.resolve(result);
            };

            return serverOptions;
        } else {
            if (!this._dotnetPath)
                throw new Error();

            const serverDirUri = vscode.Uri.joinPath(this._extensionContext.extensionUri, 'servers', 'language');
            const dllUri = vscode.Uri.joinPath(this._extensionContext.extensionUri, 'servers', 'language', 'Code4Arm.LanguageServer.dll');
            const exeArgs = [dllUri.fsPath];

            return {
                run: {
                    command: this._dotnetPath,
                    args: exeArgs,
                    options: { cwd: serverDirUri.fsPath }
                },
                debug: {
                    command: this._dotnetPath,
                    args: exeArgs,
                    options: { cwd: serverDirUri.fsPath }
                }
            };
        }
    }

    public async makeDebugger(): Promise<string | null> {
        const config = this._configService.get();
        if (this._currentProcess && this._currentProcess.exitCode === null)
            this._currentProcess.kill();

        if (config.useLocalRuntimeInstallation) {
            if (dev.DevMode && dev.ExecutionServiceAddress != null)
                return dev.ExecutionServiceAddress;

            if (!this._dotnetPath)
                throw new Error();

            const serverDirUri = vscode.Uri.joinPath(this._extensionContext.extensionUri, 'servers', 'debug');
            const dllUri = vscode.Uri.joinPath(this._extensionContext.extensionUri, 'servers', 'debug', 'Code4Arm.ExecutionService.dll');
            const freePort = await portfinder.getPortPromise();
            const exeArgs = [dllUri.fsPath];
            const url = `http://127.0.0.1:${freePort}`;
            const env = { ASPNETCORE_URLS: url };

            if (!this._debuggerOutputChannel)
                this._debuggerOutputChannel = vscode.window.createOutputChannel("Arm Simulator Service");

            this._currentProcess = spawn(this._dotnetPath, exeArgs, { env: env, detached: false, cwd: serverDirUri.fsPath });
            this._currentProcess.stdout?.on('data', data => {
                this._debuggerOutputChannel?.append(data.toString());
            });

            await new Promise(r => setTimeout(r, 3000)); // TODO: figure out a better mechanism for waiting for the service initialization
            return url;
        } else {
            if (!config.remoteRuntimeAddress)
                throw new Error();

            return config.remoteRuntimeAddress;
        }
    }

    dispose(): void {
        deactivateLanguageSupport();
        deactivateDebugAdapter();
        if (this._currentProcess && this._currentProcess.exitCode === null)
            this._currentProcess.kill();
    }

}

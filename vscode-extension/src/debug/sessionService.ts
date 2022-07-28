// sessionService.ts
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

import { debug, DebugSession, Disposable, EventEmitter, Event, TextDocument, Uri, window, workspace } from "vscode";
import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';
import { DebugConfigurationService } from "./configuration/debugConfigurationService";

/**
 * Manages a 'tool' connection to a *remote* execution service.
 * If the current configuration uses a local service, the functions in this class are
 * basically no-ops.
 */
export class SessionService implements Disposable {

    private readonly _connection?: HubConnection;
    private _sessionId: string | null = null;

    private _sessionAttachedEmitter: EventEmitter<string> = new EventEmitter<string>();
    public readonly onDidAttachToSession: Event<string> = this._sessionAttachedEmitter.event;
    private _toolConfigChangeHandlerDisposable?: Disposable;

    constructor(private _configService: DebugConfigurationService) {
        const url = _configService.getToolAddress();
        if (!url) {
            if (_configService.isRemote()) {
                throw new Error();
            }

            return;
        }
        
        const builder = new HubConnectionBuilder()
            .withUrl(url)
            .configureLogging(LogLevel.Information);

        this._connection = builder.build();
    }

    public async getSessionId(): Promise<string | null> {
        if (!this._configService.isRemote()) {
            return null;
        }

        if (!(await this.ensureConnected())) {
            await window.showErrorMessage('Cannot connect to the remote Code4Arm service.');
            return null;
        }

        if (this._sessionId === null) {
            await this.makeNewSession();
        } else {
            const attachResponse = await this._connection?.invoke('AttachToSession', this._sessionId);
            if (!attachResponse) {
                await this.makeNewSession();
            }
        }

        if (this._sessionId !== null) {
            this._sessionAttachedEmitter.fire(this._sessionId);
        }

        return this._sessionId;
    }

    public async syncRemoteFiles(debugSession: DebugSession) {
        if (!this._configService.isRemote()) {
            await workspace.saveAll();
            return;
        }

        const files = debugSession.configuration.sourceFiles;

        if (typeof files == 'undefined') {
            await debug.stopDebugging(debugSession);
            await window.showErrorMessage('When using a remote Code4Arm service, the launch configuration must use sourceFiles, not sourceDirectory.');

            return;
        }

        const workspaceFiles: TextDocument[] = [];
        let filesVersions = [];

        await workspace.saveAll();
        for (const file of files) {
            const uri = Uri.file(file);
            const doc = await workspace.openTextDocument(uri);
            workspaceFiles.push(doc);
            filesVersions.push({ name: file, version: doc.version });
        }

        const toSend: number[] = await this._connection!.invoke('RequestedFiles', filesVersions);
        if (toSend.length === 0) {
            return;
        }

        filesVersions = [];
        for (const toSendIndex of toSend) {
            const doc = workspaceFiles[toSendIndex];
            const text = doc.getText();
            filesVersions.push({ name: files[toSendIndex], version: doc.version, text: text });
        }

        await this._connection!.invoke('SyncFiles', filesVersions);
    }

    public async closeSession() {
        if (this._connection?.state === HubConnectionState.Connected) {
            await this._connection.invoke('closeSession');
            this._sessionId = null;
        }
    }

    public async dispose() {
        if (this._connection) {
            await this.closeSession();
            this._connection.stop();
        }

        this._sessionAttachedEmitter.dispose();
        this._toolConfigChangeHandlerDisposable?.dispose();
    }

    private async makeNewSession() {
        this.log('Asking for a new session.');
        this._sessionId = await this._connection?.invoke('CreateSession') ?? null;

        if (this._sessionId !== null) {
            this.log('Pushing editor configuration (from SeSrv).');
            await this._connection!.invoke('UseClientConfiguration', this._configService.getConfigurationForService());

            this._toolConfigChangeHandlerDisposable?.dispose();
            this._toolConfigChangeHandlerDisposable = this._configService.onDidChangeClientConfiguration(
                async (c) => await this._connection!.invoke('UseClientConfiguration', c), this)
        } else {
            await window.showErrorMessage('Cannot use the remote Code4Arm service (error when establishing session).');
        }
    }

    private async ensureConnected(): Promise<boolean> {
        if (!this._configService.isRemote())
            return true;

        if (this._connection!.state == HubConnectionState.Disconnected) {
            const _this = this;

            this._connection!.onclose((error?: Error) => { _this.handleConnectionClose(error) });

            try {
                await this._connection!.start();
                this.log('Tool connection started.');
                return true;
            } catch (err) {
                this.logError(err);
                return false;
            }
        }

        return true;
    }

    private handleConnectionClose(error?: Error | undefined) {
        // TODO
        if (error) {
            this.logError(error);
        } else {
            this.log('Connection closed.');
        }
    }

    private log(msg: any) {
        console.info(msg);
    }

    private logError(msg: any) {
        console.error(msg);
    }
}
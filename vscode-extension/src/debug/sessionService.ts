import { debug, DebugSession, Disposable, EventEmitter, Event, TextDocument, Uri, window, workspace } from "vscode";
import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';

export class SessionService implements Disposable {

    private readonly _connection?: HubConnection;
    private _sessionId: string | null = null;

    private _sessionAttachedEmitter: EventEmitter<string> = new EventEmitter<string>();
    public readonly onDidAttachToSession: Event<string> = this._sessionAttachedEmitter.event;

    constructor() {
        const builder = new HubConnectionBuilder()
            .withUrl('http://localhost:5058/toolSession')
            .configureLogging(LogLevel.Information);

        this._connection = builder.build();
    }

    public async getSessionId(): Promise<string | null> {
        // TODO: when lost connection, attach to existing session
        if (!this.isRemote()) {
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

    private async makeNewSession() {
        this._sessionId = await this._connection?.invoke('CreateSession') ?? null;
    }

    private async ensureConnected(): Promise<boolean> {
        if (!this.isRemote())
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

    public isRemote(): boolean {
        // TODO
        return false;
    }

    public async initDebugging(debugSession: DebugSession) {
        if (!this.isRemote()) {
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
    }

    private log(msg: any) {
        console.info(msg);
    }

    private logError(msg: any) {
        console.error(msg);
    }
}
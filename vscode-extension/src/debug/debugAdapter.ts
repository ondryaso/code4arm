import { DebugSession, ExitedEvent, logger, LoggingDebugSession, Response, TerminatedEvent } from '@vscode/debugadapter';
import { DebugProtocol } from '@vscode/debugprotocol';
import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';
import { ProtocolServer } from '@vscode/debugadapter/lib/protocol';
import { SessionService } from './sessionService';
import { DebugConfigurationService } from './configuration/debugConfigurationService';
import { Disposable } from 'vscode-languageclient';

interface ICustomLaunchRequestArguments extends DebugProtocol.LaunchRequestArguments {
    sourceDirectory?: string;
    sourceFiles?: string[];
}

interface IDebuggerResponse {
    success: boolean;
    message?: string;
    body?: any;
}

enum ServiceLogLevel {
    Trace = 0,
    Debug,
    Information,
    Warning,
    Error,
    Critical,
    None,
}


export class Code4ArmDebugSession extends ProtocolServer {

    private readonly _connection: HubConnection;
    private _toolConfigChangeHandlerDisposable?: Disposable;

    public constructor(private _configService: DebugConfigurationService, private _sessionService: SessionService) {
        super();

        const builder = new HubConnectionBuilder()
            .withUrl('http://localhost:5058/debuggerSession')
            .configureLogging(LogLevel.Information);

        this._connection = builder.build();
    }

    private log(msg: any) {
        const protoEvent: DebugProtocol.OutputEvent = {
            seq: 0,
            type: 'event',
            event: 'output',
            body: {
                output: msg,
                category: 'console'
            }
        };

        this.sendEvent(protoEvent);
        console.info(msg);
    }

    private logError(msg: any) {
        const protoEvent: DebugProtocol.OutputEvent = {
            seq: 0,
            type: 'event',
            event: 'output',
            body: {
                output: msg,
                category: 'console'
            }
        };

        this.sendEvent(protoEvent);
        console.error(msg);
    }


    private handleServiceLog(eventId: number, message: string, description: string) {
        this.log(description);
    }

    private async ensureConnected(): Promise<boolean> {
        if (this._connection.state == HubConnectionState.Disconnected) {
            const _this = this;

            this._connection.on('HandleEvent', (eventName: string, body: any | null) => { _this.handleRemoteEvent(eventName, body); });
            this._connection.on('Log', (id: number, name: string, message: string) => { _this.handleServiceLog(id, name, message); });

            this._connection.onclose((error?: Error) => { _this.handleConnectionClose(error) });

            try {
                await this._connection.start();
                return true;
            } catch (err) {
                this.logError(err);
                return false;
            }
        }

        // TODO: wait for connection?
        return true;
    }

    private handleRemoteEvent(eventName: string, body: any | null) {
        console.info("-> EVENT " + eventName);

        const protoEvent: DebugProtocol.Event = {
            event: eventName,
            type: 'event',
            seq: 0
        };

        if (body != null) {
            protoEvent.body = body;
        }

        this.sendEvent(protoEvent);
    }

    private handleConnectionClose(error?: Error | undefined) {
        // TODO
        console.info("Connection closed");

        this.sendEvent(new TerminatedEvent());
        this.stop();

        if (!this._isRunningInline()) {
            setTimeout(() => { process.exit(0); }, 100);
        }
    }

    private makeErrorResponse(request: DebugProtocol.Request, message: string, description: string, id: number, showUser?: boolean): DebugProtocol.Response {
        const errorResponse = new Response(request);
        errorResponse.success = false;

        const errorMessage: DebugProtocol.Message = {
            id: id,
            format: description,
            showUser: (typeof showUser === 'undefined' ? true : showUser),
            sendTelemetry: true
        };

        (<any>errorResponse).message = message;
        (<any>errorResponse).body = {
            error: errorMessage
        };

        return errorResponse;
    }

    private async dispatchPreInitTasks(request: DebugProtocol.Request): Promise<boolean> {
        let errResponse: DebugProtocol.Response | null = null;

        if (this._configService.isRemote()) {
            // If remote, attach this debugger SignalR connection to the session created by the tool (SessionService)
            const sessionId = await this._sessionService.getSessionId();
            if (sessionId !== null) {
                this.log(`Attaching the debug adapter to session ${sessionId}.`);
                await this._connection.invoke('AttachToSession', sessionId);
            } else {
                errResponse = this.makeErrorResponse(request, 'remoteConnectionError',
                    'Cannot connect to the execution service (cannot get session ID).', 1002, false);
            }
        } else {
            // If not remote, pass client configuration
            this.log('Pushing editor configuration (from DA).');
            const config = this._configService.getConfigurationForService();

            try {
                await this._connection.invoke('UseClientConfiguration', config);

                this._toolConfigChangeHandlerDisposable = this._configService.onDidChangeClientConfiguration(
                    async (c) => await this._connection.invoke('UseClientConfiguration', c), this)
            } catch {
                errResponse = this.makeErrorResponse(request, 'remoteConnectionError',
                    'Cannot connect to the execution service (error pushing configuration).', 1003, false);
            }
        }

        if (errResponse !== null) {
            this.sendResponse(errResponse);
            this.handleConnectionClose();

            return false;
        }

        return true;
    }

    protected async dispatchRequest(request: DebugProtocol.Request) {
        if (!(await this.ensureConnected())) {
            const response = this.makeErrorResponse(request, 'remoteConnectionError',
                'Cannot connect to the execution service.', 1001);

            this.sendResponse(response);
            this.handleConnectionClose();
            return;
        }

        if (request.command == 'initialize') {
            if (!(await this.dispatchPreInitTasks(request)))
                return;
        }

        try {
            const remoteMethodName = request.command.charAt(0).toUpperCase() + request.command.slice(1);
            console.info("<- REQ " + remoteMethodName);

            let remoteResponse: IDebuggerResponse;

            if (typeof request.arguments === 'undefined' || request.arguments === null) {
                remoteResponse = await this._connection.invoke<IDebuggerResponse>(remoteMethodName, null);
            } else {
                remoteResponse = await this._connection.invoke<IDebuggerResponse>(remoteMethodName, request.arguments);
            }

            let response: DebugProtocol.Response = new Response(request);

            response.success = remoteResponse.success;
            response.body = remoteResponse.body;

            if (!remoteResponse.success) {
                response.message = remoteResponse.message;
            }

            console.info("   | RESP " + (response.success ? "Success" : ("Error " + response.message)) + " (" + remoteMethodName + ")");

            this.sendResponse(response);
        } catch (err) {
            this.logError(err);
            const response = this.makeErrorResponse(request, 'unexpectedError', 'Unexpected execution service error. Connection ID: ' + this._connection.connectionId, 1000, false);
            this.sendResponse(response);
        }
    }

    override dispose() {
        super.dispose();
        this._toolConfigChangeHandlerDisposable?.dispose();
    }
}

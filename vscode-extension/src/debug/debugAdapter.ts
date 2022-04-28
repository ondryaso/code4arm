import { DebugSession, ExitedEvent, logger, LoggingDebugSession, Response, TerminatedEvent } from '@vscode/debugadapter';
import { DebugProtocol } from '@vscode/debugprotocol';
import { HubConnection, HubConnectionBuilder, HubConnectionState, LogLevel } from '@microsoft/signalr';
import { ProtocolServer } from '@vscode/debugadapter/lib/protocol';

interface ICustomLaunchRequestArguments extends DebugProtocol.LaunchRequestArguments {
    sourceDirectory?: string;
    sourceFiles?: string[];
}

interface IDebuggerResponse {
    success: boolean;
    message?: string;
    body?: any;
}

export class Code4ArmDebugSession extends ProtocolServer {

    private readonly connection: HubConnection;


    public constructor() {
        super();

        const builder = new HubConnectionBuilder()
            .withUrl('http://localhost:5058/debuggerSession')
            .configureLogging(LogLevel.Information);

        this.connection = builder.build();
    }

    private log(msg: any) {
        // TODO
        console.info(msg);
    }

    private logError(msg: any) {
        // TODO
        console.error(msg);
    }

    private async ensureConnected(): Promise<boolean> {
        if (this.connection.state == HubConnectionState.Disconnected) {
            this.connection.on('HandleEvent', this.handleRemoteEvent);
            this.connection.onclose(this.handleConnectionClose);

            try {
                await this.connection.start();
                return true;
            } catch (err) {
                this.logError(err);
                return false;
            }
        }

        // TODO: wait for connection?
        return true;
    }

    private handleRemoteEvent(eventName: string, body: any) {
        this.log("-> EVENT " + eventName);

        const protoEvent: DebugProtocol.Event = {
            event: eventName,
            type: 'event',
            body: body,
            seq: 0
        };

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

    private makeErrorResponse(request: DebugProtocol.Request, message: string, description: string, id: number): DebugProtocol.Response {
        const errorResponse = new Response(request);
        errorResponse.success = false;

        const errorMessage: DebugProtocol.Message = {
            id: id,
            format: description,
            showUser: true
        };

        (<any>errorResponse).message = message;
        (<any>errorResponse).body = {
            error: errorMessage
        };

        return errorResponse;
    }

    protected async dispatchRequest(request: DebugProtocol.Request) {
        if (!(await this.ensureConnected())) {
            const response = this.makeErrorResponse(request, 'remoteConnectionError', 'Cannot connect to the execution service', 100);
            this.sendResponse(response);
            this.sendEvent(new TerminatedEvent());
        }

        try {
            const remoteMethodName = request.command.charAt(0).toUpperCase() + request.command.slice(1);
            this.log("<- REQ " + remoteMethodName);

            let remoteResponse: IDebuggerResponse;

            if (typeof request.arguments === 'undefined' || request.arguments === null) {
                remoteResponse = await this.connection.invoke<IDebuggerResponse>(remoteMethodName, null);
            } else {
                remoteResponse = await this.connection.invoke<IDebuggerResponse>(remoteMethodName, request.arguments);
            }

            let response: DebugProtocol.Response = new Response(request);

            response.success = remoteResponse.success;
            response.body = remoteResponse.body;

            if (!remoteResponse.success) {
                response.message = remoteResponse.message;
            }

            this.sendResponse(response);
        } catch (err) {
            this.logError(err);
            const response = this.makeErrorResponse(request, 'remoteError', 'Unhandled execution service error.', 101);
            this.sendResponse(response);
        }
    }
}
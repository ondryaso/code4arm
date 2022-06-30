import * as vscode from 'vscode';
import { Disposable, LanguageClient, LanguageClientOptions, StreamInfo, Trace } from 'vscode-languageclient/node';
import { commands, ExtensionContext, OutputChannel, Range, TextDocumentShowOptions, window } from 'vscode';
import { RuntimeService } from '../packageManager/runtimeService';

let client: LanguageClient;
let clientDisposable: Disposable;
let outputChannel: OutputChannel;

export async function activateLanguageSupport(context: ExtensionContext, runtimeService: RuntimeService) {
    const refreshHandler = async () => {
        const currentIndex = context.subscriptions.indexOf(clientDisposable);
        context.subscriptions.splice(currentIndex, 1);

        outputChannel.appendLine("\n--- Refreshing Code4Arm connection ---\n");

        await initLanguageServer(context, runtimeService);
    };

    const labelRefsHandler = async (line: number, char: number) => {
        const doc = window.activeTextEditor?.document;
        if (!doc)
            return;

        const opts: TextDocumentShowOptions = {
            selection: new Range(line, char, line, char)
        };

        await window.showTextDocument(doc, opts);
        await commands.executeCommand('editor.action.goToReferences');
    };

    context.subscriptions.push(commands.registerCommand('code4arm.refreshConnection', refreshHandler));
    context.subscriptions.push(commands.registerCommand('code4arm.labelAndReferences', labelRefsHandler));

    outputChannel = window.createOutputChannel("Arm UAL Language Server");
    await initLanguageServer(context, runtimeService);
    context.subscriptions.push(outputChannel);
}

export async function deactivateLanguageSupport() {
	if (!client) {
		return;
	}

	await client.stop();
}

async function initLanguageServer(context: ExtensionContext, runtimeService: RuntimeService) {
    // Options to control the language client
    const clientOptions: LanguageClientOptions = {
        // Register the server for plain text documents
        documentSelector: [{ scheme: 'file', language: 'arm-ual' }],
        diagnosticCollectionName: "arm-ual",
        outputChannel: outputChannel,
        synchronize: {
            // Notify the server about file changes to '.clientrc files contained in the workspace
            fileEvents: [
                vscode.workspace.createFileSystemWatcher('**/.s'),
                vscode.workspace.createFileSystemWatcher('**/.S')
            ]
        },
        markdown: {
            isTrusted: true
        }
    };

    // Get server options
    const serverOptions = await runtimeService.makeLanguageServerOptions();

    // Create the language client and start the client.
    client = new LanguageClient(
        'arm-ual',
        'Arm UAL',
        serverOptions,
        clientOptions
    );

    client.trace = Trace.Verbose;

    // Start the client. This will also launch the server
    clientDisposable = client.start();
    context.subscriptions.push(clientDisposable);
}
import * as net from 'net';
import { workspace, ExtensionContext, commands, OutputChannel, window, SignatureHelp } from 'vscode';

import {
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	Executable,
	TransportKind,
	Trace,
	StreamInfo
} from 'vscode-languageclient/node';

let client: LanguageClient;

export async function activate(context: ExtensionContext) {
	await initLanguageServer(context);
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}

	return client.stop();
}

async function initLanguageServer(context: ExtensionContext) {
	// TODO: find dotnet path: https://github.com/YarnSpinnerTool/VSCodeExtension/blob/main/src/extension.ts

	/*
	const dotnetPath = "dotnet";
	const exeArgs = ["run", "--project",
		"/home/ondryaso/Projects/bp/Armulator/Armfors.LanguageServer"];

	const serverOptions: ServerOptions = {
		run: {
			command: dotnetPath,
			args: exeArgs
		},
		debug: {
			command: dotnetPath,
			args: exeArgs
		}
	};
	*/

	const serverOptions = () => {
		const stream = net.connect({ host: '127.0.0.1', port: 5057 });

		let result: StreamInfo = {
			writer: stream,
			reader: stream
		};

		return Promise.resolve(result);
	};

	const outputChannel: OutputChannel = window.createOutputChannel("Arm UAL Language Server");


	// Options to control the language client
	const clientOptions: LanguageClientOptions = {
		// Register the server for plain text documents
		documentSelector: [{ scheme: 'file', language: 'arm-ual' }],
		diagnosticCollectionName: "arm-ual",
		outputChannel: outputChannel,
		synchronize: {
			// Notify the server about file changes to '.clientrc files contained in the workspace
			fileEvents: [
				workspace.createFileSystemWatcher('**/.s'),
				workspace.createFileSystemWatcher('**/.S')
			]
		},
		markdown: {
			isTrusted: true
		}
	};

	// Create the language client and start the client.
	client = new LanguageClient(
		'arm-ual',
		'Arm UAL',
		serverOptions,
		clientOptions
	);

	client.trace = Trace.Verbose;

	// Start the client. This will also launch the server
	let disposable = client.start();
	context.subscriptions.push(disposable);
}

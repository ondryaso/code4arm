"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const net = require("net");
const vscode_1 = require("vscode");
const node_1 = require("vscode-languageclient/node");
let client;
async function activate(context) {
    await initLanguageServer(context);
}
exports.activate = activate;
function deactivate() {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
exports.deactivate = deactivate;
async function initLanguageServer(context) {
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
        let result = {
            writer: stream,
            reader: stream
        };
        return Promise.resolve(result);
    };
    const outputChannel = vscode_1.window.createOutputChannel("Arm UAL Language Server");
    // Options to control the language client
    const clientOptions = {
        // Register the server for plain text documents
        documentSelector: [{ scheme: 'file', language: 'arm-ual' }],
        diagnosticCollectionName: "arm-ual",
        outputChannel: outputChannel,
        synchronize: {
            // Notify the server about file changes to '.clientrc files contained in the workspace
            fileEvents: [
                vscode_1.workspace.createFileSystemWatcher('**/.s'),
                vscode_1.workspace.createFileSystemWatcher('**/.S')
            ]
        }
    };
    // Create the language client and start the client.
    client = new node_1.LanguageClient('arm-ual', 'Arm UAL', serverOptions, clientOptions);
    client.trace = node_1.Trace.Verbose;
    // Start the client. This will also launch the server
    let disposable = client.start();
    context.subscriptions.push(disposable);
}
//# sourceMappingURL=main.js.map
import * as vscode from 'vscode';

export class ApsrViewProvider implements vscode.WebviewViewProvider {

	public static readonly viewType = 'code4arm.apsr';

	private _view?: vscode.WebviewView;

	constructor(
		private readonly _extensionUri: vscode.Uri,
        private readonly _onDidChangeApsr: vscode.Event<number>,
        private readonly _onDidChangeApsrAvailable: vscode.Event<boolean>
	) { }

	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken,
	) {
		this._view = webviewView;

		webviewView.webview.options = {
			// Allow scripts in the webview
			enableScripts: true,

			// Allow the webview to load resources from the extension files 
			localResourceRoots: [
				this._extensionUri
			]
		};

		webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);
        this._onDidChangeApsr(this.onApsrChange, this);
        this._onDidChangeApsrAvailable(this.onApsrAvailableChange, this)
	}

    public onApsrAvailableChange(available: boolean) {
		if (!this._view) {
            return;
		}

        this._view.webview.postMessage({ enabled: available });
    }

	public onApsrChange(apsr: number) {
		if (!this._view) {
            return;
		}

        const n = (apsr & (1 << 31)) !== 0;
        const z = (apsr & (1 << 30)) !== 0;
        const c = (apsr & (1 << 29)) !== 0;
        const v = (apsr & (1 << 28)) !== 0;

        this._view.webview.postMessage({ n, z, c, v });
	}

	private getHtmlForWebview(webview: vscode.Webview) {
		// Convert local resource paths to 'webview URIs' available from within the webview 
		const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'apsrWebview', 'main.js'));
		const styleResetUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'reset.css'));
		const styleVSCodeUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'vscode.css'));
		const styleMainUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'apsrWebview', 'main.css'));

		// Use a nonce to only allow a specific script to be run
		const nonce = getNonce();

		return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<link href="${styleResetUri}" rel="stylesheet">
				<link href="${styleVSCodeUri}" rel="stylesheet">
				<link href="${styleMainUri}" rel="stylesheet">
				
				<title>Arm APSR</title>
			</head>
			<body>
                <div id="not-available">
                    The CPU status flags are not available.
                    <i>Control variables</i> must be enabled.
                </div>

                <div id="main-grid" class="grid hidden">
                    <div id="n" title="Negative">
                        <span class="label-full">Negative</span>
                        <span class="label-abbr">N</span>
                        <span class="bit"></span>
                    </div>
                    <div id="z" title="Zero">
                        <span class="label-full">Zero</span>
                        <span class="label-abbr">Z</span>
                        <span class="bit"></span>
                    </div>
                    <div id="c" title="Carry">
                        <span class="label-full">Carry</span>
                        <span class="label-abbr">C</span>
                        <span class="bit"></span>
                    </div>
                    <div id="v" title="Overflow">
                        <span class="label-full">Overflow</span>
                        <span class="label-abbr">O</span>
                        <span class="bit"></span>
                    </div>
                </div>
				<script nonce="${nonce}" src="${scriptUri}"></script>
			</body>
			</html>`;
	}
}

function getNonce() {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}
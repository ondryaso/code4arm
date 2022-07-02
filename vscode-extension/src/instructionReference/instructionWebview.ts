import * as vscode from 'vscode';
import { Uri } from 'vscode';
import { readFile } from 'node:fs/promises';
import { MnemonicProvider } from './instructionsProvider';

export class InstructionWebviewService {
    private _dataUri: Uri;
    private _mediaUri: Uri;

    private _sharedPseudocodeView?: vscode.WebviewPanel;
    private _views: Map<string, vscode.WebviewPanel> = new Map<string, vscode.WebviewPanel>();

    constructor(_dataPath: string, private _extensionUri: Uri, private _provider: MnemonicProvider) {
        this._dataUri = Uri.file(_dataPath);
        this._mediaUri = Uri.joinPath(this._extensionUri, 'media', 'instructionWebview');
    }

    private async makeBody(webview: vscode.Webview, docLink: string): Promise<string> {
        const path = Uri.joinPath(this._dataUri, docLink).fsPath;
        let body = await readFile(path, { encoding: 'utf-8' });

        const stylePath = Uri.joinPath(this._mediaUri, 'insn_custom.css');
        const styleSrc = webview.asWebviewUri(stylePath);
        const origStylePath = Uri.joinPath(this._dataUri, 'insn.css');
        const origStyleSrc = webview.asWebviewUri(origStylePath);
        const scriptSrc = webview.asWebviewUri(Uri.joinPath(this._mediaUri, 'main.js'));

        body = body.replace('href="insn.css"/>', `href="${origStyleSrc.toString()}"/><link rel="stylesheet" type="text/css" href="${styleSrc.toString()}"/>`);

        // cut header
        body = body.replace('<body>', '<body><!--');
        body = body.replace('</table><hr/>', '</table><hr/>-->');
        // cut footer
        body = body.replace('<hr/><table style="margin: 0 auto;">', '<!--<hr/><table style="margin: 0 auto;">');
        body = body.replace('</body>', `--><script type="text/javascript" src="${scriptSrc}"></script></body>`);

        return body;
    }

    public async viewInstruction(docLink?: string | undefined, mnemonic?: string | undefined) {
        if (!docLink) {
            if (!mnemonic) {
                throw new Error('Invalid instruction documentation request.');
            }

            docLink = await this._provider.getDocLinkForMnemonic(mnemonic);
        }

        docLink = docLink.trim();

        const existing = this._views.get(docLink);
        if (existing) {
            try {
                existing.reveal();
                return;
            } catch {
                this._views.delete(docLink);
            }
        }

        const panel = vscode.window.createWebviewPanel('code4arm.mnemonicWebview',
            mnemonic ?? 'Instruction', vscode.ViewColumn.One,
            {
                localResourceRoots: [this._mediaUri, this._dataUri],
                enableScripts: true,
                enableFindWidget: true
            }
        );

        panel.webview.onDidReceiveMessage(async (name: string) => {
            if (name === '__loaded')
                return;

            if (name.startsWith('shared_pseudocode.html')) {
                const anchorIndex = name.indexOf('#');

                if (anchorIndex > 0) {
                    const anchor = name.substring(anchorIndex + 1);
                    await this.viewSharedPseudocode(anchor);
                } else {
                    await this.viewSharedPseudocode();
                }

                return;
            }

            await this.viewInstruction(name);
        });

        const body = await this.makeBody(panel.webview, docLink);
        if (!mnemonic) {
            panel.title = this.getTitle(body);
        }

        panel.webview.html = body;

        this._views.set(docLink, panel);
        panel.onDidDispose(() => this._views.delete(docLink!));
        panel.reveal();
    }

    private _lastAnchor?: string;

    public async viewSharedPseudocode(anchor?: string | undefined) {
        const hasNewInstance = !this._sharedPseudocodeView;
        this._lastAnchor = anchor;

        if (hasNewInstance) {
            this._sharedPseudocodeView = vscode.window.createWebviewPanel('code4arm.mnemonicWebview',
                'Instruction pseudocodes', vscode.ViewColumn.One,
                {
                    localResourceRoots: [this._mediaUri, this._dataUri],
                    enableScripts: true,
                    retainContextWhenHidden: true,
                    enableFindWidget: true
                }
            );

            this._sharedPseudocodeView.webview.onDidReceiveMessage((m) => {
                if (m === '__loaded' && this._lastAnchor) {
                    this._sharedPseudocodeView?.webview.postMessage(this._lastAnchor);
                    this._lastAnchor = undefined;
                }
            });

            this._sharedPseudocodeView.onDidDispose(() => this._sharedPseudocodeView = undefined);

            const path = Uri.joinPath(this._dataUri, 'shared_pseudocode.html').fsPath;
            let body = await this.makeBody(this._sharedPseudocodeView.webview, 'shared_pseudocode.html');

            body = body.replace(/shared_pseudocode.html/g, "");
            this._sharedPseudocodeView.webview.html = body;
        }

        this._sharedPseudocodeView!.reveal();
        if (anchor && !hasNewInstance) {
            this._sharedPseudocodeView!.webview.postMessage(anchor);
        }
    }

    private getTitle(body: string): string {
        const mnemonicRegex = /<h2 class="instruction-section">(.*?)<\/h2>/;
        const mnemonicMatch = body.match(mnemonicRegex);
        const mnemonic = mnemonicMatch ? mnemonicMatch[1] : 'Instruction';

        return mnemonic;
    }
}

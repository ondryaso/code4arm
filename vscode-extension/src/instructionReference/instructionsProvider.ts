// instructionsProvider.ts
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

import * as vscode from 'vscode';
import { readFile } from 'node:fs/promises';

export class ParsedMnemonic {
    constructor(public readonly mnemonic: string,
        public readonly description: string,
        public readonly docLink: string) {
    }
}

export class MnemonicProvider {
    private _baseData?: ParsedMnemonic[];
    private _simdData?: ParsedMnemonic[];

    constructor(private _dataPath: string) {
    }

    public async getBaseMnemonics(): Promise<ParsedMnemonic[]> {
        if (!this._baseData)
            this._baseData = await this.parseIndexFile(this.getFilePath('index.html'));

        return this._baseData!;
    }

    public async getSimdMnemonics(): Promise<ParsedMnemonic[]> {
        if (!this._simdData)
            this._simdData = await this.parseIndexFile(this.getFilePath('fpsimdindex.html'));

        return this._simdData!;
    }

    public async getAllMnemonics(): Promise<ParsedMnemonic[]> {
        const base = await this.getBaseMnemonics();
        const simd = await this.getSimdMnemonics();

        return base.concat(simd);
    }

    async getDocLinkForMnemonic(mnemonic: string): Promise<string> {
        let m = (await this.getBaseMnemonics()).find((v, i, o) => v.mnemonic == mnemonic);
        if (!m)
            m = (await this.getSimdMnemonics()).find((v, i, o) => v.mnemonic == mnemonic);

        if (!m)
            throw new Error('Instruction documentation not found.');
        
        return m.docLink;
    }

    private async parseIndexFile(path: string): Promise<ParsedMnemonic[]> {
        const html = await readFile(path, {
            encoding: 'utf-8'
        });

        const regex = /<a href="(.*\.html)">(.*)<\/a>[:\n\s]*(.*?)(?:\.<\/span>|:)/g;
        const matches = html.matchAll(regex);

        let pd: ParsedMnemonic[] = Array.from(matches, (m, i) => new ParsedMnemonic(m[2], m[3], m[1]));

        return pd;
    }

    private getFilePath(file: string) {
        return vscode.Uri.joinPath(vscode.Uri.file(this._dataPath), file).fsPath;
    }
}

export class MnemonicTreeDataProvider implements vscode.TreeDataProvider<ParsedMnemonic> {

    onDidChangeTreeData?: vscode.Event<undefined> = undefined;

    constructor(private _provider: MnemonicProvider, private _simd: boolean) {
    }

    getTreeItem(element: ParsedMnemonic): vscode.TreeItem | Thenable<vscode.TreeItem> {
        let ti = new vscode.TreeItem(element.mnemonic, vscode.TreeItemCollapsibleState.None);
        ti.command = {
            command: 'code4arm.showInstructionReference',
            arguments: [element.mnemonic, element.docLink],
            title: 'Show documentation'
        };
        ti.description = element.description;
        ti.iconPath = new vscode.ThemeIcon('debug-breakpoint-log-unverified');

        return ti;
    }

    async getChildren(element?: ParsedMnemonic | undefined): Promise<ParsedMnemonic[]> {
        if (element)
            return [];

        return await (this._simd ? this._provider.getSimdMnemonics()
            : this._provider.getBaseMnemonics());
    }


}

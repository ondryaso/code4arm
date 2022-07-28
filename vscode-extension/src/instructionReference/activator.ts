// activator.ts
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

import { Uri } from 'vscode';
import { MnemonicProvider, MnemonicTreeDataProvider } from "./instructionsProvider";
import { InstructionWebviewService } from './instructionWebview';

let firstActivationAttempt = true;

export async function activateInstructionReference(context: vscode.ExtensionContext) {
    if (firstActivationAttempt) {
        context.subscriptions.push(vscode.commands.registerCommand('code4arm.fetchDocs',
            async () => {
                await context.globalState.update('noDocsPrompt', undefined);
                await activateInstructionReference(context);
            }));


        firstActivationAttempt = false;
    }

    const dataUri = await ensureDocs(context);
    if (!dataUri)
        return;

    const provider = new MnemonicProvider(dataUri);
    const viewService = new InstructionWebviewService(dataUri, context.extensionUri, provider);

    const baseProvider = new MnemonicTreeDataProvider(provider, false);
    const simdProvider = new MnemonicTreeDataProvider(provider, true);

    context.subscriptions.push(vscode.window.registerTreeDataProvider(
        'arm-instructions.base', baseProvider));
    context.subscriptions.push(vscode.window.registerTreeDataProvider(
        'arm-instructions.simd', simdProvider));

    context.subscriptions.push(vscode.commands.registerCommand('code4arm.showInstructionReference',
        (mnemonic, path) => viewService.viewInstruction(path, mnemonic)));
    context.subscriptions.push(vscode.commands.registerCommand('code4arm.showInstructionPseudocodes',
        () => viewService.viewSharedPseudocode()));
    context.subscriptions.push(vscode.commands.registerCommand('code4arm.findMnemonicDocumentation',
        () => pickInstruction(provider)));
    context.subscriptions.push(vscode.commands.registerCommand('code4arm.showIsaProprietaryNotice',
        () => viewService.viewInstruction('notice.html', 'Proprietary Notice')));
}

async function pickInstruction(provider: MnemonicProvider) {
    const quickPick = vscode.window.createQuickPick();
    const items = await provider.getAllMnemonics();

    quickPick.items = items.map(m => ({ label: m.mnemonic, description: m.description }));
    quickPick.matchOnDescription = true;

    quickPick.onDidHide(() => quickPick.dispose());
    quickPick.onDidAccept(() => {
        const i = quickPick.selectedItems[0];
        if (i)
            vscode.commands.executeCommand('code4arm.showInstructionReference', i.label);
    });
    quickPick.show();
}

export async function ensureDocs(context: vscode.ExtensionContext, cont: boolean = true): Promise<string | undefined> {
    const path = Uri.joinPath(context.globalStorageUri, 'docs');
    let exists = true;
    try {
        const files = await vscode.workspace.fs.readDirectory(path);

        if (files.length !== 0) {
            for (let f of files) {
                if (f[1] === vscode.FileType.Directory && f[0].startsWith('ISA_AArch32')) {
                    const dataUri = Uri.joinPath(path, f[0], 'xhtml');

                    try {
                        await vscode.workspace.fs.stat(dataUri);
                    } catch {
                        vscode.window.showErrorMessage('ISA documentation files seem to exist but the actual data directory doesn\'t.');
                        return;
                    }

                    await vscode.commands.executeCommand('setContext', 'code4arm.noDocs', false);
                    return dataUri.fsPath;
                }
            }
        }
    } catch {
        if (!cont)
            return;

        exists = false;
    }

    await vscode.commands.executeCommand('setContext', 'code4arm.noDocs', true);
    if (await context.globalState.get('noDocsPrompt'))
        return;

    const res = await vscode.window.showInformationMessage(`To use instruction documentation, you must
download the ISA descriptions package protected by copyright held by Arm Limited. By clicking Download,
you agree to proprietary notice of the package. Find more information [here](https://developer.arm.com/downloads/-/exploration-tools).`,
        'Agree and Download', "Don't ask again");

    if (!res)
        return;

    if (res === "Don't ask again") {
        await context.globalState.update('noDocsPrompt', true);
        return;
    }

    if (exists)
        await vscode.workspace.fs.delete(path, { recursive: true, useTrash: false });

    await vscode.workspace.fs.createDirectory(path);

    const url = context.extension.packageJSON.armDocsLink;

    const Downloader = require('nodejs-file-downloader');
    const d = new Downloader({
        url: url,
        maxAttempts: 2,
        cloneFiles: false,
        fileName: 'package.tar.gz',
        directory: path.fsPath,
        timeout: 5000
    });

    try {
        await d.download();
    } catch (e) {
        vscode.window.showErrorMessage('Error when downloading ISA files: ' + (<Error>e).message);
        return;
    }

    const fn = Uri.joinPath(path, 'package.tar.gz');
    const extrakt = require('extrakt');

    try {
        await extrakt(fn.fsPath, path.fsPath);
    } catch (e) {
        vscode.window.showErrorMessage('Error when decompressing ISA files: ' + (<Error>e).message);
        return;
    }

    await vscode.workspace.fs.delete(fn);

    vscode.window.showInformationMessage('Instruction set architecture documentation downloaded.');
    return await ensureDocs(context, false);
}
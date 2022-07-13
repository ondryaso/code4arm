/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

export interface IWindowDisplayWorker {
    showErrorMessage(message: string, callback: (response: string| undefined) => void, ...items: string[]): void;
    showWarningMessage(message: string, callback: (response: string| undefined) => void, ...items: string[]): void;
    showInformationMessage(message: string, callback: (response: string| undefined) => void, ...items: string[]): void;
    copyToUserClipboard(text: string): Promise<void>;
    displayPathConfigPopUp(): Thenable<string | undefined>;
}

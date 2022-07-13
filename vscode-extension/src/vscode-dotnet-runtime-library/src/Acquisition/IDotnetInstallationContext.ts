/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

export interface IDotnetInstallationContext {
    installDir: string;
    version: string;
    dotnetPath: string;
    timeoutValue: number;
    installRuntime: boolean;
}

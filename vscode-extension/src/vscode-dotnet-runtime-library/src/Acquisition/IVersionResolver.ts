/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

export interface IVersionResolver {
    getFullRuntimeVersion(version: string): Promise<string>;
    getFullSDKVersion(version: string): Promise<string>;
}

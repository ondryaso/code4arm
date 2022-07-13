/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import { IInstallationDirectoryProvider } from './IInstallationDirectoryProvider';

export class SdkInstallationDirectoryProvider extends IInstallationDirectoryProvider {
    public getInstallDir(version: string): string {
        return this.getStoragePath();
    }
}

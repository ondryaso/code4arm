/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import * as path from 'path';
import { IInstallationDirectoryProvider } from './IInstallationDirectoryProvider';

export class RuntimeInstallationDirectoryProvider extends IInstallationDirectoryProvider {
    public getInstallDir(version: string): string {
        const dotnetInstallDir = path.join(this.getStoragePath(), version);
        return dotnetInstallDir;
    }
}

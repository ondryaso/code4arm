/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import { UninstallErrorConfiguration } from './Utils/ErrorHandler';

export interface IDotnetUninstallContext {
    errorConfiguration?: UninstallErrorConfiguration;
}

/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import { IDotnetAcquireResult } from '../IDotnetAcquireResult';

export interface IDotnetCoreAcquisitionWorker {
    uninstallAll(): void;

    acquireRuntime(version: string): Promise<IDotnetAcquireResult>;

    acquireSDK(version: string): Promise<IDotnetAcquireResult>;
}

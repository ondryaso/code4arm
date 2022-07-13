/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */
import { IEventStream } from '../EventStream/EventStream';
import { IExtensionState } from '../IExtensionState';
import { IAcquisitionInvoker } from './IAcquisitionInvoker';
import { IInstallationDirectoryProvider } from './IInstallationDirectoryProvider';
import { IInstallationValidator } from './IInstallationValidator';

export interface IAcquisitionWorkerContext {
    storagePath: string;
    extensionState: IExtensionState;
    eventStream: IEventStream;
    acquisitionInvoker: IAcquisitionInvoker;
    installationValidator: IInstallationValidator;
    timeoutValue: number;
    installDirectoryProvider: IInstallationDirectoryProvider;
}

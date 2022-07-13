/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import { IEventStream } from '../EventStream/EventStream';

export abstract class IInstallationValidator {
    constructor(protected readonly eventStream: IEventStream) {}

    public abstract validateDotnetInstall(version: string, dotnetPath: string): void;
}

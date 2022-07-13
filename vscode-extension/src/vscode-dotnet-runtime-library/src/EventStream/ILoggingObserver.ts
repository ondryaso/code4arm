/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */
import { IEvent } from './IEvent';
import { IEventStreamObserver } from './IEventStreamObserver';

export interface ILoggingObserver extends IEventStreamObserver {
    post(event: IEvent): void;
    dispose(): void;
    getFileLocation(): string;
}

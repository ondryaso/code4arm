/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */
import { IWindowDisplayWorker } from './EventStream/IWindowDisplayWorker';

export interface IExtensionContext {
    extensionConfiguration: IExtensionConfiguration;
    displayWorker: IWindowDisplayWorker;
}

export interface IExtensionConfiguration {
    get<T>(name: string): T | undefined;
    update<T>(section: string, value: T, globalSettings: boolean): Thenable<void>;
}

export namespace ExistingPathKeys {
    export const extensionIdKey = 'extensionId';
    export const pathKey = 'path';
}

export interface IExistingPath {
    [ExistingPathKeys.extensionIdKey]: string;
    [ExistingPathKeys.pathKey]: string;
}

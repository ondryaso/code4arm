/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { IEvent } from './IEvent';

export interface IEventStream {
    post(event: IEvent): void;
}

export class EventStream implements IEventStream {
    private readonly subscribeEmitter: vscode.EventEmitter<IEvent>;

    constructor() {
        this.subscribeEmitter = new vscode.EventEmitter<IEvent>();
    }

    public post(event: IEvent) {
        this.subscribeEmitter.fire(event);
    }

    public get subscribe() { return this.subscribeEmitter.event; }
}

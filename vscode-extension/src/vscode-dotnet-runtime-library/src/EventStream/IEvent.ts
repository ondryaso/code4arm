/*---------------------------------------------------------------------------------------------
*  Copyright (c) Microsoft Corporation. All rights reserved.
*  Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
*--------------------------------------------------------------------------------------------*/

import { sanitizeProperties } from '../Utils/ContentSantizer';
import { EventType } from './EventType';

export abstract class IEvent {
    public abstract type: EventType;

    public abstract readonly eventName: string;

    public isError = false;

    public abstract getProperties(telemetry?: boolean): { [key: string]: string } | undefined;

    public getSanitizedProperties(): { [key: string]: string } | undefined {
        return sanitizeProperties(this.getProperties(true));
    }
}

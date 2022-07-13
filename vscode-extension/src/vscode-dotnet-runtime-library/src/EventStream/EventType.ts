/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 *--------------------------------------------------------------------------------------------*/

export enum EventType {
    DotnetAcquisitionStart,
    DotnetSDKAcquisitionStart,
    DotnetRuntimeAcquisitionStart,
    DotnetAcquisitionCompleted,
    DotnetAcquisitionError,
    DotnetAcquisitionSuccessEvent,
    DotnetAcquisitionMessage,
    DotnetAcquisitionTest,
}

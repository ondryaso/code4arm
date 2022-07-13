/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt for license information.
 * ------------------------------------------------------------------------------------------ */

import { IExistingPath } from "../IExtensionContext";

export interface IExtensionConfigurationWorker {
    getPathConfigurationValue(): IExistingPath[] | undefined;
    setPathConfigurationValue(configValue: IExistingPath[]): Promise<void>;
}

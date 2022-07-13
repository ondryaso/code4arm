/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See src/vscode-dotnet-runtime-library/License.txt in the project root for license information.
 * ------------------------------------------------------------------------------------------ */

import * as fs from 'fs';
import { commands, ExtensionContext, OutputChannel, workspace } from "vscode";
import { AcquisitionInvoker } from '../vscode-dotnet-runtime-library/src/Acquisition/AcquisitionInvoker';
import { DotnetCoreAcquisitionWorker } from '../vscode-dotnet-runtime-library/src/Acquisition/DotnetCoreAcquisitionWorker';
import { ExistingPathResolver } from "../vscode-dotnet-runtime-library/src/Acquisition/ExistingPathResolver";
import { InstallationValidator } from '../vscode-dotnet-runtime-library/src/Acquisition/InstallationValidator';
import { RuntimeInstallationDirectoryProvider } from '../vscode-dotnet-runtime-library/src/Acquisition/RuntimeInstallationDirectoryProvider';
import { VersionResolver } from "../vscode-dotnet-runtime-library/src/Acquisition/VersionResolver";
import { EventStream } from "../vscode-dotnet-runtime-library/src/EventStream/EventStream";
import { DotnetRuntimeAcquisitionStarted, DotnetAcquisitionRequested, DotnetExistingPathResolutionCompleted, DotnetAcquisitionStatusRequested } from "../vscode-dotnet-runtime-library/src/EventStream/EventStreamEvents";
import { IEventStreamContext, registerEventStream } from "../vscode-dotnet-runtime-library/src/EventStream/EventStreamRegistration";
import { IEventStreamObserver } from "../vscode-dotnet-runtime-library/src/EventStream/IEventStreamObserver";
import { LoggingObserver } from "../vscode-dotnet-runtime-library/src/EventStream/LoggingObserver";
import { WindowDisplayWorker } from "../vscode-dotnet-runtime-library/src/EventStream/WindowDisplayWorker";
import { IDotnetAcquireContext } from '../vscode-dotnet-runtime-library/src/IDotnetAcquireContext';
import { IDotnetAcquireResult } from "../vscode-dotnet-runtime-library/src/IDotnetAcquireResult";
import { IExtensionConfiguration } from "../vscode-dotnet-runtime-library/src/IExtensionContext";
import { AcquireErrorConfiguration, callWithErrorHandling, ErrorConfiguration } from "../vscode-dotnet-runtime-library/src/Utils/ErrorHandler";
import { ExtensionConfigurationWorker } from "../vscode-dotnet-runtime-library/src/Utils/ExtensionConfigurationWorker";
import { IIssueContext } from "../vscode-dotnet-runtime-library/src/Utils/IIssueContext";

let _context: ExtensionContext;
let _existingPathResolver = new ExistingPathResolver();
const _displayWorker = new WindowDisplayWorker();
let _eventStream: EventStream;
let _outputChannel: OutputChannel;
let _loggingObserver: LoggingObserver;
let _eventStreamObservers: IEventStreamObserver[];
let _versionResolver: VersionResolver;
let _extensionConfigWorker: ExtensionConfigurationWorker;
let _acquisitionWorker: DotnetCoreAcquisitionWorker;

namespace configKeys {
    export const installTimeoutValue = 'installTimeoutValue';
    export const existingPath = 'existingDotnetPath';
}

const _moreInfoUrl = 'https://github.com/dotnet/vscode-dotnet-runtime/blob/main/Documentation/troubleshooting-runtime.md';
const _defaultTimeoutValue = 120;

export async function activateDotnetAcquire(context: ExtensionContext) {
    _context = context;

    const eventStreamContext = {
        displayChannelName: ".NET Runtime",
        logPath: context.logUri.fsPath,
        extensionId: context.extension.id,
        showLogCommand: `code4arm.dotnet.showAcquisitionLog`,
        packageJson: context.extension.packageJSON
    } as IEventStreamContext;

    [_eventStream, _outputChannel, _loggingObserver, _eventStreamObservers] = registerEventStream(eventStreamContext);
    _eventStreamObservers.forEach(o => context.subscriptions.push(o));

    _versionResolver = new VersionResolver(context.globalState, _eventStream);

    const extensionConfiguration: IExtensionConfiguration = workspace.getConfiguration('code4arm.dotnet');
    _extensionConfigWorker = new ExtensionConfigurationWorker(extensionConfiguration, configKeys.existingPath);

    const timeoutValue = extensionConfiguration.get<number>(configKeys.installTimeoutValue);
    if (!fs.existsSync(context.globalStorageUri.fsPath)) {
        fs.mkdirSync(context.globalStorageUri.fsPath);
    }

    _acquisitionWorker = new DotnetCoreAcquisitionWorker({
        storagePath: context.globalStorageUri.fsPath,
        extensionState: context.globalState,
        eventStream: _eventStream,
        acquisitionInvoker: new AcquisitionInvoker(context.globalState, _eventStream),
        installationValidator: new InstallationValidator(_eventStream),
        timeoutValue: timeoutValue === undefined ? _defaultTimeoutValue : timeoutValue,
        installDirectoryProvider: new RuntimeInstallationDirectoryProvider(context.globalStorageUri.fsPath),
    });

    context.subscriptions.push(commands.registerCommand('code4arm.dotnet.showAcquisitionLog', () => _outputChannel.show(false)));
}

export async function getDotnetPath(requestingExtensionId: string): Promise<string | undefined> {
    if (!_context)
        return;

    const commandContext = {
        version: "6.0",
        requestingExtensionId: requestingExtensionId,
        errorConfiguration: 0 // DisplayAllErrorPopups
    };

    const dotnetPath = await callWithErrorHandling<Promise<IDotnetAcquireResult>>(async () => {
        _eventStream.post(new DotnetRuntimeAcquisitionStarted());
        _eventStream.post(new DotnetAcquisitionRequested(commandContext.version, commandContext.requestingExtensionId));

        if (!commandContext.version || commandContext.version === 'latest') {
            throw new Error(`Cannot acquire .NET version "${commandContext.version}". Please provide a valid version.`);
        }

        const existingPath = _existingPathResolver.resolveExistingPath(_extensionConfigWorker.getPathConfigurationValue(),
            commandContext.requestingExtensionId, _displayWorker);

        if (existingPath) {
            _eventStream.post(new DotnetExistingPathResolutionCompleted(existingPath.dotnetPath));
            return new Promise((resolve) => {
                resolve(existingPath);
            });
        }

        const version = await _versionResolver.getFullRuntimeVersion(commandContext.version);
        return _acquisitionWorker.acquireRuntime(version);
    }, {
        logger: _loggingObserver,
        errorConfiguration: commandContext.errorConfiguration || AcquireErrorConfiguration.DisplayAllErrorPopups,
        displayWorker: _displayWorker,
        extensionConfigWorker: _extensionConfigWorker,
        eventStream: _eventStream,
        commandName: 'acquire',
        version: commandContext.version,
        moreInfoUrl: _moreInfoUrl,
        timeoutInfoUrl: `${_moreInfoUrl}#install-script-timeouts`,
    } as IIssueContext, commandContext.requestingExtensionId);


    return dotnetPath?.dotnetPath;
}
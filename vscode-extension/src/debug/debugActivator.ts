import * as vscode from 'vscode';
import { debug, DebugAdapterDescriptor, DebugAdapterDescriptorFactory, DebugSession, ExtensionContext } from 'vscode';
import { Code4ArmDebugSession } from './debugAdapter';
import { Code4ArmDebugAdapterTrackerFactory } from './debugAdapterTracker';
import { Code4ArmDebugConfigurationProvider } from './debugConfigurationProvider';
import { ApsrViewProvider } from './apsrWebview';
import { SessionService } from './sessionService';
import { DebugConfigurationService } from './configuration/debugConfigurationService';
import { MainConfigurationService } from '../configuration/mainConfigurationService';
import { RuntimeService } from '../packageManager/runtimeService';

let subscriptions: { dispose(): any }[] = [];

export async function activateDebugAdapter(context: ExtensionContext, mainConfigurationService: MainConfigurationService,
    runtimeService: RuntimeService) {
    if (subscriptions.length > 0) {
       throw new Error('The debug services are already initialized.'); 
    }

    // Provider for making debug configurations
    const configurationProvider = new Code4ArmDebugConfigurationProvider();
    subscriptions.push(debug.registerDebugConfigurationProvider('code4arm-runtime', configurationProvider));

    // Configuration service
    const configService = new DebugConfigurationService(mainConfigurationService);
    subscriptions.push(configService);

    // Session service
    const sessionService = new SessionService(configService);
    subscriptions.push(sessionService);

    // Debug adapter
    const factory = new InlineDebugAdapterFactory(configService, sessionService, runtimeService);
    subscriptions.push(debug.registerDebugAdapterDescriptorFactory('code4arm-runtime', factory));

    // Tracker factory that creates our tracker that updates sessions and APSR
    const trackerFactory = new Code4ArmDebugAdapterTrackerFactory(sessionService);
    subscriptions.push(debug.registerDebugAdapterTrackerFactory('code4arm-runtime', trackerFactory));

    // Custom 'CPU flags' view
    const apsrView = new ApsrViewProvider(context.extensionUri, trackerFactory.instance.onDidChangeApsr,
        trackerFactory.instance.onDidChangeApsrAvailable);
    subscriptions.push(
        vscode.window.registerWebviewViewProvider(ApsrViewProvider.viewType, apsrView));
}

export function deactivateDebugAdapter() {
    for (const subscription of subscriptions) {
        subscription.dispose();
    }

    subscriptions = [];
}

class InlineDebugAdapterFactory implements DebugAdapterDescriptorFactory {

    constructor(private _configService: DebugConfigurationService, private _sessionService: SessionService,
        private _runtimeService: RuntimeService) {
    }

    async createDebugAdapterDescriptor(_session: DebugSession): Promise<DebugAdapterDescriptor> {
        const serviceUrl = await this._runtimeService.makeDebugger();
        if (serviceUrl == null)
            throw new Error();

        const debuggerUrl = this._configService.getDebuggerAddress(serviceUrl);

        return new vscode.DebugAdapterInlineImplementation(new Code4ArmDebugSession(this._configService, this._sessionService, debuggerUrl));
    }
}
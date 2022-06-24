import * as vscode from 'vscode';
import { debug, DebugAdapterDescriptor, DebugAdapterDescriptorFactory, DebugSession, ExtensionContext, ProviderResult } from 'vscode';
import { Code4ArmDebugSession } from './debugAdapter';
import { Code4ArmDebugAdapterTrackerFactory } from './debugAdapterTracker';
import { Code4ArmDebugConfigurationProvider } from './debugConfigurationProvider';
import { ApsrViewProvider } from './apsrWebview';
import { SessionService } from './sessionService';
import { DebugConfigurationService } from './configuration/debugConfigurationService';

export async function activateDebugAdapter(context: ExtensionContext) {
    // Provider for making debug configurations
    const configurationProvider = new Code4ArmDebugConfigurationProvider();
    context.subscriptions.push(debug.registerDebugConfigurationProvider('code4arm-runtime', configurationProvider));

    // Configuration service
    const configService = new DebugConfigurationService();
    context.subscriptions.push(configService);

    // Session service
    const sessionService = new SessionService(configService);
    context.subscriptions.push(sessionService);

    // Debug adapter
    const factory = new InlineDebugAdapterFactory(configService, sessionService);
    context.subscriptions.push(debug.registerDebugAdapterDescriptorFactory('code4arm-runtime', factory));

    // Tracker factory that creates our tracker that updates sessions and APSR
    const trackerFactory = new Code4ArmDebugAdapterTrackerFactory(sessionService);
    context.subscriptions.push(debug.registerDebugAdapterTrackerFactory('code4arm-runtime', trackerFactory));

    // Custom 'CPU flags' view
    const apsrView = new ApsrViewProvider(context.extensionUri, trackerFactory.instance.onDidChangeApsr, 
        trackerFactory.instance.onDidChangeApsrAvailable);
    context.subscriptions.push(
	    vscode.window.registerWebviewViewProvider(ApsrViewProvider.viewType, apsrView));
}

class InlineDebugAdapterFactory implements DebugAdapterDescriptorFactory {

    constructor(private _configService: DebugConfigurationService, private _sessionService : SessionService) {
    }

    createDebugAdapterDescriptor(_session: DebugSession): ProviderResult<DebugAdapterDescriptor> {
        return new vscode.DebugAdapterInlineImplementation(new Code4ArmDebugSession(this._configService, this._sessionService));
    }
}
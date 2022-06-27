import * as vscode from 'vscode';
import { debug, DebugAdapterDescriptor, DebugAdapterDescriptorFactory, DebugSession, ExtensionContext, ProviderResult } from 'vscode';
import { Code4ArmDebugSession } from './debugAdapter';
import { Code4ArmDebugAdapterTrackerFactory } from './debugAdapterTracker';
import { Code4ArmDebugConfigurationProvider } from './debugConfigurationProvider';
import { ApsrViewProvider } from './apsrWebview';
import { SessionService } from './sessionService';

export async function activateDebugAdapter(context: ExtensionContext) {
    // Provider for making debug configurations
    const configurationProvider = new Code4ArmDebugConfigurationProvider();
    context.subscriptions.push(debug.registerDebugConfigurationProvider('code4arm-runtime', configurationProvider));

    // Session service
    const sessionService = new SessionService();
    context.subscriptions.push(sessionService);

    // Debug adapter
    const factory = new InlineDebugAdapterFactory(sessionService);
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

    constructor(private _sessionService : SessionService) {
    }

    createDebugAdapterDescriptor(_session: DebugSession): ProviderResult<DebugAdapterDescriptor> {
        return new vscode.DebugAdapterInlineImplementation(new Code4ArmDebugSession(this._sessionService));
    }
}
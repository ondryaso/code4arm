import * as vscode from 'vscode';
import { debug, DebugAdapterDescriptor, DebugAdapterDescriptorFactory, DebugSession, ExtensionContext, ProviderResult } from 'vscode';
import { Code4ArmDebugSession } from './debugAdapter';
import { Code4ArmDebugAdapterTrackerFactory } from './debugAdapterTracker';
import { Code4ArmDebugConfigurationProvider } from './debugConfigurationProvider';
import { ApsrViewProvider } from './apsrWebview';

export function activateDebugAdapter(context: ExtensionContext) {
    const configurationProvider = new Code4ArmDebugConfigurationProvider();
    context.subscriptions.push(debug.registerDebugConfigurationProvider('code4arm-runtime', configurationProvider));

    const factory = new InlineDebugAdapterFactory();
    context.subscriptions.push(debug.registerDebugAdapterDescriptorFactory('code4arm-runtime', factory));

    const trackerFactory = new Code4ArmDebugAdapterTrackerFactory();
    context.subscriptions.push(debug.registerDebugAdapterTrackerFactory('code4arm-runtime', trackerFactory));

    const apsrView = new ApsrViewProvider(context.extensionUri, trackerFactory.instance.onDidChangeApsr, 
        trackerFactory.instance.onDidChangeApsrAvailable);
        
    context.subscriptions.push(
	    vscode.window.registerWebviewViewProvider(ApsrViewProvider.viewType, apsrView));
}

class InlineDebugAdapterFactory implements DebugAdapterDescriptorFactory {
    createDebugAdapterDescriptor(_session: DebugSession): ProviderResult<DebugAdapterDescriptor> {
        return new vscode.DebugAdapterInlineImplementation(new Code4ArmDebugSession());
    }
}
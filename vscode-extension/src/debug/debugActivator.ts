import * as vscode from 'vscode';
import { debug, DebugAdapterDescriptor, DebugAdapterDescriptorFactory, DebugSession, ExtensionContext, ProviderResult } from 'vscode';
import { Code4ArmDebugSession } from './debugAdapter';
import { Code4ArmDebugConfigurationProvider } from './debugConfigurationProvider';

export function activateDebugAdapter(context: ExtensionContext) {
    const configurationProvider = new Code4ArmDebugConfigurationProvider();
    context.subscriptions.push(debug.registerDebugConfigurationProvider('code4arm-runtime', configurationProvider));

    const factory = new InlineDebugAdapterFactory();
    context.subscriptions.push(debug.registerDebugAdapterDescriptorFactory('code4arm-runtime', factory));

}

class InlineDebugAdapterFactory implements DebugAdapterDescriptorFactory {
    createDebugAdapterDescriptor(_session: DebugSession): ProviderResult<DebugAdapterDescriptor> {
        return new vscode.DebugAdapterInlineImplementation(new Code4ArmDebugSession());
    }
}
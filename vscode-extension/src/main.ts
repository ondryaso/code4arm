import { window, ExtensionContext } from 'vscode';
import { MainConfigurationService } from './configuration/mainConfigurationService';
import { activateRuntimeOptionPick } from './configuration/runtimeChangeQuickPick';
import { activateInstructionReference } from './instructionReference/activator';
import { RuntimeService } from './packageManager/runtimeService';

export async function activate(context: ExtensionContext) {
	const configService = new MainConfigurationService(context);

	configService.onDidChangeRuntimeMode(m => window.showInformationMessage(m ? 'Using a local Arm simulator instance.'
		: 'Using a remote Arm simulator instance.'));

	await activateRuntimeOptionPick(context, configService);

	const runtimeService = new RuntimeService(configService, context);
	context.subscriptions.push(runtimeService);

	await runtimeService.initRuntime();
	await activateInstructionReference(context);
}

export function deactivate() {
}

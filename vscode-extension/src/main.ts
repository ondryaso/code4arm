import { ExtensionContext } from 'vscode';
import { MainConfigurationService } from './configuration/mainConfigurationService';
import { activateInstructionReference } from './instructionReference/activator';
import { RuntimeService } from './packageManager/runtimeService';

export async function activate(context: ExtensionContext) {
	const configService = new MainConfigurationService();
	const runtimeService = new RuntimeService(configService, context);
	context.subscriptions.push(runtimeService);

	await runtimeService.initRuntime();
	await activateInstructionReference(context);
}

export function deactivate() {
}


import { window, ExtensionContext } from 'vscode';
import { MainConfigurationService } from './configuration/mainConfigurationService';
import { activateRuntimeOptionPick } from './configuration/runtimeChangeQuickPick';
import { activateInstructionReference } from './instructionReference/activator';
import { activateDotnetAcquire } from './packageManager/dotnetAcquire';
import { RuntimeService } from './packageManager/runtimeService';

export async function activate(context: ExtensionContext) {
	await activateDotnetAcquire(context);

	const configService = new MainConfigurationService(context);

	configService.onDidChangeRuntimeMode(m => window.showInformationMessage(m ? 'Using a local Arm simulator instance.'
		: 'Using a remote Arm simulator instance.'));

	configService.onDidUpdateDebuggerServices(m => window.showInformationMessage(m
		? (configService.get().useLocalRuntimeInstallation
			? 'Using a local Arm simulator instance.'
			: 'Using a remote Arm simulator instance.')
		: 'Arm simulator disabled.'))

	await activateRuntimeOptionPick(context, configService);

	const runtimeService = new RuntimeService(configService, context);
	context.subscriptions.push(runtimeService);

	await runtimeService.initRuntime();
	await activateInstructionReference(context);
}

export function deactivate() {
}

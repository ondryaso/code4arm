import { ExtensionContext } from 'vscode';
import { activateDebugAdapter } from './debug/debugActivator';

import { activateLanguageSupport, deactivateLanguageSupport } from './lang/langSupportActivator';


export async function activate(context: ExtensionContext) {
	// await activateLanguageSupport(context);
	activateDebugAdapter(context);
}

export function deactivate() {
	// deactivateLanguageSupport();
}


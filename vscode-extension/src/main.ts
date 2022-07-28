// main.ts
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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

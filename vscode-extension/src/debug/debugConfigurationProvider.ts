// debugConfigurationProvider.ts
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

import path = require('path');
import { workspace, window, WorkspaceFolder, DebugConfiguration, CancellationToken, DebugConfigurationProvider } from 'vscode';

export class Code4ArmDebugConfigurationProvider implements DebugConfigurationProvider {
    /**
     * Provides a launch configuration when no launch.json exists.
     * If it does, it doesn't modify it.
     * If the launch is triggered when an editor with an asm file is active, only that file is used.
     * Otherwise, provideDebugConfigurations is used to create a configuration with all .s files in the workspace.
     */
    public async resolveDebugConfiguration(folder: WorkspaceFolder | undefined, config: DebugConfiguration, token?: CancellationToken):
        Promise<DebugConfiguration | undefined> {
        if (!config.type && !config.request && !config.name) {
            const editor = window.activeTextEditor;
            if (editor && editor.document.languageId === 'arm-ual') {
                config.type = 'code4arm-runtime';
                config.name = 'Code4Arm: Build and Execute current file in simulator';
                config.request = 'launch';
                config.sourceFiles = ['${file}'];

                return config;
            } else {
                const r = await this.provideDebugConfigurations(folder, token);
                if (r)
                    return r[0];
            }
        }

        return config;
    }

    /**
     * Provides a launch configuration with all .s/.S files in the workspace.
     */
    public async provideDebugConfigurations(folder: WorkspaceFolder | undefined, token?: CancellationToken):
        Promise<DebugConfiguration[] | undefined> {
        const files = await workspace.findFiles('**/*.{s,S}', undefined, undefined, token);
        if (files.length === 0)
            return;

        let c: DebugConfiguration = {
            name: "Code4Arm: Build and Debug in simulator",
            request: "launch",
            type: "code4arm-runtime",
            sourceFiles: files.map((v, _0, _1) => '${workspaceFolder}' + path.sep +
                workspace.asRelativePath(v, false))
        };

        return [c];
    }
}

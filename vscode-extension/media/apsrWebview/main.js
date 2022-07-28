// main.js
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

(function () {
    const vscode = acquireVsCodeApi();
    const oldState = vscode.getState() || { enabled: false, data: { n: false, v: false, c: false, z: false } };

    if (updateVisibility(oldState)) {
        update(oldState);
    }

    window.addEventListener('message', event => {
        const message = event.data;
        let state = vscode.getState() || oldState;

        if (typeof message.enabled !== 'undefined') {
            state.enabled = message.enabled;
            updateVisibility(state);
        } else {
            state.data = message;
            update(state);
        }

        vscode.setState(state);
    });

    function updateVisibility(state) {
        if (!state.enabled) {
            document.getElementById('not-available').classList.remove('hidden');
            document.getElementById('main-grid').classList.add('hidden');
        } else {
            document.getElementById('not-available').classList.add('hidden');
            document.getElementById('main-grid').classList.remove('hidden');
        }

        return state.enabled;
    }

    function update(state) {
        for (const prop in state.data) {
            const value = state.data[prop];
            const el = document.getElementById(prop);

            if (el) {
                el.className = value ? 'on' : 'off';
            }
        }
    }
}());
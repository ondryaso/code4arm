// dev_consts.ts
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

/** In development mode, the extension can:
 *  - Connect to a remote language server using sockets (without launching it).
 *  - Connect to a remote execution service in local mode (without launching it).
 * 
 * This also enables the code4arm.refreshConnection command that reconnects
 * to the language server.
 */
const DevMode: boolean = false;

/** The remote language server hostname. If null, the extension will behave
 * as if it wasn't in dev mode so it will launch its own server instance (from
 * `servers/language/`) connected using stdio.
 */
const LanguageServerHost: string | null = '127.0.0.1';
/** The remote language server port. */
const LanguageServerPort: number = 5057;

/** The remote execution service URL. If provided, it will be used when the extension
 * is configured to used the *local* mode. If null, the extension will behave
 * as if it wasn't in dev mode so it will launch its own local service instance (from
 * `servers/debug/`) on a discovered free port.
 */
const ExecutionServiceAddress: string | null = /*null; // */'http://127.0.0.1:5058';
/** If true, DAP requests and responses will be logged in console. */
const DebugRequestLogging: boolean = DevMode;

export {
    DevMode, LanguageServerHost, LanguageServerPort, ExecutionServiceAddress,
    DebugRequestLogging
};

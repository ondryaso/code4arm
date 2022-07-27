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

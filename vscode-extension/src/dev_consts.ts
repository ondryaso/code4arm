const DevMode: boolean = false;
const LanguageServerHost: string = '127.0.0.1';
const LanguageServerPort: number = 5057;
const ExecutionServiceAddress: string | null = null; // 'http://127.0.0.1:5058';
const DebugAdapterTracking: boolean = DevMode;

export {
    DevMode, LanguageServerHost, LanguageServerPort, ExecutionServiceAddress,
    DebugAdapterTracking
};

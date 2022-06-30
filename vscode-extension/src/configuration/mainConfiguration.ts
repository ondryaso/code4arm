export interface IMainConfiguration {
    readonly enableLanguageServices: boolean;
    readonly enableDebuggerServices: boolean;
    readonly useLocalRuntimeInstallation: boolean;

    readonly remoteRuntimeAddress?: string;
}
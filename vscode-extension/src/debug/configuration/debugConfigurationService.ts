import { EventEmitter, Event, Disposable, workspace, ConfigurationChangeEvent } from "vscode";
import { IClientConfiguration, ExecutionOptionsOverlay, DebuggerOptionsOverlay } from "./serverModels";

export class DebugConfigurationService implements Disposable {
    private _onDidChangeClientConfigurationEmitter: EventEmitter<IClientConfiguration> = new EventEmitter<IClientConfiguration>();
    public readonly onDidChangeClientConfiguration: Event<IClientConfiguration> = this._onDidChangeClientConfigurationEmitter.event;

    private _currentConfig: IClientConfiguration;

    constructor() {
        this._currentConfig = {};
        this.handleConfigurationChange();
        workspace.onDidChangeConfiguration(this.handleConfigurationChange, this);
    }

    public getConfigurationForService(): IClientConfiguration {
        return this._currentConfig;
    }

    public isRemote(): boolean {
        return false;
    }

    private handleConfigurationChange(event?: ConfigurationChangeEvent) {
        if (!event || event.affectsConfiguration('code4arm.runtime')
            || event.affectsConfiguration('code4arm.debugger') || event.affectsConfiguration('code4arm.build')) {

            this._currentConfig = this.loadConfig();
            this._onDidChangeClientConfigurationEmitter.fire(this._currentConfig);
        }
    }

    private loadConfig(): IClientConfiguration {
        const config = workspace.getConfiguration('code4arm');

        let debuggerConfig = config.get<DebuggerOptionsOverlay>('debugger');
        let executionConfig = config.get<ExecutionOptionsOverlay>('runtime');
        let clientConfig = config.get<IClientConfiguration>('build') ?? {};

        if (debuggerConfig) {
            let dbgAny = <any>(debuggerConfig);
            debuggerConfig.showFloatIeeeSubvariables = dbgAny.showFloatDecomposition;

            if (debuggerConfig.simdRegistersOptions) {
                let simdAny = <any>(debuggerConfig.simdRegistersOptions);
                debuggerConfig.simdRegistersOptions.dIeeeSubvariables = simdAny.dFloatDecompositionSubvariables;
                debuggerConfig.simdRegistersOptions.sIeeeSubvariables = simdAny.sFloatDecompositionSubvariables;
            }
        }

        clientConfig.executionOptions = executionConfig;
        clientConfig.debuggerOptions = debuggerConfig;

        return clientConfig;
    }

    dispose(): void {
        this._onDidChangeClientConfigurationEmitter.dispose();
    }
}
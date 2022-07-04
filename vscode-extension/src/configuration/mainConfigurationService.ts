import { EventEmitter, Event } from "vscode";
import { HasLocalExecutionService } from "../has_local_es";
import { IMainConfiguration } from "./mainConfiguration";

class Configuration implements IMainConfiguration {
    enableLanguageServices: boolean = false;
    enableDebuggerServices: boolean = true;
    useLocalRuntimeInstallation: boolean = HasLocalExecutionService;
    remoteRuntimeAddress?: string;
    localRuntimeAllowed: boolean = HasLocalExecutionService;
}

/**
 * Provides top-level configuration, that is, settings that enable/disable language services
 * and execution service and control the execution mode (local/remote).
 */
export class MainConfigurationService {
    private _instance: Configuration = new Configuration();

    private _onDidUpdateLanguageServicesEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidUpdateLanguageServices: Event<boolean> = this._onDidUpdateLanguageServicesEmitter.event;

    private _onDidUpdateDebuggerServicesEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidUpdateDebuggerServices: Event<boolean> = this._onDidUpdateDebuggerServicesEmitter.event;

    private _onDidChangeRuntimeModeEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidChangeRuntimeMode: Event<boolean> = this._onDidChangeRuntimeModeEmitter.event;

    private _onDidChangeRemoteAddressEmitter: EventEmitter<string> = new EventEmitter<string>();
    public readonly onDidChangeRemoteAddress: Event<string> = this._onDidChangeRemoteAddressEmitter.event;


    public get(): IMainConfiguration {
        return this._instance;
    }

    public useLocalRuntime() {
        if (!HasLocalExecutionService) {
            throw Error('Local runtime is not available on this platform.');
        }

        if (this._instance.useLocalRuntimeInstallation)
            return;

        this._instance.remoteRuntimeAddress = undefined;
        this._instance.useLocalRuntimeInstallation = true;
        this._onDidChangeRuntimeModeEmitter.fire(true);
    }

    public useRemoteRuntime(address: string) {
        const changedMode = this._instance.useLocalRuntimeInstallation;
        const changedAddress = !changedMode && address != this._instance.remoteRuntimeAddress;

        this._instance.remoteRuntimeAddress = address;
        this._instance.useLocalRuntimeInstallation = false;

        if (changedMode)
            this._onDidChangeRuntimeModeEmitter.fire(false);
        if (changedAddress)
            this._onDidChangeRemoteAddressEmitter.fire(address);
    }
}
import { EventEmitter, Event, ExtensionContext, workspace } from "vscode";
import { HasLocalExecutionService } from "../has_local_es";
import { IMainConfiguration } from "./mainConfiguration";

class Configuration implements IMainConfiguration {
    enableLanguageServices: boolean = true;
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
    private _instance: Configuration;
    private _onDidUpdateLanguageServicesEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidUpdateLanguageServices: Event<boolean> = this._onDidUpdateLanguageServicesEmitter.event;

    private _onDidUpdateDebuggerServicesEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidUpdateDebuggerServices: Event<boolean> = this._onDidUpdateDebuggerServicesEmitter.event;

    private _onDidChangeRuntimeModeEmitter: EventEmitter<boolean> = new EventEmitter<boolean>();
    public readonly onDidChangeRuntimeMode: Event<boolean> = this._onDidChangeRuntimeModeEmitter.event;

    private _onDidChangeRemoteAddressEmitter: EventEmitter<string> = new EventEmitter<string>();
    public readonly onDidChangeRemoteAddress: Event<string> = this._onDidChangeRemoteAddressEmitter.event;

    constructor(private _context: ExtensionContext) {

        let enableLanguageServer = workspace.getConfiguration("code4arm.editor").get<boolean>("enableLanguageServer") ?? true;
        this._instance = _context.globalState.get<Configuration>("code4arm.main", {
            enableLanguageServices: enableLanguageServer,
            enableDebuggerServices: HasLocalExecutionService,
            useLocalRuntimeInstallation: HasLocalExecutionService,
            localRuntimeAllowed: HasLocalExecutionService
        });

        workspace.onDidChangeConfiguration(e => {
            if (!e.affectsConfiguration("code4arm.editor.enableLanguageServer"))
                return;

            const current = this._instance.enableLanguageServices;
            this._instance.enableLanguageServices = workspace.getConfiguration("code4arm.editor").get<boolean>("enableLanguageServer") ?? true;
            if (current != this._instance.enableLanguageServices)
                this, this._onDidUpdateLanguageServicesEmitter.fire(this._instance.enableLanguageServices);
        });
    }

    public get(): IMainConfiguration {
        return this._instance;
    }

    public useLocalRuntime() {
        if (!HasLocalExecutionService) {
            throw Error('Local runtime is not available on this platform.');
        }

        if (this._instance.useLocalRuntimeInstallation) {
            if(!this._instance.enableDebuggerServices) {
                this._instance.enableDebuggerServices = true;
                this.save();
                this._onDidUpdateDebuggerServicesEmitter.fire(true);
            }

            return;
        }

        this._instance.remoteRuntimeAddress = undefined;
        this._instance.useLocalRuntimeInstallation = true;
        this._instance.enableDebuggerServices = true;

        this.save();

        this._onDidChangeRuntimeModeEmitter.fire(true);
    }

    public useRemoteRuntime(address: string) {
        const changedMode = this._instance.useLocalRuntimeInstallation;
        const changedAddress = !changedMode && address != this._instance.remoteRuntimeAddress;

        this._instance.remoteRuntimeAddress = address;
        this._instance.useLocalRuntimeInstallation = false;
        this._instance.enableDebuggerServices = true;

        this.save();

        if (changedMode)
            this._onDidChangeRuntimeModeEmitter.fire(false);
        if (changedAddress)
            this._onDidChangeRemoteAddressEmitter.fire(address);
    }

    public disableRuntime() {
        if (!this._instance.enableDebuggerServices)
            return;

        this._instance.enableDebuggerServices = false;
        this.save();
        this._onDidUpdateDebuggerServicesEmitter.fire(false);
    }

    private save() {
        this._context.globalState.update("code4arm.main", this._instance);
    }
}

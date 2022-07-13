import { commands, ExtensionContext, Uri, window } from 'vscode';
import { HasLocalExecutionService } from '../has_local_es';
import { MainConfigurationService } from './mainConfigurationService';

async function showRuntimeOptionPick(configService: MainConfigurationService): Promise<boolean> {
    let items: { [key: string]: number | undefined } =
        { 'Use local simulation service': 1, 'Use remote simulation service': 2, 'Disable Arm simulation': 3 };

    const currentCfg = configService.get();
    let currentState = currentCfg.enableDebuggerServices
        ? (currentCfg.useLocalRuntimeInstallation ? "using local" : "using remote")
        : "disabled";

    if (!HasLocalExecutionService) {
        delete items['Use local simulation service'];
        currentState += ', local instance not available';
    }

    const result = await window.showQuickPick(Object.keys(items), {
        canPickMany: false,
        title: 'Choose how you want to use the Code4Leg simulator (currently ' + currentState + ')'
    });

    if (!result)
        return false;

    const idx = items[result];
    if (!idx || idx > 3) {
        window.showErrorMessage('Invalid option selected.');
        return false;
    } else if (idx == 3) {
        configService.disableRuntime();
    } else if (idx == 1) {
        configService.useLocalRuntime();
    } else if (idx == 2) {
        const addr = await window.showInputBox({
            title: 'Enter the remote service URL',
            validateInput: validateUrl
        });

        if (!addr || validateUrl(addr) != null)
            return false;

        configService.useRemoteRuntime(addr);
    }

    return true;
}

function validateUrl(text: string) {
    try {
        const uri = Uri.parse(text, true);
        if (uri.scheme != 'http' && uri.scheme != 'https')
            return 'Invalid URL (http or https must be used).';
        if (uri.authority?.trim()?.length == 0)
            return 'Invalid URL.';

        return null;
    }
    catch { return 'Invalid URL.'; }
}

export async function activateRuntimeOptionPick(context: ExtensionContext, configService: MainConfigurationService) {
    context.subscriptions.push(commands.registerCommand('code4arm.configureRuntime', async () => await showRuntimeOptionPick(configService)));

    if (!context.globalState.get('code4arm.runtimeOptionShown')) {
        const res = await showRuntimeOptionPick(configService);
        context.globalState.update('code4arm.runtimeOptionShown', res);
    }
}

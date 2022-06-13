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
(function () {
    const vscode = acquireVsCodeApi();

    const links = document.getElementsByTagName('a');
    for (let a of links) {
        const href = a.getAttribute('href');

        if (!href)
            continue;
        if (href.startsWith('#'))
            continue;

        a.onclick = () => { vscode.postMessage(href); return false; }
    }

    window.addEventListener('message', event => {
        const message = event.data;
        document.getElementById(message).scrollIntoView();
    });

    vscode.postMessage('__loaded');
}());
CURRENT_PLATFORM="$(uname -s | awk '{print tolower($0)}')-$(uname -m)"

SCRIPT_DIR="$( dirname -- "$( readlink -f -- "$0"; )"; )"
TOOLCHAINS_DIR="$SCRIPT_DIR/build-cmake-defs/$CURRENT_PLATFORM"

PUB_DIR="$SCRIPT_DIR/publish"
LS_DIR="$PUB_DIR/language-server"
ES_DIR="$PUB_DIR/execution-service-local"
VSIX_DIR="$PUB_DIR/extension"

EXTENSION_SRC_DIR="$SCRIPT_DIR/../vscode-extension"
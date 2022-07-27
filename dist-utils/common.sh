CURRENT_PLATFORM="$(uname -s | awk '{print tolower($0)}')-$(uname -m)"

SCRIPT_DIR="$( dirname -- "$( readlink -f -- "$0"; )"; )"
TOOLCHAINS_DIR="$SCRIPT_DIR/build-cmake-defs/$CURRENT_PLATFORM"

PUB_DIR="$SCRIPT_DIR/publish"
LS_DIR="$PUB_DIR/language-server"
ES_DIR="$PUB_DIR/execution-service-local"
VSIX_DIR="$PUB_DIR/extension"

EXTENSION_SRC_DIR="$SCRIPT_DIR/../vscode-extension"

TOOLCHAIN_ARM="/home/ondryaso/bp/toolchains/gcc-arm-11.2-2022.02-x86_64-arm-none-linux-gnueabihf"
TOOLCHAIN_AARCH64="/home/ondryaso/bp/toolchains/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu"

export BINUTILS_ARM="$TOOLCHAIN_ARM/bin"
export BINUTILS_AARCH64="$TOOLCHAIN_AARCH64/bin"

export ROOT_ARM="$TOOLCHAIN_ARM/arm-none-linux-gnueabihf/"
export ROOT_AARCH64="$TOOLCHAIN_AARCH64/aarch64-none-linux-gnu/"
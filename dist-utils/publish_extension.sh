#!/bin/bash

. common.sh

if [ ! -d "$LS_DIR" ];
then
    echo "Language Server not found."
    exit 1
fi

if [ ! -d "$ES_DIR" ];
then
    echo "Execution Service not found."
    exit 1
fi

if [[ "$1" == "--publish" ]];
then
    PUBLISH=0
    shift
else
    PUBLISH=1
fi

cd "$EXTENSION_SRC_DIR"
npm install
mkdir -p ./servers/language ./servers/debug
cp -r $LS_DIR/* ./servers/language/

prepare_execution_service() {
    uni_platform="$1"
    vsc_platform="$2"

    cd "$EXTENSION_SRC_DIR"

    if [[ "$uni_platform" == *"windows"* ]];
    then
        uni="$PUB_DIR/unicorn/build-$uni_platform/unicorn.dll"
        uni_target="./servers/debug/unicorn.dll"
    else
        uni="$PUB_DIR/unicorn/build-$uni_platform/libunicorn.so.2"
        uni_target="./servers/debug/unicorn.so"
    fi

    tc="$SCRIPT_DIR/toolchains/$uni_platform"
    if [ ! -d "$tc" ];
    then
        echo "Toolchain (as+ld) not available for $uni_platform; publishing $vsc_platform without local runtime support."
        rm -rf "./servers/debug/"
        return 1
    fi

    if [ ! -f "$uni" ];
    then
        echo "Unicorn build $uni_platform not found; publishing $vsc_platform without local runtime support."
        rm -rf "./servers/debug/"
        return 1
    fi

    if [ ! -f "./servers/debug/Code4Arm.LanguageServer.dll" ];
    then
        mkdir -p ./servers/debug
        cp -r $ES_DIR/* ./servers/debug/
    fi

    cp -f $ES_DIR/appsettings.json ./servers/debug/appsettings.json

    if [[ "$uni_platform" == *"windows"* ]];
    then
        patch "./servers/debug/appsettings.json" "$SCRIPT_DIR/res/appsettings.windows.json.patch"
    else
        patch "./servers/debug/appsettings.json" "$SCRIPT_DIR/res/appsettings.unix.json.patch"
    fi

    tc_target="./servers/debug/toolchain"
    rm -rf "$tc_target"
    rm -f "./servers/debug/unicorn.so" "./servers/debug/unicorn.dll"

    cp "$uni" "$uni_target"
    cp -r "$tc" "$tc_target"
}

publish_platform() {
    uni_platform="$1"
    vsc_platform="$2"
    shift 2

    prepare_execution_service "$uni_platform" "$vsc_platform"
    if [ "$?" -eq 0 ];
    then
        cp -f "$SCRIPT_DIR/res/allow_es.ts" "$EXTENSION_SRC_DIR/src/has_local_es.ts"
    else
        cp -f "$SCRIPT_DIR/res/disallow_es.ts" "$EXTENSION_SRC_DIR/src/has_local_es.ts"
    fi

    mkdir -p "$VSIX_DIR"
    target="$VSIX_DIR/ondryaso.code4arm.$vsc_platform.vsix"

    cd "$EXTENSION_SRC_DIR"
    vsce package --target "$vsc_platform" --out "$target" "$@"

    if [ "$PUBLISH" -eq 0 ];
    then
        vsce publish --packagePath "$target"
    fi
}

# The currently available platforms are:
# win32-x64, win32-ia32, win32-arm64,
# linux-x64, linux-arm64, linux-armhf,
# alpine-x64, alpine-arm64,
# darwin-x64 and darwin-arm64.

publish_platform "linux-x86_64" "linux-x64" "$@"
publish_platform "linux-arm64" "linux-arm64" "$@"
#publish_platform "linux-arm" "linux-armhf" "$@"

publish_platform "windows-x86_64" "win32-x64" "$@"
publish_platform "windows-i386" "win32-ia32" "$@"
#publish_platform "windows-arm64" "win32-arm64" "$@"

#publish_platform "darwin-x86_64" "darwin-x64" "$@"
#publish_platform "darwin-arm64" "darwin-arm64" "$@"

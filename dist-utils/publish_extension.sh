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

if [ ! -d "$PUB_DIR/unicorn" ];
then
    echo "Unicorn not found."
    exit 1
fi

if [[ "$1" == "--publish" ]];
then
    PUBLISH=0
    shift
fi

cd "$EXTENSION_SRC_DIR"
mkdir -p ./servers/language ./servers/debug
cp -r $LS_DIR/* ./servers/language/
cp -r $ES_DIR/* ./servers/debug/

publish_platform() {
    uni_platform="$1"
    vsc_platform="$2"
    shift 2

    uni="$PUB_DIR/unicorn/build-$uni_platform/libunicorn.so.2"
    if [ ! -f "$uni" ];
    then
        echo "Unicorn build $uni_platform not found, skipping $vsc_platform"
        return 1
    fi

    cp "$uni" "./servers/debug/unicorn.so"
    cd "$EXTENSION_SRC_DIR"

    mkdir -p "$VSIX_DIR"
    target="$VSIX_DIR/ondryaso.code4arm.$vsc_platform.vsix"

    vsce package --target "$vsc_platform" --out "$target" "$@"

    if [ $PUBLISH ];
    then
        vsce publish --packagePath "$target"
    fi
}

publish_platform "linux-x86_64" "linux-x64" "$@"
publish_platform "linux-arm64" "linux-arm64" "$@"
publish_platform "linux-arm" "linux-armhf" "$@"

publish_platform "windows-amd64" "win32-x64" "$@"
publish_platform "windows-x86" "win32-ia32" "$@"
publish_platform "windows-arm64" "win32-arm64" "$@"

publish_platform "darwin-x86_64" "darwin-x64" "$@"
publish_platform "darwin-arm64" "darwin-arm64" "$@"
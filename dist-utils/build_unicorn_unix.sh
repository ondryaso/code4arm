#!/bin/bash

export PATH="$PATH:/home/ondryaso/Projects/bp/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu/bin/:/home/ondryaso/Projects/bp/gcc-arm-11.2-2022.02-x86_64-arm-none-linux-gnueabihf/bin/"

. common.sh

if [ ! -d "$PUB_DIR" ];
then
    mkdir "$PUB_DIR"
fi

cd "$PUB_DIR"

# Pull Unicorn
if [ -d "unicorn" ];
then
    echo "Pulling latest Unicorn files"
    cd unicorn
    git pull
else
    echo "Cloning Unicorn"
    git clone --branch dev --depth 1 git@github.com:unicorn-engine/unicorn.git unicorn
    cd unicorn
fi

build_unicorn() {
    target=${1:-"$CURRENT_PLATFORM"}
    echo "Building for $target"

    mkdir -p "build-$target"
    cd "build-$target"

    if [ -z "$1" ];
    then
        cmake .. -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm > build.log
    else
        file="$TOOLCHAINS_DIR/$1.cmake"
        if [ ! -f "$file" ]; then
            echo "Toolchain file $1 does not exist."
            exit 1
        fi

        if [[ "$1" == "linux-i386" ]]; then
            echo "Patching CMakeLists"
            # Patch the CMakeLists to pass the i386 configuration to QEMU build script
            mv ../CMakeLists.txt ../_tmp_cmakelists
            awk '{gsub("execute_process\\(COMMAND \\${CMAKE_C_COMPILER}", "execute_process(COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS}");sub("--cc=\\${CMAKE_C_COMPILER}", "--cc=${CMAKE_C_COMPILER} --cpu=i386");print}' ../_tmp_cmakelists > ../CMakeLists.txt
        fi

        cmake .. -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAINS_DIR/$1.cmake" -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm > "build-$1.log"

        if [[ "$1" == "linux-i386" ]]; then
            echo "Unpatching CMakeLists"
            rm ../CMakeLists.txt
            mv ../_tmp_cmakelists ../CMakeLists.txt
        fi
    fi

    make
    cd ..
}

if [ -z "$1" ];
then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        build_unicorn
        build_unicorn "darwin-arm64"
    else
        build_unicorn
        build_unicorn "linux-arm64"
        build_unicorn "linux-arm"
        # build_unicorn "linux-i386"
    fi
else
    build_unicorn "$1"
fi


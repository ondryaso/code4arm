#!/bin/bash

. common.sh

if [ ! -z "$BINUTILS_ARM" ];
then
    export PATH="$PATH:$BINUTILS_ARM/bin"
fi

if [ ! -z "$BINUTILS_AARCH64" ];
then
    export PATH="$PATH:$BINUTILS_AARCH64/bin"
fi

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
    git clone --branch dev --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn
    cd unicorn
fi

build_unicorn() {
    target=${1:-"$CURRENT_PLATFORM"}
    echo "Building for $target"

    cd "$PUB_DIR/unicorn" || { echo "Unicorn not found"; return 1; }

    mkdir -p "build-$target"
    cd "build-$target"

    if [ -z "$1" ];
    then
        # Building FOR the SAME platform we're running on
        cmake .. -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm > build.log
    elif [[ "$target" == "windows"* ]];
    then
        # Building for Windows in WSL
        kr="$(uname -r)"

        if [[ "$kr" != *"WSL"* ]]; then
            echo "windows builds may only be started from a WSL instance"
            return 1
        fi

        # Test if the script is saved in the WSL filesystem or in the Windows filesystem
        [[ "$(wslpath -w .)" == "\\\\wsl"* ]]
        is_wsl_path=$?

        if [ "$is_wsl_path" -eq 0 ];
        then
            # If it's saved in WSL, we must copy the build tools to the Windows filesystem
            tmp_dir="/mnt/c/Windows/Temp/_c4a_build"
            rm -rf "$tmp_dir"
            cp -rf "$SCRIPT_DIR" "$tmp_dir"

            # Save variables
            prev_sd=$SCRIPT_DIR
            prev_pb=$PUB_DIR

            SCRIPT_DIR=$tmp_dir
            PUB_DIR="$SCRIPT_DIR/publish"
            cd "$PUB_DIR/unicorn/build-$target"
        fi

        if [[ "$target" == "windows-x86_64" ]];
        then
            # 64bit Windows needs a modified CMakeLists to force a specific 
            # MSVC runtime library linking mode
            echo "Patching CMakeLists"
            mv ../CMakeLists.txt ../_tmp_cmakelists
            cp "$SCRIPT_DIR/build-cmake-defs/windows-x86_64/CMakeLists.txt" ../CMakeLists.txt

            echo "Running cmd.exe script"
            cd "$SCRIPT_DIR"
            cmd.exe /K "build_windows_x64.bat"

            echo "Restoring CMakeLists"
            rm "$PUB_DIR/unicorn/CMakeLists.txt"
            mv "$PUB_DIR/unicorn/_tmp_cmakelists" "$PUB_DIR/unicorn/CMakeLists.txt"
        elif [[ "$target" == "windows-i386" ]];
        then
            echo "Running cmd.exe script"
            cd "$SCRIPT_DIR"
            cmd.exe /K "build_windows_x86.bat"
        else
            echo "Windows taget $target is not supported yet"
            return 1
        fi

        if [ "$is_wsl_path" -eq 0 ];
        then
            # Copy the built dll, delete the temporary directory and restore variables
            cp -rf "$PUB_DIR/unicorn/build-$target" "$prev_pb/unicorn/"
            SCRIPT_DIR=$prev_sd
            PUB_DIR=$prev_pb
            cd "$PUB_DIR/unicorn/build-$target" 
            rm -rf "$tmp_dir"
        fi

        return 0
    else
        # Cross-compiling
        file="$TOOLCHAINS_DIR/$1.cmake"
        if [ ! -f "$file" ]; then
            echo "Toolchain file $1 does not exist."
            return 1
        fi

        if [[ "$1" == "linux-i386" ]]; then
            echo "Patching CMakeLists"
            # Patch the CMakeLists to pass the i386 configuration to QEMU build script
            mv ../CMakeLists.txt ../_tmp_cmakelists
            awk '{gsub("execute_process\\(COMMAND \\${CMAKE_C_COMPILER}", "execute_process(COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS}");sub("--cc=\\${CMAKE_C_COMPILER}", "--cc=${CMAKE_C_COMPILER} --cpu=i386");print}' ../_tmp_cmakelists > ../CMakeLists.txt
        fi

        cmake .. -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAINS_DIR/$1.cmake" -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm > "build-$1.log"

        if [[ "$1" == "linux-i386" ]]; then
            echo "Restoring CMakeLists"
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
        build_unicorn "windows-x86_64"
        build_unicorn "windows-i386"
        # build_unicorn "windows-arm64" # TODO
    fi
else
    build_unicorn "$1"
fi


#!/bin/bash

. common.sh

if [ -d "$PUB_DIR" ];
then
    rm -rf "$LS_DIR"
    rm -rf "$ES_DIR"
else
    mkdir "$PUB_DIR"
fi

dotnet publish "$SCRIPT_DIR/../src/Code4Arm.LanguageServer" -c Release -p:Platform=AnyCPU -o "$LS_DIR" --no-self-contained -v m
dotnet publish "$SCRIPT_DIR/../src/Code4Arm.ExecutionService" -c Release -p:Platform=AnyCPU -o "$ES_DIR" --no-self-contained -v m

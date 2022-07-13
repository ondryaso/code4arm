#!/bin/bash

. common.sh

for fn in "$VSCX_DIR/*.vscx"; do
    vsce publish --packagePath "$fn"
done

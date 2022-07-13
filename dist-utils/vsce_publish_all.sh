#!/bin/bash

. common.sh

for fn in "$VSIX_DIR"/*.vsix; do
    echo "Publishing: $fn"
    vsce publish --packagePath "$fn"
    echo ""
done

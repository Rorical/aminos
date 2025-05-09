#!/usr/bin/env bash

set -euo pipefail

# Make sure we're in the rust-miner directory
cd "$(dirname "$0")"

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack is not installed. Installing now..."
    cargo install wasm-pack
fi

# Create js directory if it doesn't exist
mkdir -p js

# Build the WASM module
echo "Building WASM module..."
wasm-pack build --target web --out-dir pkg

# Create output directory
mkdir -p ../static/js/wasm

# Copy WASM files to static directory
echo "Copying WASM files to static directory..."
cp -f pkg/*.wasm ../static/js/wasm/
cp -f pkg/*.js ../static/js/wasm/

# Print file list in the target directory
echo "Files in static/js/wasm directory:"
ls -la ../static/js/wasm/

echo "Build complete!" 
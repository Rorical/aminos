#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

LICENSE='/*
@licstart  The following is the entire license notice for the
JavaScript code in this page.

Copyright (c) 2025 Xe Iaso <me@xeiaso.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

@licend  The above is the entire license notice
for the JavaScript code in this page.
*/'

# Build WASM miner if possible
if command -v wasm-pack &> /dev/null; then
  echo "Building WASM miner..."
  (cd rust-miner && ./build.sh)
  mkdir -p static/js/wasm
  
  # Copy WASM files if they exist
  if [ -d "rust-miner/pkg" ]; then
    echo "Copying WASM files..."
    cp -f rust-miner/pkg/*.wasm static/js/wasm/ || true
    cp -f rust-miner/pkg/*.js static/js/wasm/ || true
  else
    echo "WASM build failed or not found. Will use JavaScript fallback."
  fi
else
  echo "wasm-pack not found. Skipping WASM miner build."
  echo "To enable WASM mining for better performance, install wasm-pack:"
  echo "cargo install wasm-pack"
fi

# Main script
esbuild js/main.mjs --sourcemap --bundle --minify --outfile=static/js/main.mjs "--banner:js=${LICENSE}"
gzip -f -k -n static/js/main.mjs
zstd -f -k --ultra -22 static/js/main.mjs
brotli -fZk static/js/main.mjs

# Bench script
esbuild js/bench.mjs --sourcemap --bundle --minify --outfile=static/js/bench.mjs
gzip -f -k -n static/js/bench.mjs
zstd -f -k --ultra -22 static/js/bench.mjs
brotli -fZk static/js/bench.mjs

# Bitcoin mining script
esbuild js/bitcoin-mining.mjs --sourcemap --bundle --minify --format=esm --outfile=static/js/bitcoin-mining.mjs "--banner:js=${LICENSE}"
gzip -f -k -n static/js/bitcoin-mining.mjs
zstd -f -k --ultra -22 static/js/bitcoin-mining.mjs
brotli -fZk static/js/bitcoin-mining.mjs
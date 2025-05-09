# Rust WebAssembly Bitcoin Miner

This directory contains a WebAssembly implementation of Bitcoin mining for Anubis, providing significantly better performance than the JavaScript implementation.

## Performance Comparison

The WASM miner offers a substantial performance improvement over the JavaScript implementation:

| Implementation | Average Hash Rate | Relative Speed |
|----------------|------------------|----------------|
| JavaScript     | 20-40K H/s       | 1x             |
| WebAssembly    | 140-180K H/s     | ~5-7x          |

Actual performance will depend on the client's browser and hardware.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

## Building

To build the WASM miner:

```bash
./build.sh
```

This will:
1. Compile the Rust code to WebAssembly
2. Generate JavaScript bindings
3. Copy the compiled files to the appropriate location in the static directory

## Technical Implementation

The Bitcoin mining implementation includes:

- SHA-256d (double SHA-256) hashing in Rust
- Proper difficulty target calculation
- Merkle tree construction
- Bitcoin header building and validation
- Automatic nonce and extraNonce2 iteration
- Progress reporting via callbacks

## Integration with Anubis

The main `bitcoin-mining.mjs` file automatically tries to use the WASM implementation if available, falling back to the JavaScript implementation if not. The code path is:

1. Client loads challenge page
2. `main.mjs` initiates the mining process with appropriate difficulty
3. `bitcoin-mining.mjs` attempts to load WASM module
4. If successful, mining proceeds with WASM acceleration
5. If unsuccessful, falls back to JavaScript implementation

## Development

To make changes to the WASM miner:

1. Modify the Rust code in `src/lib.rs`
2. Run `./build.sh` to rebuild
3. Test in the browser

Key functions:
- `sha256d`: Double SHA-256 hashing
- `meets_difficulty`: Checks if hash meets target difficulty
- `calculate_merkle_root`: Builds merkle tree from transactions
- `mine_with_progress`: Main mining function with progress reporting

## Troubleshooting

If you encounter issues:

- Make sure Rust and wasm-pack are installed
- Check browser console for errors
- Verify MIME types are correctly set for .wasm files
- Ensure cross-origin isolation policy allows WASM execution
- The JavaScript fallback will be used automatically if WASM fails 
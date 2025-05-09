// Bitcoin Mining implementation for Anubis
// This file implements client-side Bitcoin mining

// We'll dynamically import the mining wrapper with the correct path
let wasmInitialized = false;
let wasmModule = null;
let MiningJob = null;

// Try to load the WASM miner
async function loadWasmMiner(basePrefix) {
  try {
    const wasmDir = `${basePrefix}/.within.website/x/cmd/anubis/static/js/wasm`;
    console.log("Attempting to load WASM miner from:", wasmDir);
    
    // First check if the WASM file exists
    try {
      const wasmResponse = await fetch(`${wasmDir}/rust_miner_bg.wasm`);
      if (!wasmResponse.ok) {
        console.warn("WASM file not found, falling back to JavaScript implementation");
        return false;
      }
    } catch (e) {
      console.warn("WASM file check failed:", e);
      return false;
    }
    
    // Now import the JS module
    try {
      const rustWasmModule = await import(`${wasmDir}/rust_miner.js`);
      console.log("WASM module loaded:", rustWasmModule);
      
      // Initialize the WASM module
      wasmModule = rustWasmModule;
      MiningJob = rustWasmModule.MiningJob;
      
      // Initialize the WASM module
      await rustWasmModule.default();
      rustWasmModule.start(); // Initialize panic hook
      
      console.log("WASM miner initialized successfully");
      wasmInitialized = true;
      return true;
    } catch (e) {
      console.error("Error initializing WASM module:", e);
      return false;
    }
  } catch (err) {
    console.warn("Failed to load WASM miner, falling back to JavaScript implementation:", err);
    return false;
  }
}

export default async function bitcoinMine(
  job,
  extraNonce1,
  extraNonce2Size,
  difficulty,
  progressCallback = null,
  basePrefix = ""
) {
  console.debug("Bitcoin mining started");

  // Try to load the WASM miner if not already loaded
  if (!wasmInitialized) {
    await loadWasmMiner(basePrefix);
  }

  // If WASM miner is loaded, use it
  if (wasmInitialized && MiningJob) {
    console.log("Using WASM miner for better performance");
    try {
      return await mineWithWasm(job, extraNonce1, extraNonce2Size, difficulty, progressCallback);
    } catch (err) {
      console.warn("WASM miner failed, falling back to JavaScript implementation:", err);
      // Fall back to JavaScript implementation
    }
  }

  // Fall back to the original JavaScript implementation
  return new Promise((resolve, reject) => {
    let webWorkerURL = URL.createObjectURL(
      new Blob(["(", bitcoinMiningTask(), ")()"], {
        type: "application/javascript",
      })
    );

    let worker = new Worker(webWorkerURL);

    worker.onmessage = (event) => {
      if (typeof event.data === "number") {
        progressCallback?.(event.data);
      } else {
        worker.terminate();
        URL.revokeObjectURL(webWorkerURL);
        resolve(event.data);
      }
    };

    worker.onerror = (event) => {
      worker.terminate();
      URL.revokeObjectURL(webWorkerURL);
      reject(event);
    };

    worker.postMessage({
      job,
      extraNonce1,
      extraNonce2Size,
      difficulty,
    });
  });
}

// WASM mining implementation using direct Rust exports
async function mineWithWasm(job, extraNonce1, extraNonce2Size, difficulty, progressCallback = null) {
  console.debug("Bitcoin WASM mining started");
  
  return new Promise((resolve, reject) => {
    try {
      // Create mining job object
      const miningJob = new MiningJob(
        job.version,
        job.prev_hash,
        job.ntime,
        job.nbits,
        job.coinbase1,
        job.coinbase2,
        extraNonce1,
        extraNonce2Size,
        difficulty
      );
      
      // Set merkle branches
      if (job.merkle_branches && job.merkle_branches.length > 0) {
        miningJob.set_merkle_branches(job.merkle_branches.join(','));
      }
      
      // Find share with progress reporting
      const batchSize = 5000000;
      let totalHashes = 0;
      let lastReportTime = Date.now();
      
      // Create a worker for reporting progress
      const reportWorker = setInterval(() => {
        if (progressCallback && totalHashes > 0) {
          const now = Date.now();
          const rate = totalHashes / ((now - lastReportTime) / 1000);
          progressCallback(totalHashes, rate);
        }
      }, 1000);
      
      // Function to mine in batches to avoid blocking the UI
      function mineNextBatch() {
        const result = miningJob.mine_with_progress(batchSize);
        const resultObj = JSON.parse(result);
        
        totalHashes += resultObj.iterations;
        
        if (resultObj.status === 'found') {
          // Found a solution
          clearInterval(reportWorker);
          resolve({
            job_id: job.job_id,
            extraNonce2: resultObj.extraNonce2,
            nTime: job.ntime,
            nonce: resultObj.nonce,
            hash: resultObj.hash
          });
        } else {
          // Continue mining
          setTimeout(mineNextBatch, 0);
        }
      }
      
      // Start mining
      mineNextBatch();
    } catch (err) {
      reject(err);
    }
  });
}

function bitcoinMiningTask() {
  return function () {
    // SHA-256 implementation
    const sha256 = async (data) => {
      const encoded =
        typeof data === "string" ? new TextEncoder().encode(data) : data;
      return crypto.subtle.digest("SHA-256", encoded.buffer || encoded);
    };

    // Double SHA-256 for Bitcoin
    const sha256d = async (data) => {
      const firstHash = await sha256(data);
      return sha256(new Uint8Array(firstHash));
    };

    // Convert hex string to Uint8Array
    function hexToBytes(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
    }

    // Convert Uint8Array to hex string
    function bytesToHex(bytes) {
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    // Swap byte order (endianness conversion)
    function swapEndian(hex) {
      return hex.match(/.{2}/g).reverse().join("");
    }

    // Calculate merkle root
    function calculateMerkleRoot(coinbaseHash, branches) {
      let hash = coinbaseHash;

      for (const branch of branches) {
        // Concatenate hash and branch
        const combined = hexToBytes(hash + branch);

        // Double SHA-256 hash
        const firstHash = crypto.subtle.digest("SHA-256", combined);
        const firstHashArray = new Uint8Array(firstHash);

        const secondHash = crypto.subtle.digest("SHA-256", firstHashArray);
        const secondHashArray = new Uint8Array(secondHash);

        // Convert to hex
        hash = bytesToHex(secondHashArray);
      }

      return hash;
    }

    // Check if hash meets difficulty
    function meetsDifficulty(hash, difficulty) {
      // Convert difficulty to target
      const target = difficultyToTarget(difficulty);

      // Convert both hash and target to BigInt for comparison
      // In Bitcoin, the hash must be less than or equal to the target
      const hashInt = BigInt("0x" + hash);
      const targetInt = BigInt("0x" + target);

      // Return true if hash <= target
      return hashInt <= targetInt;
    }

    // Convert difficulty to target
    function difficultyToTarget(difficulty) {
      // The highest possible target (difficulty 1) in Bitcoin
      const maxTargetHex =
        "00000000FFFF0000000000000000000000000000000000000000000000000000";
      const maxTarget = BigInt("0x" + maxTargetHex);

      // Handle edge cases
      if (difficulty <= 0) {
        return maxTargetHex;  // Return max target for zero or negative difficulty
      }

      // For better precision with floating point difficulties:
      // 1. Convert difficulty to a fixed precision value
      // 2. Use the relationship: target = maxTarget / difficulty
      
      // Convert to a large integer with 8 decimal places of precision
      const precisionFactor = 100000000;
      const difficultyInt = Math.floor(difficulty * precisionFactor);
      
      // Calculate target using integer math first, then adjust for the precision factor
      let target = maxTarget * BigInt(precisionFactor) / BigInt(difficultyInt);

      // Convert to hex string with proper padding
      return target.toString(16).padStart(64, "0");
    }

    addEventListener("message", async (event) => {
      const { job, extraNonce1, extraNonce2Size, difficulty } = event.data;

      // Calculate max value for extraNonce2 based on its size (in bytes)
      const maxExtraNonce2 = Math.pow(2, extraNonce2Size * 8) - 1;

      // Randomize extraNonce2 starting value within valid range
      let extraNonce2 = Math.floor(Math.random() * maxExtraNonce2);
      console.debug(
        `Starting mining with random extraNonce2: 0x${extraNonce2.toString(16)}`
      );

      // Use random starting nonce instead of always starting at 0
      // This helps distribute the search space across multiple clients
      let nonce = Math.floor(Math.random() * 0xffffffff);
      console.debug(
        `Starting mining with random nonce: 0x${nonce.toString(16)}`
      );

      // Mining loop
      while (true) {
        // Format extraNonce2 with proper padding
        const extraNonce2Hex = extraNonce2
          .toString(16)
          .padStart(extraNonce2Size * 2, "0");

        // Construct coinbase transaction
        const coinbaseTx =
          job.coinbase1 + extraNonce1 + extraNonce2Hex + job.coinbase2;

        // Hash coinbase transaction with double SHA-256
        const coinbaseHash = await sha256d(hexToBytes(coinbaseTx));
        const coinbaseHashHex = bytesToHex(new Uint8Array(coinbaseHash));

        // Calculate merkle root
        let merkleRoot = coinbaseHashHex;
        for (const branch of job.merkle_branches) {
          // Concatenate hash and branch
          const combined = hexToBytes(merkleRoot + branch);

          // Double SHA-256
          const hash = await sha256d(combined);
          merkleRoot = bytesToHex(new Uint8Array(hash));
        }

        // Bitcoin block header is in little-endian, but we'll keep it in big-endian for simplicity
        // Swap endianness when necessary for compatibility with pool

        // Format nonce as hex with proper padding
        const nonceHex = nonce.toString(16).padStart(8, "0");

        // Construct block header
        const blockHeader =
          job.version +
          job.prev_hash +
          merkleRoot +
          job.ntime +
          job.nbits +
          nonceHex;

        // Hash block header with double SHA-256
        const headerHash = await sha256d(hexToBytes(blockHeader));
        const hashHex = bytesToHex(new Uint8Array(headerHash));

        // Bitcoin expects the hash in little-endian format for difficulty comparison
        const hashReversed = swapEndian(hashHex);

        // Check if hash meets difficulty
        if (meetsDifficulty(hashReversed, difficulty)) {
          // Found a valid share
          postMessage({
            job_id: job.job_id,
            extraNonce2: extraNonce2Hex,
            nTime: job.ntime,
            nonce: nonceHex,
            hash: hashReversed,
          });
          break;
        }

        // Update nonce
        nonce++;
        if (nonce > 0xffffffff) {
          // We've tried all possible nonce values for this extraNonce2
          // Reset nonce to 0 and try a different extraNonce2
          nonce = 0;
          extraNonce2++;

          // Safety check to avoid infinite loops if we've gone through the entire extraNonce2 range
          if (extraNonce2 > maxExtraNonce2) {
            console.warn(
              "Exhausted all possible extraNonce2 values without finding a solution"
            );
            // In a real implementation, we might want to request a new job at this point
            // For now, just wrap around to 0
            extraNonce2 = 0;
          }

          // Report progress periodically
          if (extraNonce2 % 100 === 0) {
            postMessage(extraNonce2 * 0xffffffff);
          }
        }

        // Periodically report progress
        if ((nonce & 0xfffff) === 0) {
          postMessage(nonce);
        }
      }
    });
  }.toString();
}

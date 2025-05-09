use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};
use web_sys::console;

// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

// Log function for debugging
fn log(s: &str) {
    console::log_1(&JsValue::from_str(s));
}

// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let res = u8::from_str_radix(&hex[i..i + 2], 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => log(&format!("Error parsing hex: {}", e)),
        }
    }
    bytes
}

// Convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Swap byte order (endianness conversion)
fn swap_endian(hex: &str) -> String {
    let mut result = String::new();
    for i in (0..hex.len()).step_by(2).rev() {
        result.push_str(&hex[i..i + 2]);
    }
    result
}

// Double SHA-256 hash
fn sha256d(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(first_hash);
    hasher.finalize().to_vec()
}

// Calculate merkle root
fn calculate_merkle_root(coinbase_hash: &str, branches: &[String]) -> String {
    let mut hash = coinbase_hash.to_string();
    
    for branch in branches {
        // Concatenate hash and branch
        let combined = hex_to_bytes(&(hash.clone() + branch));
        
        // Double SHA-256
        let hash_result = sha256d(&combined);
        hash = bytes_to_hex(&hash_result);
    }
    
    hash
}

// Use a full 256-bit representation for better precision
#[derive(Debug, Clone, Copy)]
struct Target {
    high: u128,
    low: u128,
}

impl Target {
    fn new(high: u128, low: u128) -> Self {
        Self { high, low }
    }
    
    fn from_hex(hex: &str) -> Self {
        assert_eq!(hex.len(), 64);
        let high = u128::from_str_radix(&hex[0..32], 16).unwrap_or(0);
        let low = u128::from_str_radix(&hex[32..], 16).unwrap_or(0);
        Self { high, low }
    }
    
    fn to_hex(&self) -> String {
        format!("{:032x}{:032x}", self.high, self.low)
    }
    
    // Compare if self <= other
    fn le(&self, other: &Self) -> bool {
        if self.high < other.high {
            true
        } else if self.high > other.high {
            false
        } else {
            self.low <= other.low
        }
    }
}

// Check if hash meets difficulty
fn meets_difficulty(hash: &str, difficulty: f64) -> bool {
    // Convert difficulty to target
    let target = difficulty_to_target(difficulty);
    
    // Convert hash to Target
    let hash_target = Target::from_hex(hash);
    
    // Return true if hash <= target
    hash_target.le(&target)
}

// Convert difficulty to target with full 256-bit precision
fn difficulty_to_target(difficulty: f64) -> Target {
    // The highest possible target (difficulty 1) in Bitcoin
    let max_target_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000";
    let max_target = Target::from_hex(max_target_hex);
    
    // Handle edge cases
    if difficulty <= 0.0 {
        return max_target;
    }
    
    // For difficulty 1, return max_target
    if (difficulty - 1.0).abs() < f64::EPSILON {
        return max_target;
    }
    
    // Use integer division with scaling for better precision
    const SCALE: u128 = 1_000_000_000;
    let scaled_diff = (difficulty * SCALE as f64) as u128;
    
    if difficulty >= 1.0 {
        // For difficulty > 1, divide the max target
        // Calculate target = max_target / difficulty
        
        // Handle the low part first
        let mut result_low = max_target.low * SCALE / scaled_diff;
        let remainder_low = max_target.low * SCALE % scaled_diff;
        
        // Handle the high part with carry from low part
        let mut result_high = max_target.high * SCALE / scaled_diff;
        let remainder_high = max_target.high * SCALE % scaled_diff;
        
        // Add the remainder from high part to low part result
        result_low += remainder_high * (u128::MAX / scaled_diff);
        
        // Handle carry from remainder_low
        if remainder_low > 0 {
            result_low += remainder_low / scaled_diff;
        }
        
        // Handle carry from low to high if needed
        if result_low > max_target.low {
            result_high += 1;
        }
        
        Target::new(result_high, result_low)
    } else {
        // For difficulty < 1, multiply the max target (target gets larger)
        let inverse_scaled = (SCALE as f64 / difficulty) as u128;
        
        // Calculate target = max_target * (1/difficulty)
        let mut result_low = max_target.low * inverse_scaled / SCALE;
        let remainder_low = max_target.low * inverse_scaled % SCALE;
        
        let mut result_high = max_target.high * inverse_scaled / SCALE;
        let remainder_high = max_target.high * inverse_scaled % SCALE;
        
        // Add the remainder from high part to low part result
        if remainder_high > 0 {
            result_low += remainder_high * (u128::MAX / SCALE);
        }
        
        // Handle carry from remainder_low
        if remainder_low > 0 {
            result_low += remainder_low / SCALE;
        }
        
        // Handle carry from low to high if needed
        if result_low > max_target.low {
            result_high += 1;
        }
        
        // Handle overflow (rare but possible for extremely small difficulty)
        if result_high >= 16_u128.pow(16) {
            return Target::new(u128::MAX, u128::MAX);
        }
        
        Target::new(result_high, result_low)
    }
}

#[wasm_bindgen]
pub struct MiningJob {
    version: String,
    prev_hash: String,
    merkle_root: String,
    ntime: String,
    nbits: String,
    coinbase1: String,
    coinbase2: String,
    extra_nonce1: String,
    extra_nonce2_size: usize,
    merkle_branches: Vec<String>,
    difficulty: f64,
    // Add state variables to persist search state between calls
    current_nonce: u32,
    current_extra_nonce2: u64,
    merkle_root_current: bool,
}

#[wasm_bindgen]
impl MiningJob {
    #[wasm_bindgen(constructor)]
    pub fn new(
        version: String, 
        prev_hash: String,
        ntime: String, 
        nbits: String,
        coinbase1: String,
        coinbase2: String,
        extra_nonce1: String,
        extra_nonce2_size: usize,
        difficulty: f64
    ) -> MiningJob {
        MiningJob {
            version,
            prev_hash,
            merkle_root: String::new(),
            ntime,
            nbits,
            coinbase1,
            coinbase2,
            extra_nonce1,
            extra_nonce2_size,
            merkle_branches: Vec::new(),
            difficulty,
            // Initialize state variables
            current_nonce: 0,
            current_extra_nonce2: 0,
            merkle_root_current: false,
        }
    }
    
    #[wasm_bindgen]
    pub fn set_merkle_branches(&mut self, branches_str: String) {
        let branches: Vec<String> = branches_str.split(',').map(|s| s.to_string()).collect();
        self.merkle_branches = branches;
    }
    
    #[wasm_bindgen]
    pub fn set_difficulty(&mut self, difficulty: f64) {
        self.difficulty = difficulty;
        // Reset mining state when difficulty changes
        self.current_nonce = 0;
        self.current_extra_nonce2 = 0;
        self.merkle_root_current = false;
    }
    
    #[wasm_bindgen]
    pub fn find_share(&mut self) -> Option<String> {
        // Calculate max value for extraNonce2 based on its size
        let max_extra_nonce2 = (1u64 << (self.extra_nonce2_size * 8)) - 1;
        
        log(&format!("Starting mining with extraNonce2: 0x{:x}, nonce: 0x{:x}", 
                   self.current_extra_nonce2, self.current_nonce));
        
        // Optimization: pre-compute parts that don't change with nonce
        let mut iterations = 0;
        let max_iterations = 100_000_000; // Limit to prevent browser hanging
        let report_interval = 500_000;
        
        while iterations < max_iterations {
            // Check if we need to recalculate the merkle root
            if !self.merkle_root_current {
                // Format extraNonce2 with proper padding
                let extra_nonce2_hex = format!("{:0width$x}", self.current_extra_nonce2, width = self.extra_nonce2_size * 2);
                
                // Construct coinbase transaction
                let coinbase_tx = format!("{}{}{}{}", self.coinbase1, self.extra_nonce1, extra_nonce2_hex, self.coinbase2);
                
                // Hash coinbase transaction
                let coinbase_hash_bytes = sha256d(&hex_to_bytes(&coinbase_tx));
                let coinbase_hash_hex = bytes_to_hex(&coinbase_hash_bytes);
                
                // Calculate merkle root
                self.merkle_root = calculate_merkle_root(&coinbase_hash_hex, &self.merkle_branches);
                
                // Update tracking variables
                self.merkle_root_current = true;
            }
            
            // Try different nonce values sequentially
            let nonce_limit = std::cmp::min(self.current_nonce + 10_000, 0xFFFFFFFF);
            
            for current_nonce in self.current_nonce..nonce_limit {
                // Format nonce as hex
                let nonce_hex = format!("{:08x}", current_nonce);
                
                // Construct block header
                let block_header = format!("{}{}{}{}{}{}", 
                    self.version, self.prev_hash, self.merkle_root, self.ntime, self.nbits, nonce_hex);
                
                // Hash block header
                let header_hash_bytes = sha256d(&hex_to_bytes(&block_header));
                let hash_hex = bytes_to_hex(&header_hash_bytes);
                
                // Bitcoin expects the hash in little-endian format for difficulty comparison
                let hash_reversed = swap_endian(&hash_hex);
                
                // Check if hash meets difficulty
                if meets_difficulty(&hash_reversed, self.difficulty) {
                    // Found a valid share!
                    log(&format!("Found valid share after {} iterations", iterations));
                    
                    // Get current extraNonce2 hex
                    let extra_nonce2_hex = format!("{:0width$x}", self.current_extra_nonce2, width = self.extra_nonce2_size * 2);
                    
                    // Update the current_nonce for next time
                    self.current_nonce = current_nonce + 1;
                    
                    // Return the result as JSON
                    return Some(format!("{{\"extraNonce2\":\"{}\",\"nonce\":\"{}\",\"hash\":\"{}\"}}",
                        extra_nonce2_hex, nonce_hex, hash_reversed));
                }
                
                iterations += 1;
            }
            
            // Update nonce for next attempt - use sequential approach
            self.current_nonce = nonce_limit;
            
            // If we've exhausted the nonce space, update extraNonce2
            if self.current_nonce >= 0xFFFFFFFF {
                self.current_nonce = 0;
                self.current_extra_nonce2 += 1;
                self.merkle_root_current = false; // Force merkle root recalculation
                
                // If we've exhausted the extraNonce2 space, we're done
                if self.current_extra_nonce2 > max_extra_nonce2 {
                    break;
                }
                
                log(&format!("Switching to new extraNonce2: 0x{:x}", self.current_extra_nonce2));
            }
            
            // Report progress
            if iterations % report_interval == 0 {
                log(&format!("Progress: {} hashes calculated", iterations));
            }
        }
        
        None
    }
    
    // Method to mine with progress updates
    #[wasm_bindgen]
    pub fn mine_with_progress(&mut self, max_iterations: u32) -> JsValue {
        let mut iterations = 0;
        
        // Calculate max value for extraNonce2 based on its size
        let max_extra_nonce2 = (1u64 << (self.extra_nonce2_size * 8)) - 1;
        
        // Use the persistent state variables instead of creating new ones
        // Mining loop
        while iterations < max_iterations {
            // Check if we need to recalculate the merkle root
            if !self.merkle_root_current {
                // Format extraNonce2 with proper padding
                let extra_nonce2_hex = format!("{:0width$x}", self.current_extra_nonce2, width = self.extra_nonce2_size * 2);
                
                // Construct coinbase transaction
                let coinbase_tx = format!("{}{}{}{}", self.coinbase1, self.extra_nonce1, extra_nonce2_hex, self.coinbase2);
                
                // Hash coinbase transaction
                let coinbase_hash_bytes = sha256d(&hex_to_bytes(&coinbase_tx));
                let coinbase_hash_hex = bytes_to_hex(&coinbase_hash_bytes);
                
                // Calculate merkle root
                self.merkle_root = calculate_merkle_root(&coinbase_hash_hex, &self.merkle_branches);
                
                // Update tracking variables
                self.merkle_root_current = true;
            }
            
            // Format nonce as hex
            let nonce_hex = format!("{:08x}", self.current_nonce);
            
            // Construct block header
            let block_header = format!("{}{}{}{}{}{}", 
                self.version, self.prev_hash, self.merkle_root, self.ntime, self.nbits, nonce_hex);
            
            // Hash block header
            let header_hash_bytes = sha256d(&hex_to_bytes(&block_header));
            let hash_hex = bytes_to_hex(&header_hash_bytes);
            
            // Bitcoin expects the hash in little-endian format for difficulty comparison
            let hash_reversed = swap_endian(&hash_hex);
            
            // Check if hash meets difficulty
            if meets_difficulty(&hash_reversed, self.difficulty) {
                // Format extraNonce2 for result (in case it wasn't formatted in this iteration)
                let extra_nonce2_hex = format!("{:0width$x}", self.current_extra_nonce2, width = self.extra_nonce2_size * 2);
                
                // Found a valid share!
                return JsValue::from_str(&format!("{{\"status\":\"found\",\"iterations\":{},\"extraNonce2\":\"{}\",\"nonce\":\"{}\",\"hash\":\"{}\"}}",
                    iterations, extra_nonce2_hex, nonce_hex, hash_reversed));
            }
            
            // Update nonce and iterations
            self.current_nonce += 1;
            iterations += 1;
            
            // If we've exhausted the nonce space, update extraNonce2
            if self.current_nonce >= 0xFFFFFFFFu32 {
                self.current_nonce = 0;
                self.current_extra_nonce2 += 1;
                self.merkle_root_current = false; // Force merkle root recalculation
                
                // If we've exhausted the extraNonce2 space, we're done
                if self.current_extra_nonce2 > max_extra_nonce2 {
                    // Reset to 0 to continue search (optional, can also just break)
                    self.current_extra_nonce2 = 0;
                    self.merkle_root_current = false;
                }
            }
        }
        
        // Return progress info
        JsValue::from_str(&format!("{{\"status\":\"progress\",\"iterations\":{}}}", iterations))
    }
}

#![deny(warnings)]

//! # Klomang Core Engine
//!
//! Production-ready BlockDAG engine implementation optimized for large-scale deployment.
//!
//! ## Key Features
//! - **GhostDAG Consensus**: BlockDAG with parallel block ordering
//! - **Verkle State Tree**: Efficient state management with O(log n) operations
//! - **Schnorr Signatures**: Batch verification for high TPS
//! - **Economic Policy**: 80/20 miner/fullnode reward distribution
//! - **Atomic State Transitions**: Rollback-safe state management
//!
//! ## Performance Optimizations
//! - Schnorr batch signature verification for block validation
//! - Incremental Verkle commitment caching for O(log n) state updates
//! - Reduced redundant root recomputation and path invalidation
//! - Parallel transaction processing with conflict detection
//!
//! ## Integration Guide
//!
//! ### Basic Usage
//! ```rust
//! use klomang_core::{GhostDag, UtxoSet, MemoryStorage, Dag, BlockNode, Hash};
//! use std::collections::HashSet;
//!
//! let storage = MemoryStorage::new();
//! let mut ghostdag = GhostDag::new(64);
//! let mut utxo = UtxoSet::new();
//! let mut dag = Dag::new();
//!
//! let genesis = BlockNode {
//!     id: Hash::new(b"genesis"),
//!     parents: HashSet::new(),
//!     children: HashSet::new(),
//!     selected_parent: None,
//!     blue_set: HashSet::new(),
//!     red_set: HashSet::new(),
//!     blue_score: 0,
//!     timestamp: 0,
//!     difficulty: 1,
//!     nonce: 0,
//!     transactions: Vec::new(),
//! };
//!
//! dag.add_block(genesis).expect("add genesis block");
//!
//! // Process blocks with automatic signature batch verification
//! // and Verkle state updates
//! ```
//!
//! ### State Management
//! ```rust
//! use klomang_core::core::state_manager::StateManager;
//! use klomang_core::core::state::v_trie::VerkleTree;
//! use klomang_core::core::state::MemoryStorage;
//! use klomang_core::core::state::utxo::UtxoSet;
//! use klomang_core::core::dag::BlockNode;
//! use klomang_core::core::crypto::Hash;
//! use std::collections::HashSet;
//!
//! # let storage = MemoryStorage::new();
//! # let tree = VerkleTree::new(storage.clone()).expect("create Verkle tree");
//! # let mut manager = StateManager::new(tree).expect("state manager");
//! # let mut utxo = UtxoSet::new();
//! # let block = BlockNode {
//! #     id: Hash::new(b"block1"),
//! #     parents: HashSet::new(),
//! #     children: HashSet::new(),
//! #     selected_parent: None,
//! #     blue_set: HashSet::new(),
//! #     red_set: HashSet::new(),
//! #     blue_score: 0,
//! #     timestamp: 0,
//! #     difficulty: 1,
//! #     nonce: 0,
//! #     transactions: Vec::new(),
//! # };
//! 
//! // Atomic block application with rollback capability
//! manager.apply_block(&block, &mut utxo).expect("apply block");
//!
//! let block = BlockNode {
//!     id: Hash::new(b"block1"),
//!     parents: HashSet::new(),
//!     children: HashSet::new(),
//!     selected_parent: None,
//!     blue_set: HashSet::new(),
//!     red_set: HashSet::new(),
//!     blue_score: 0,
//!     timestamp: 0,
//!     difficulty: 1,
//!     nonce: 0,
//!     transactions: Vec::new(),
//! };
//!
//! // Atomic block application with rollback capability
//! manager.apply_block(&block, &mut utxo).expect("apply block");
//! ```
//!
//! ## Security
//! - Anti-burn address enforcement
//! - Supply cap validation
//! - Double-spend prevention
//! - Cryptographic signature verification

pub mod core;

// Re-export public API for external node integration
pub use core::crypto::Hash;
pub use core::dag::{BlockNode, Dag};
pub use core::consensus::ghostdag::GhostDag;
pub use core::state::transaction::Transaction;
pub use core::state::BlockchainState;
pub use core::state::utxo::UtxoSet;
pub use core::state::{MemoryStorage, Storage};
pub use core::errors::CoreError;
pub use core::config::Config;
pub use core::consensus::emission::{COIN_UNIT, MAX_SUPPLY, block_reward};
pub use core::daa::difficulty::Daa;
pub use core::pow::Pow;

#[no_mangle]
pub extern "C" fn __rust_probestack() {}


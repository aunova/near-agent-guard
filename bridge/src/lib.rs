//! `guard`, the bridge between a sandboxed AI agent and the NEAR vault contract.
//!
//! The agent never holds a key. Each raw request is screened by `spend-screen.wasm` inside
//! WasmBox in a child process, signed into a hash-chained audit log, and only then, if screened
//! in, sent to the vault with the agent's function-call key (shared contract, section 3).

#![forbid(unsafe_code)]

pub mod audit;
pub mod chain;
pub mod config;
pub mod gate;
pub mod screen;
pub mod serve;
pub mod verify;

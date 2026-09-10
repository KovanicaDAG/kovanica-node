//! UniFFI bindings for the Kovanica light node.
//!
//! The mobile app is a **light validating wallet**: it syncs compact block
//! records over its own transport (the byte-blob API here wraps the exact wire
//! format full nodes speak), verifies and applies them under the same hybrid
//! admission rules as everyone else, and — once bonded — produces its own
//! stake-weighted VRF blocks by signing one hash. No mining rig required.
//!
//! Generate language bindings with the bundled helper:
//!
//! ```text
//! cargo run -p kovanica-ffi --bin uniffi-bindgen -- \
//!     generate --library target/debug/libkovanica_ffi.so \
//!     --language kotlin --out-dir bindings/kotlin
//! ```
//!
//! (Same command with `--language swift` for iOS.)

uniffi::setup_scaffolding!("kovanica");

mod light_node;

pub use light_node::*;

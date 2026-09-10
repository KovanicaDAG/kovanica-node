//! Thin HTTP client for the Kovanica explorer JSON API.
//!
//! Routes and shapes mirror `kovanica-node`'s `explorer.rs`:
//!   * `GET  /api/head`              — chain head summary
//!   * `GET  /api/p2p`               — p2p listen/peers/bootstrap
//!   * `GET  /api/bootstrap`         — network parameters
//!   * `GET  /api/state`             — full snapshot (includes the block DAG)
//!   * `GET  /api/utxos?address=…`   — balance + unspent outputs
//!   * `POST /api/prepare?from&to&amount`  — returns the sighash to sign
//!   * `POST /api/submit?from&to&amount&sig` — broadcasts the signed transfer
//!
//! Note: `/api/blocks` returns a binary record export, not JSON, so the `blocks`
//! command reads the `node.dag` array out of `/api/state` instead.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

/// A client bound to one explorer base URL (no trailing slash).
pub struct Client {
    base: String,
}

impl Client {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn call(builder: ureq::Request) -> Result<Value> {
        match builder.call() {
            Ok(resp) => {
                let text = resp.into_string()?;
                serde_json::from_str(&text)
                    .map_err(|e| anyhow!("response was not valid JSON: {e}\n{text}"))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                bail!("HTTP {code}: {}", body.trim())
            }
            Err(e) => Err(anyhow!("request failed: {e}")),
        }
    }

    fn get(&self, path: &str) -> Result<Value> {
        Self::call(ureq::get(&self.url(path)))
    }

    fn post(&self, path: &str) -> Result<Value> {
        Self::call(ureq::post(&self.url(path)))
    }

    pub fn head(&self) -> Result<Value> {
        self.get("/api/head")
    }

    pub fn p2p(&self) -> Result<Value> {
        self.get("/api/p2p")
    }

    pub fn bootstrap(&self) -> Result<Value> {
        self.get("/api/bootstrap")
    }

    pub fn state(&self) -> Result<Value> {
        self.get("/api/state")
    }

    /// The block DAG, pulled out of the full state snapshot.
    pub fn blocks(&self) -> Result<Value> {
        let mut state = self.state()?;
        match state.get_mut("node").and_then(|n| n.get_mut("dag")) {
            Some(dag) => Ok(dag.take()),
            None => Ok(state),
        }
    }

    /// Balance + unspent outputs for an address (hex or `kvnc…dag`).
    pub fn utxos(&self, address: &str) -> Result<Value> {
        self.get(&format!("/api/utxos?address={address}"))
    }

    /// Ask the node to build a transfer and return its signature hash.
    pub fn prepare(&self, from: &str, to: &str, amount: u64) -> Result<Value> {
        self.post(&format!("/api/prepare?from={from}&to={to}&amount={amount}"))
    }

    /// Broadcast a signed transfer. `sig` is 128 lowercase hex chars.
    pub fn submit(&self, from: &str, to: &str, amount: u64, sig: &str) -> Result<Value> {
        self.post(&format!(
            "/api/submit?from={from}&to={to}&amount={amount}&sig={sig}"
        ))
    }
}

/// Pretty-print a JSON value to stdout.
pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

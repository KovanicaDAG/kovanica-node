# kovanica-node

Run a **KovanicaDAG** node on `kovanica-testnet-1`.

GHOSTDAG BlockDAG + UTXO ledger (Ed25519). Native token **KVNC** (8 decimals).
Explorer: [explorer.kovanica.online](https://explorer.kovanica.online).
Wallet: [wallet.kovanica.online](https://wallet.kovanica.online) — the node never sees your seed.

**Join without git:** [JOIN.md](./JOIN.md)

```sh
curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash
```

Windows: `irm https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.ps1 | iex`

USB stick files: [`scripts/usb/`](./scripts/usb/).

## About this repo

This repository contains the **runnable node binary** (`kovanica-node`). The full protocol — DAG consensus, UTXO ledger, CLI, and web UI — lives in the unified [**kovanica-protocol**](https://github.com/KovanicaDAG/kovanica-protocol) monorepo:

```
kovanica-protocol/
├── crates/
│   ├── kovanica-dag/     # DAG + GHOSTDAG consensus
│   ├── kovanica-state/   # UTXO ledger
│   ├── kovanica-node/    # Node binary (this code)
│   └── kovanica-cli/     # CLI wallet
└── web/                  # React/TS UI (explorer, wallet, map)
```

For development, pull from [kovanica-protocol](https://github.com/KovanicaDAG/kovanica-protocol). This repo is a mirror for standalone binary distribution.

## Requirements

- Rust 1.75+ ([rustup](https://rustup.rs)) — the installer fetches this
- Linux, macOS, or Windows

## Build from a git checkout (optional)

```sh
git clone https://github.com/KovanicaDAG/kovanica-protocol.git
cd kovanica-protocol
cargo build --release -p kovanica-node
```

Binary: `./target/release/kovanica-node`

## Run a local node

HTTP explorer + JSON API on loopback:

```sh
export KOVANICA_POW=1
export KOVANICA_MINE=0
export KOVANICA_MINE_SECS=120
export KOVANICA_FAUCET=0
export KOVANICA_ALLOW_RESET=0
export KOVANICA_OPERATOR=0
export KOVANICA_DATA="$PWD/data"

./target/release/kovanica-node explorer 127.0.0.1:8080
```

Open http://127.0.0.1:8080

```sh
curl -s http://127.0.0.1:8080/api/head
```

First start writes genesis into `KOVANICA_DATA`. Keep that directory.

## Join the public testnet (TCP P2P)

**One path:** plaintext TCP on **9000**. There is no libp2p / 30333.

```
KOVANICA_PEERS=seed.kovanica.online:9000
```

That is the default when `KOVANICA_PEERS` is unset.

```sh
export KOVANICA_LISTEN=0.0.0.0:9000
export KOVANICA_PEERS=seed.kovanica.online:9000
export KOVANICA_POW=1
export KOVANICA_MINE=0
export KOVANICA_MINE_SECS=120
export KOVANICA_FAUCET=0
export KOVANICA_ALLOW_RESET=0
export KOVANICA_DATA="$PWD/data"

./target/release/kovanica-node explorer 127.0.0.1:8080
```

Open **9000/tcp** inbound only if you want to serve other peers. Outbound 9000
to the bootstrap host is enough to catch up.

After the first pull, these should match:

```sh
curl -s http://127.0.0.1:8080/api/head
curl -s https://explorer.kovanica.online/api/head
```

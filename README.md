# kovanica-node

Run a **KovanicaDAG** node on the public testnet.

GHOSTDAG BlockDAG + UTXO ledger (Ed25519). Native token **KVNC** (8 decimals).

| | |
| --- | --- |
| Explorer | https://explorer.kovanica.online |
| Wallet | https://wallet.kovanica.online |
| Network | `kovanica-testnet-1` |
| P2P | TCP **9000** only (no libp2p) |
| Bootstrap | `seed.kovanica.online:9000` |

The node never sees your wallet seed. You sign in the browser; the node only verifies.

---

## Quick start (recommended)

**Linux / macOS** — one command, no `git clone` required:

```sh
curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash
```

Start on login (systemd user unit):

```sh
curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash -s -- --systemd
```

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.ps1 | iex
```

The installer prefers a **prebuilt binary** from the latest GitHub Release when available, and falls back to building from source (Rust is installed automatically if needed).

After install:

```sh
# Linux / macOS
~/kovanica-node/run.sh

# Windows
%USERPROFILE%\kovanica-node\run.cmd
```

Then open http://127.0.0.1:8080 and verify:

```sh
curl -s http://127.0.0.1:8080/api/head
curl -s https://explorer.kovanica.online/api/head
```

`network` and `genesis` must match. `blocks` / tip will catch up after the first pull.

More detail: **[JOIN.md](./JOIN.md)** · Testnet parameters: **[TESTNET.md](./TESTNET.md)**

---

## USB stick (offline-friendly scripts)

Copy the folder [`scripts/usb/`](./scripts/usb/) onto a FAT32 stick. On the target machine run `install.sh` (or `install.ps1` on Windows) from that folder. Network is still required for the first build / binary download.

---

## Build from source (developers)

Requirements: Rust 1.75+ ([rustup](https://rustup.rs)), Linux / macOS / Windows.

```sh
git clone https://github.com/KovanicaDAG/kovanica-node.git
cd kovanica-node
cargo build --release -p kovanica-node
```

Binary: `./target/release/kovanica-node` (or `.exe` on Windows).

### Run a local node (solo / offline)

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
First start writes genesis into `KOVANICA_DATA`. Keep that directory.

### Join the public testnet

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

- Outbound TCP 9000 to the seed is enough to catch up.
- Open **inbound** 9000/tcp only if you want to serve other peers.
- If DNS/IPv6 stalls the pull on some Ubuntu setups, use the origin IP:

  ```sh
  export KOVANICA_PEERS=145.223.116.178:9000
  ```

---

## Environment variables (clone defaults)

| Variable | Default | Notes |
| --- | --- | --- |
| `KOVANICA_LISTEN` | `0.0.0.0:9000` | P2P bind (also tries `[::]:9000`) |
| `KOVANICA_PEERS` | `seed.kovanica.online:9000` | Comma-separated bootstrap list |
| `KOVANICA_POW` | `1` | Consensus PoW |
| `KOVANICA_MINE` | `0` | Leave off unless you intend to mint |
| `KOVANICA_MINE_SECS` | `120` | Interval when mining is on |
| `KOVANICA_FAUCET` | `0` | |
| `KOVANICA_DATA` | `./data` | Persistence directory |
| `KOVANICA_ALLOW_RESET` | `0` | |
| `KOVANICA_OPERATOR` | `0` | Never enable on public clones |

Addresses on screen look like `kvnc…dag` (base58). The ledger stores 64-hex; both forms work in the API / send UI.

---

## About this repository

This repo ships the **runnable node** and the supporting crates so anyone can build or install a clone without the full monorepo.

```
kovanica-node/                  ← this repository
├── crates/
│   ├── kovanica-dag/           # DAG + GHOSTDAG consensus
│   ├── kovanica-state/         # UTXO ledger
│   ├── kovanica-node/          # Node binary + explorer
│   ├── kovanica-cli/           # CLI wallet helpers
│   └── kovanica-ffi/           # Mobile / FFI bindings
├── scripts/                    # One-click installers + USB
└── deploy/                     # Optional nginx / Caddy / systemd examples
```

The broader protocol (web UI source, extra tooling) lives in the unified monorepo when you need it for development. For simply **running a node**, this repository is enough.

---

## Publishing prebuilt binaries (maintainers)

The install script prefers assets from GitHub Releases. After tagging a release, attach tarballs named:

- `kovanica-node-x86_64-linux.tar.gz`
- `kovanica-node-aarch64-linux.tar.gz`
- `kovanica-node-x86_64-macos.tar.gz`
- `kovanica-node-aarch64-macos.tar.gz`

Each tarball should contain a single `kovanica-node` (or `kovanica-node.exe`) binary at the root. See [RELEASES.md](./RELEASES.md) for the exact steps.

---

## License

MIT OR Apache-2.0. See [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE).

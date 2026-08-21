# kovanica-node

Clone this repo to **run a KovanicaDAG node** on `kovanica-testnet-1`.

GHOSTDAG BlockDAG + UTXO ledger (Ed25519). Native token **KVNC** (8 decimals).
The public explorer is [explorer.kovanica.online](https://explorer.kovanica.online).
The wallet UI is [wallet.kovanica.online](https://wallet.kovanica.online) — the node never sees your seed.

## Requirements

- Rust 1.75+ ([rustup](https://rustup.rs))
- Linux / macOS (Windows untested)

## Build

```sh
git clone https://github.com/KovanicaDAG/kovanica-node.git
cd kovanica-node
cargo build --release -p kovanica-node
```

Binary: `./target/release/kovanica-node`

## Run a local node

HTTP explorer + JSON API on loopback (does not collide with other sites):

```sh
export KOVANICA_POW=1
export KOVANICA_MINE=0
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

First start writes genesis into `KOVANICA_DATA`. Keep that directory if you want the same chain next time.

## Join the public testnet (TCP P2P)

**One path:** plaintext TCP on **9000**. There is no libp2p / 30333 — that layer
discovered peers and never exchanged blocks.

Public bootstrap:

```
KOVANICA_PEERS=explorer.kovanica.online:9000
```

That is the default when `KOVANICA_PEERS` is unset. The node also **listens** on
`0.0.0.0:9000` by default so other clones can pull from you.

```sh
export KOVANICA_LISTEN=0.0.0.0:9000          # default; set to `off` to disable
export KOVANICA_PEERS=explorer.kovanica.online:9000
export KOVANICA_POW=1
export KOVANICA_MINE=0
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

Same `genesis`, and `tip` once the seed has served its blocks. Status:

```sh
curl -s http://127.0.0.1:8080/api/p2p
```

If the seed is not yet listening on 9000, a clone is a **solo** explorer (own
genesis, no sync). That is a seed-side bind, not a bug in this binary.

Live chain info without running a node: `GET https://explorer.kovanica.online/api/head`

## Modes

```sh
./target/release/kovanica-node explorer 127.0.0.1:8080   # HTTP API + UI + TCP P2P
./target/release/kovanica-node demo                      # scripted smoke
./target/release/kovanica-node                           # stdin RPC
./target/release/kovanica-node help
```

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `KOVANICA_DATA` | `./data` | snapshots |
| `KOVANICA_POW` | `1` | hash-target PoW |
| `KOVANICA_MINE` | `0` | auto-mine empty blocks |
| `KOVANICA_FAUCET` | `0` | mint to an address |
| `KOVANICA_OPERATOR` | `0` | mine / miner / mining endpoints |
| `KOVANICA_ALLOW_RESET` | `0` | wipe the DAG |
| `KOVANICA_LISTEN` | `0.0.0.0:9000` | TCP P2P bind (`off` to disable) |
| `KOVANICA_PEERS` | `explorer.kovanica.online:9000` | comma-separated `host:9000` (`off` to disable) |

Public seed node keeps faucet / mine / reset **off**. Do the same if you peer with it.
The seed should set `KOVANICA_PEERS=off` so it does not dial itself.

Do **not** bind 80, 443, 3010, 8080 (that's the HTTP explorer), 5000, 5173, or 8000.

## Crates

| Crate | Role |
| --- | --- |
| `kovanica-dag` | BlockDAG, GHOSTDAG, PoW |
| `kovanica-state` | UTXO, Ed25519, snapshots |
| `kovanica-node` | this binary (RPC, explorer, TCP P2P) |

Web UI (not this repo): [kovanica-web](https://github.com/KovanicaDAG/kovanica-web).

See [TESTNET.md](./TESTNET.md) for `kovanica-testnet-1` constants.

## License

MIT OR Apache-2.0

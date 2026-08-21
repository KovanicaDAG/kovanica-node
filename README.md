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

## Join the public testnet (P2P)

TCP gossip (blocks):

```sh
export KOVANICA_LISTEN=0.0.0.0:9000
export KOVANICA_PEERS=BOOTSTRAP_HOST:9000
```

Open **9000/tcp** on your firewall. `KOVANICA_PEERS` is a comma-separated list.

libp2p (mdns / gossipsub) also listens on **30333/tcp** when explorer mode starts.

Live chain info without running a node: `GET https://explorer.kovanica.online/api/head`

## Modes

```sh
./target/release/kovanica-node explorer 127.0.0.1:8080   # HTTP API + UI
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
| `KOVANICA_LISTEN` | unset | TCP P2P bind (`0.0.0.0:9000`) |
| `KOVANICA_PEERS` | unset | `host:9000,host2:9000` |

Public seed node keeps faucet / mine / reset **off**. Do the same if you peer with it.

## Crates

| Crate | Role |
| --- | --- |
| `kovanica-dag` | BlockDAG, GHOSTDAG, PoW |
| `kovanica-state` | UTXO, Ed25519, snapshots |
| `kovanica-node` | this binary (RPC, explorer, P2P) |

Web UI (not this repo): [kovanica-web](https://github.com/KovanicaDAG/kovanica-web).

See [TESTNET.md](./TESTNET.md) for `kovanica-testnet-1` constants.

## License

MIT OR Apache-2.0

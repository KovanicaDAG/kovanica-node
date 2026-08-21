# kovanica-testnet-1

Public BlockDAG testnet. Native token **KVNC** (8 decimals).

| | |
| --- | --- |
| Explorer | https://explorer.kovanica.online |
| Wallet | https://wallet.kovanica.online |
| Node source | https://github.com/KovanicaDAG/kovanica-node |
| Network | `kovanica-testnet-1` |
| Premine | 50 KVNC (founder) |
| Subsidy cap | 50 KVNC / block, halves every 1000 blocks |
| Min fee | 0.0001 KVNC at genesis |
| k | 3 (GHOSTDAG) |
| PoW | on (`KOVANICA_POW=1`) |
| P2P | TCP `KOVANICA_LISTEN` (default `:9000`); libp2p `:30333` |

Live genesis and tip: `GET https://explorer.kovanica.online/api/head`  
Bootstrap blob: `GET https://explorer.kovanica.online/api/bootstrap`

## Tokenomics

- 1 KVNC = 10^8 atoms.
- New coins only from coinbase (issuance + fees to the miner).
- Faucet and empty-block minting are **off** on the public explorer.
- Wallet `prepare` / `submit` stays open: you sign in the browser; the node never sees the seed.

## Run

See [README.md](./README.md).

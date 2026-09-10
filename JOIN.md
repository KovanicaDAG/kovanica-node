# Join kovanica-testnet

Public seed: **`seed.kovanica.online:9000`** (TCP only, grey-cloud DNS).  
HTTP explorer: https://explorer.kovanica.online  
Wallet: https://wallet.kovanica.online

Your node is a **clone**. It pulls the DAG over TCP 9000 and can push extra
blocks back to the seed. Do **not** point `KOVANICA_PEERS` at this box if you
**are** the seed.

## One click (no `git clone`)

**Linux / macOS:**

```sh
curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash
```

Start on login (systemd user unit):

```sh
curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash -s -- --systemd
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.ps1 | iex
```

The installer:

1. Tries a **prebuilt binary** from the latest GitHub Release (Linux/macOS x86_64 & arm64).
2. Falls back to downloading the source tarball/zip and building with Cargo (Rust is installed automatically if missing).
3. Writes `~/kovanica-node/run.sh` (or `run.cmd` on Windows) and a `data/` directory.

Override install location or peers:

```sh
KOVANICA_HOME=~/my-node KOVANICA_PEERS=seed.kovanica.online:9000,seed3.kovanica.online:9000 \
  bash <(curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh)
```

## USB stick

Copy [`scripts/usb/`](./scripts/usb/) onto a FAT32 stick (folder copy — do not
`dd` an image). On the target machine run `install.sh` or `install.ps1` from
that folder. Same installer logic; needs network for the first build or binary download.

## Start & check

```sh
# after install
~/kovanica-node/run.sh          # Linux/macOS
# or open run.cmd on Windows
```

Then:

```sh
curl -s http://127.0.0.1:8080/api/head
curl -s https://explorer.kovanica.online/api/head
```

`network` and `genesis` must match. `blocks` / tip catch up after the first pull.

If Ubuntu prefers IPv6 and the pull stalls, set:

```sh
export KOVANICA_PEERS=145.223.116.178:9000
```

and restart the node.

## Environment (clone)

| Variable | Default |
| --- | --- |
| `KOVANICA_LISTEN` | `0.0.0.0:9000` (also tries `[::]:9000`) |
| `KOVANICA_PEERS` | `seed.kovanica.online:9000` |
| `KOVANICA_MINE` | `0` |
| `KOVANICA_MINE_SECS` | `120` (only if mine is on) |
| `KOVANICA_FAUCET` | `0` |
| `KOVANICA_TAP` | `0` on clones |
| `KOVANICA_POW` | `1` |
| `KOVANICA_DATA` | `./data` (installer uses `~/kovanica-node/data`) |
| `KOVANICA_ALLOW_RESET` | `0` |
| `KOVANICA_OPERATOR` | `0` — never enable on public clones |

Addresses on screen look like `kvnc…dag` (base58 of the 32-byte key). The ledger
still stores 64-hex; paste either form into send / API.

## Firewall note

Outbound TCP 9000 to the seed is enough. Open inbound 9000 only if you want to
serve other peers. Do **not** bind the explorer HTTP port on `0.0.0.0` unless
you intentionally want a public explorer (the installer binds `127.0.0.1:8080`).

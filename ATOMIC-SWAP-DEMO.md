# Atomic Swap Demo — M1.6 runbook

End-to-end atomic swap over the public testnet, exactly as staged for the MVP
demo (roadmap M1.4–M1.6): a maker locks KVNC into a hash-locked contract
(HTLC), a taker claims it by revealing the preimage, and — on timeout — the
maker recovers the funds. **Keys never leave the browser**; the node only ever
sees 64-byte signatures.

Backing proof of the exact HTTP flow used below: `explorer::tests::htlc_http_prepare_sign_submit_status_flow` and `explorer::tests::htlc_http_refund_flow` in `crates/kovanica-node/src/explorer.rs`.

## 1. Topology

| Piece | URL / value |
| --- | --- |
| Public explorer | `https://explorer.kovanica.online` (orange-cloud) |
| P2P seed | `seed.kovanica.online:9000` (grey-cloud / origin IP) |
| Faucet | `https://faucet.kovanica.online` (1 tKVNC, rate-limited) |
| Wallet | `https://wallet.kovanica.online` |
| Network | `kovanica-testnet-1`, k=3, KVNC = 10^8 atoms |
| HTLC address version | `0x04` (100-byte script, see RFC-004) |
| Preimage | BLAKE3, 32 bytes; committed on-chain as `preimage_hash` |

## 2. Run a local explorer + join node (optional)

The public explorer is read-only (`KOVANICA_MINE=0`, no faucet). For a
hands-on demo you can run your own node that mines and joins the seed:

```bash
cd /root/kovanica/kovanica-node
cargo build --release

KOVANICA_DATA=/tmp/kovanica-demo \
KOVANICA_MINE=1 \
KOVANICA_MINE_SECS=10 \
KOVANICA_FAUCET=1 \
KOVANICA_PEERS=seed.kovanica.online:9000 \
KOVANICA_LISTEN=0.0.0.0:9000 \
  ./target/release/kovanica-node explorer 0.0.0.0:8080
```

- `KOVANICA_MINE_SECS` — empty-block spacing (120s on the public node; 10s here so the demo doesn't drag).
- `KOVANICA_FAUCET=1` — open the genesis grants on *your* node only.
- On first boot the node pulls the chain dump from the seed over TCP 9000; wait for `P2P` heads to converge: `curl localhost:8080/api/p2p`.

### Coinbase maturity (CSV)

Spends of your freshly-mined coinbase are rejected for the first **100 blocks**
after mining (RFC-006 enforced at block construction against the real next
height). Mine ~100 blocks before funding the swap, or fund from UTXOs that are
already mature.

## 3. Fund the two wallets

1. `https://wallet.kovanica.online` — create wallet A (maker) and wallet B (taker).
2. Copy each address (note: the wallet address's 32-byte payload **is** the
   recipient public key, hex, 64 chars).
3. Hit the faucet for wallet A; if running your own node, `KOVANICA_FAUCET=1`
   plus a fee-agent/`send` covers B.
4. Confirm balances on the explorer, then open **Atomic Swap** in the wallet
   (the swap view live-renders both contract sides).

## 4. Browser demo

### 4.1 Maker (Alice) creates the offer

1. **Create Offer** — enter amount (min **0.001 KVNC**, see fee note below),
   recipient_pk **= wallet B's address payload**, a preimage (auto-generated),
   and a timeout (absolute block height, e.g. current tip + 10).
2. The view funds **HTLC-A** via `/api/htlc/prepare` → local `signSighash` →
   `/api/htlc/finalize` → `/api/submit_tx`. The preimage stays in Alice's
   browser.
3. Copy the offer: `{recipient_pk, preimage_hash, timeout, amount}` and send it
   to the taker out-of-band.

### 4.2 Taker (Bob) funds HTLC-B and claims

1. **Paste Offer**, then **Fund HTLC-B** — Bob's wallet funds the reflected
   contract `{preimage_hash, timeout}` back to Alice (the mirrored side).
2. To reveal the preimage and claim HTLC-B, Bob needs Alice's preimage. In the
   demo this is pasted (or walked over); on a real swap the timelock arms — Bob
   claims HTLC-B, which reveals the preimage on-chain, then Bob claims HTLC-A.
3. **Claim (Taker, Reveal Preimage)** on HTLC-A — the view calls
   `/api/htlc/spend` with `kind:"redeem"`, signs the sighash locally, sends the
   signature to `/api/htlc/finalize`, and submits. The node verifies the
   signature against the script's recipient pk and that
   `BLAKE3(preimage) == preimage_hash`.

### 4.3 Timeout path

If Bob never claims, after `tip >= timeout` Alice uses **Refund (Sender, after
Timeout)** on HTLC-A → `/api/htlc/spend` `kind:"refund"`, signs, finalizes,
submits. Before the timeout the ledger drops the refund spend at block
construction (`HtlcTimeoutNotReached`).

## 5. Verify on the explorer

Every step is plain HTTP, so a demo can also be shown in a terminal:

```bash
# unsigned funding tx + sighash (sign the sighash in the browser, never here)
curl -s localhost:8080/api/htlc/prepare -H 'Content-Type: application/json' \
  -d '{"from":"<wallet-a-addr>","amount":100000000,
       "recipient_pk":"<wallet-b-pk>",
       "preimage_hash":"<b3-hex>","timeout":<tip+10>}'
# → {"ok":true,"tx_hex":"…","sighash":"…","script_hex":"…","address":"…","value":…,"fee":…}

# funding tx with a locally-signed signature
curl -s localhost:8080/api/htlc/finalize -H 'Content-Type: application/json' \
  -d '{"tx_hex":"…","signature_hex":"…"}'
curl -s localhost:8080/api/submit_tx -H 'Content-Type: application/json' -d '{"tx_hex":"…"}'
# → {"ok":true,"tx":"<funding-txid>"}

# locked? balance == amount
curl -s localhost:8080/api/htlc/status -H 'Content-Type: application/json' \
  -d '{"script_hex":"…"}'
# → {"ok":true,"balance":100000000,"redeem_tx":null,"preimage":null}

# unsigned redeem (taker), then finalize + submit as above
curl -s localhost:8080/api/htlc/spend -H 'Content-Type: application/json' \
  -d '{"outpoint_tx":"<funding-txid>","outpoint_index":0,
       "script_hex":"…","to":"<taker-addr>","kind":"redeem",
       "preimage_hex":"<b3-hex>"}'
# → {"ok":true,"tx_hex":"…","sighash":"…","value":…,"fee":…}

# after the redeem lands → {"ok":true,"balance":0,"redeem_tx":"…","preimage":"…"}
curl -s localhost:8080/api/htlc/status -H 'Content-Type: application/json' -d '{"script_hex":"…"}'
```

The `sighash`/`tx_hex` are the *unsigned* spend; `/api/htlc/finalize` with
`{"script_hex","kind","preimage_hex","signature_hex"}` returns `signed_tx_hex`.
A signature from the wrong key returns `400 bad spend signature`.

## 6. Gotchas

- **Fee eats the locked value.** The native refund/redeem pays the fee out of
  the locked amount (`value - fee` to the claimant). A 500-atom HTLC is
  *un-refundable* because the fee exceeds the value — fund the demo contract
  comfortably above the fee (1 KVNC is safe).
- **Taker claim ⊕ chain scrape.** Once either contract is redeemed on-chain the
  ledger reveals the preimage bytes; the web view's **Scrape Preimage** button
  recovers it from `/api/htlc/status` (`preimage` field), verifies
  `BLAKE3(preimage) == payment_hash`, and unlocks the remaining claim — no
  copy-paste needed. The lock-time ordering that *enforces* atomicity (HTLC-B
  timeout < HTLC-A timeout) is exercised at the protocol layer by
  `tests/htlc_node.rs::{swap_prepare_external_sign_submit_flow, swap_refund_path, swap_e2e_same_chain}`.
- **Timeout is absolute block height** — if the network stalls, Alice's refund
  stays pending until the tip advances past `timeout`.
- **CSV maturity (100 blocks)** applies to coinbase UTXOs before they can fund
  an HTLC.
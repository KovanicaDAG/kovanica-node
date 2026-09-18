#!/usr/bin/env bash
# Atomic-swap HTLC demo over the explorer HTTP API (M1.6).
#
# Everything a browser wallet does is executed here, with the same boundary:
# the node NEVER sees a secret key — the included `htlc-signer` example stands
# in for `signSighash()` in the browser.
#
# Prereqs (from the repo root):
#   cargo build --example htlc-signer --bin kovanica-node
#
# Runs a disposable local node (kovanica explorer on 127.0.0.1:8087,
# KOVANICA_MINE=0 — blocks are mined via /api/mine so the demo is fast and
# deterministic) and drives: fund HTLC-A -> status (locked) -> redeem by the
# recipient -> status (spent, preimage revealed) -> refund path on a second
# contract. Green lights only, exits non-zero on the first failure.

set -euo pipefail

BASE=${BASE:-127.0.0.1:8087}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIGNER="$ROOT/target/debug/examples/htlc-signer"
NODE_BIN="$ROOT/target/debug/kovanica-node"

step() { printf '\n== %s ==\n' "$*"; }

base_url() { echo "http://$BASE"; }
json() { curl -sf -X POST -H 'Content-Type: application/json' -d "$2" "$(base_url)$1"; }
mine() { curl -sf -X POST "$(base_url)/api/mine" >/dev/null; }

cd "$ROOT"

step "start disposable explorer node"
rm -rf /tmp/kovanica-htlc-demo
KOVANICA_DATA=/tmp/kovanica-htlc-demo \
KOVANICA_LISTEN=off KOVANICA_PEERS=off KOVANICA_MINE=0 KOVANICA_FAUCET=0 \
KOVANICA_OPERATOR=1 KOVANICA_ALLOW_RESET=1 \
  "$NODE_BIN" explorer 127.0.0.1:8087 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT

step "wait for the explorer to answer"
for _ in $(seq 1 100); do
  curl -sf "$(base_url)/api/head" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -s "$(base_url)/api/head" | jq -c .

ALICE=$("$SIGNER" addr 1)
BOB=$("$SIGNER" addr 2)
BOB_PK=${BOB:2}   # drop the version byte -> 32-byte recipient public key
PREIMAGE=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
PREIMAGE_HASH=$("$SIGNER" hash "$PREIMAGE")

step "actors"
echo "alice (founder/seed 1): $ALICE"
echo "bob   (seed 2):         $BOB"
echo "preimage:    $PREIMAGE"
echo "preimage_hash (BLAKE3, committed on-chain): $PREIMAGE_HASH"
echo "bob recipient_pk: $BOB_PK"

step "mature the founder coinbase (CSV needs 100 blocks)"
for _ in $(seq 1 104); do mine; done
ALICE_UTXOS=$(curl -sf "$(base_url)/api/utxos?address=$ALICE")
echo "alice utxos after maturity:"
echo "$ALICE_UTXOS" | jq -c .utxos

step "1) /api/htlc/prepare — unsigned HTLC-A funding (50000 atoms locked to Bob)"
TIMEOUT=1000000000
PREP=$(json /api/htlc/prepare "{\"from\":\"$ALICE\",\"amount\":50000,\"recipient_pk\":\"$BOB_PK\",\"preimage_hash\":\"$PREIMAGE_HASH\",\"timeout\":$TIMEOUT}")
echo "$PREP" | jq -c .
TX_HEX=$(echo "$PREP" | jq -r .tx_hex)
SIGHASH=$(echo "$PREP" | jq -r .sighash)
SCRIPT_HEX=$(echo "$PREP" | jq -r .script_hex)
HTLC_ADDR=$(echo "$PREP" | jq -r .htlc_address)

step "2) sign the sighash locally (browser equivalent) + /api/htlc/finalize"
SIG=$("$SIGNER" sign 1 "$SIGHASH")
echo "sig = ${SIG:0:16}…"
SIGNED=$(json /api/htlc/finalize "{\"tx_hex\":\"$TX_HEX\",\"signature_hex\":\"$SIG\"}")
echo "$SIGNED" | jq -c .
SIGNED_TX=$(echo "$SIGNED" | jq -r .signed_tx_hex)

step "3) /api/submit_tx — broadcast the funding"
echo "$(json /api/submit_tx "{\"tx_hex\":\"$SIGNED_TX\"}" | jq -c .) (mined)"

step "4) /api/htlc/status — locked on-chain"
echo "htlc address: $HTLC_ADDR"
json /api/htlc/status "{\"script_hex\":\"$SCRIPT_HEX\"}" | jq -c .
mine

step "5) /api/htlc/spend — unsigned redeem by the recipient (reveals preimage)"
OUTPOINT_TX=$(echo "$PREP" | jq -r .outpoint.tx)
echo "outpoint = $OUTPOINT_TX#$(echo "$PREP" | jq -r .outpoint.index)"
SPEND=$(json /api/htlc/spend "{\"outpoint_tx\":\"$OUTPOINT_TX\",\"outpoint_index\":0,\"script_hex\":\"$SCRIPT_HEX\",\"to\":\"$BOB\",\"kind\":\"redeem\",\"preimage_hex\":\"$PREIMAGE\"}")
echo "$SPEND" | jq -c .
R_TX=$(echo "$SPEND" | jq -r .tx_hex)
R_SIGHASH=$(echo "$SPEND" | jq -r .sighash)

step "6) recipient signs + finalize + submit the redeem"
R_SIG=$("$SIGNER" sign 2 "$R_SIGHASH")
R_SIGNED=$(json /api/htlc/finalize "{\"tx_hex\":\"$R_TX\",\"script_hex\":\"$SCRIPT_HEX\",\"kind\":\"redeem\",\"preimage_hex\":\"$PREIMAGE\",\"signature_hex\":\"$R_SIG\"}")
echo "$R_SIGNED" | jq -c .
echo "$(json /api/submit_tx "{\"tx_hex\":\"$(echo "$R_SIGNED" | jq -r .signed_tx_hex)\"}" | jq -c .) (mined)"

step "7) /api/htlc/status — spent: balance 0, redeem_tx + revealed preimage"
json /api/htlc/status "{\"script_hex\":\"$SCRIPT_HEX\"}" | jq -c .
mine

step "8) refund path on a second contract (sender reclaims after timeout)"
PREP2=$(json /api/htlc/prepare "{\"from\":\"$ALICE\",\"amount\":50000,\"recipient_pk\":\"$BOB_PK\",\"preimage_hash\":\"$PREIMAGE_HASH\",\"timeout\":$TIMEOUT}")
S2=$(echo "$PREP2" | jq -r .sighash)
SIG2=$("$SIGNER" sign 1 "$S2")
SIGNED2=$(json /api/htlc/finalize "{\"tx_hex\":\"$(echo "$PREP2" | jq -r .tx_hex)\",\"signature_hex\":\"$SIG2\"}")
echo "$(json /api/submit_tx "{\"tx_hex\":\"$(echo "$SIGNED2" | jq -r .signed_tx_hex)\"}" | jq -c .) (mined)"
SCRIPT2=$(echo "$PREP2" | jq -r .script_hex)
OUT2=$(echo "$PREP2" | jq -r .outpoint.tx)
REF=$(json /api/htlc/spend "{\"outpoint_tx\":\"$OUT2\",\"outpoint_index\":0,\"script_hex\":\"$SCRIPT2\",\"to\":\"$ALICE\",\"kind\":\"refund\"}")
echo "$REF" | jq -c . 
REF_SIG=$("$SIGNER" sign 1 "$(echo "$REF" | jq -r .sighash)")
REF_SIGNED=$(json /api/htlc/finalize "{\"tx_hex\":\"$(echo "$REF" | jq -r .tx_hex)\",\"script_hex\":\"$SCRIPT2\",\"kind\":\"refund\",\"signature_hex\":\"$REF_SIG\"}")
echo "$(json /api/submit_tx "{\"tx_hex\":\"$(echo "$REF_SIGNED" | jq -r .signed_tx_hex)\"}" | jq -c .) (mined)"

step "9) refunded contract status — balance 0"
json /api/htlc/status "{\"script_hex\":\"$SCRIPT2\"}" | jq -c .

step "DONE — full atomic-swap HTTP cycle verified locally"
kill "$SRV" 2>/dev/null || true
trap - EXIT
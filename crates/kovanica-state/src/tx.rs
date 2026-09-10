//! Transactions: the payload a block carries, and the unit the ledger applies.
//!
//! The ledger follows the **UTXO** model (as GHOSTDAG's reference system, Kaspa,
//! does). A [`Transaction`] consumes existing unspent outputs by reference
//! ([`OutPoint`]) and creates new ones ([`TxOutput`]). Each spend is authorised
//! by an ed25519 signature (see [`crate::keys`]) carried on its [`TxInput`].
//!
//! A transaction with **no inputs** is a *coinbase* (issuance) transaction: it
//! mints new value under the ledger's subsidy/fee rules (see [`crate::ledger`])
//! rather than consuming existing outputs. Its [`Transaction::tag`] should be
//! unique (e.g. the producing block's height/label) so distinct coinbases have
//! distinct ids.
//!
//! ## Canonical encoding
//!
//! Everything is length-prefixed and little-endian so the encoding is
//! unambiguous and identical on every node (mirroring `kovanica_dag::Block`).
//! A block's payload is a length-prefixed list of transactions — see
//! [`encode_block_payload`] / [`decode_block_payload`], which bridge the ledger
//! to `kovanica_dag`'s opaque block payloads.
//!
//! ## Stealth addresses (RFC-003 / 6A)
//!
//! Outputs locked to a `v0x03` stealth address carry a **stealth extension** in the
//! encoding: a 1-byte `stealth_flag` (0 = ordinary, 1 = stealth), followed when set
//! by `R = r·G` (32 bytes), a 1-byte `view_tag` (first byte of `BLAKE3(scan_pk · r)`),
//! and `P = H(r · spend_pk) · G` (32 bytes, the one-time pubkey the ledger verifies
//! spend signatures against). The `owner` of a stealth output is the `v0x03` address
//! (`BLAKE3(scan_pk || spend_pk)`), and `TxOutput::stealth` is `Some(...)`.
//!
//! ## Script v2 (RFC-003 / 3B)
//!
//! Transactions carry `n_lock_time` (BIP-65 CLTV) and `sequence` (BIP-112 CSV) fields.
//! The sighash domain includes these so lock-time-signed transactions are bound to their
//! lock time. Script v2 spends reveal the script in `witness[0]` and execute it with a
//! bounded step budget; see [`crate::script_v2`].

use core::fmt;

use crate::keys::{Address, KeyPair};

/// 32-byte BLAKE3 digest identifying a transaction.
///
/// Ordering is over the raw bytes for deterministic tie-breaks.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Construct a `TxId` from raw bytes (decoding / tests).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes of the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering of the full digest.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A reference to one specific output of a previous transaction: the funding
/// transaction's id plus the output's index within it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OutPoint {
    /// Id of the transaction that created the referenced output.
    pub tx: TxId,
    /// Index of the output within that transaction.
    pub index: u32,
}

impl OutPoint {
    /// Construct an outpoint.
    pub const fn new(tx: TxId, index: u32) -> Self {
        Self { tx, index }
    }
}

/// A raw 64-byte ed25519 signature. Newtyped so it can carry a readable `Debug`
/// (fixed arrays larger than 32 bytes have none) and a clear domain meaning.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig([u8; 64]);

impl Sig {
    /// Wrap raw signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw 64 signature bytes.
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// The all-zero placeholder used before an input is signed.
    pub const fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({}…)", &hex::encode(self.0)[..8])
    }
}

/// A spend: which previous output is being consumed, and the witness stack
/// authorising it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxInput {
    /// The previous output being spent.
    pub outpoint: OutPoint,
    /// Witness stack authorising the spend:
    /// - For Version 0x00 (P2PK): `vec![signature_64_bytes]`.
    /// - For Version 0x01 (P2SH): `vec![redeem_script, sig_1, ..., sig_M]`.
    /// - For Version 0x02 (Script v2): `vec![script_bytes, stack_elem_1, ...]`.
    /// - For Version 0x03 (Stealth): `vec![signature_64_bytes]` (one-time key sign).
    pub witness: Vec<Vec<u8>>,
}

impl TxInput {
    /// Construct a TxInput with an explicit witness stack.
    pub fn new(outpoint: OutPoint, witness: Vec<Vec<u8>>) -> Self {
        Self { outpoint, witness }
    }

    /// Construct a single-signature input (Version 0x00 P2PK or Version 0x03 Stealth):
    /// the witness stack contains exactly one 64-byte Ed25519 signature.
    pub fn single_sig(outpoint: OutPoint, signature: [u8; 64]) -> Self {
        Self {
            outpoint,
            witness: vec![signature.to_vec()],
        }
    }

    /// Construct a multisig input (Version 0x01 P2SH):
    /// the witness stack contains the raw redeem script followed by M signatures.
    pub fn multisig(outpoint: OutPoint, redeem_script: Vec<u8>, signatures: Vec<Vec<u8>>) -> Self {
        let mut witness = Vec::with_capacity(1 + signatures.len());
        witness.push(redeem_script);
        witness.extend(signatures);
        Self { outpoint, witness }
    }

    /// Number of elements in the witness stack.
    pub fn witness_len(&self) -> usize {
        self.witness.len()
    }

    /// Whether the witness stack is empty.
    pub fn is_empty_witness(&self) -> bool {
        self.witness.is_empty()
    }
}

/// A 32-byte BLAKE3 digest identifying an asset definition.
///
/// The native KVNC asset is represented by `None` (or `AssetId::native()`).
/// All other assets carry their definition hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AssetId([u8; 32]);

impl AssetId {
    /// Construct an `AssetId` from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes of the asset id.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The native KVNC asset id (all zeros).
    pub const fn native() -> Self {
        Self([0u8; 32])
    }

    /// Whether this is the native KVNC asset.
    pub fn is_native(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Lowercase hex rendering.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The one-time key material that accompanies a stealth output (Version 0x03).
///
/// Present only on stealth outputs (`TxOutput::stealth` is `Some`). The `owner` of a
/// stealth output is the `v0x03` address; these fields are the on-chain ephemeral data
/// the sender publishes so the recipient can detect and spend the output.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StealthExt {
    /// `R = r·G`: the sender's ephemeral public key (32 bytes).
    pub r: [u8; 32],
    /// View tag: first byte of `BLAKE3(scan_pk · r)`, for SPV filtering.
    pub view_tag: u8,
    /// `P = H(r · spend_pk) · G`: the one-time public key the ledger verifies spends against.
    pub p: [u8; 32],
}

/// A newly created output: an amount, an optional asset id, and the address that may later spend it.
///
/// For stealth outputs (version 0x03), the output carries additional one-time key material
/// (`R`, `view_tag`, `P`) — the `stealth` field. The `owner` of a stealth output is a v0x03
/// address (BLAKE3(scan_pk || spend_pk)); the on-chain spend authorisation uses the derived
/// one-time public key `P`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxOutput {
    /// The value locked in this output.
    pub value: u64,
    /// The asset this output locks. `None` = native KVNC.
    pub asset_id: Option<AssetId>,
    /// The address that owns (may spend) this output.
    pub owner: Address,
    /// The stealth extension for v0x03 outputs. `None` for ordinary outputs.
    pub stealth: Option<StealthExt>,
}

impl TxOutput {
    /// Construct an output with an explicit asset id.
    pub const fn new(value: u64, asset_id: Option<AssetId>, owner: Address) -> Self {
        Self {
            value,
            asset_id,
            owner,
            stealth: None,
        }
    }

    /// Construct a native KVNC output (asset_id = None).
    pub const fn native(value: u64, owner: Address) -> Self {
        Self {
            value,
            asset_id: None,
            owner,
            stealth: None,
        }
    }

    /// Construct a stealth output with the given one-time key material.
    ///
    /// `owner` must be a `v0x03` address (the recipient's stealth address).
    /// `r` is the sender's ephemeral pubkey, `view_tag` the filter byte, `p` the
    /// derived one-time pubkey the recipient verifies spends against.
    pub fn stealth(value: u64, owner: Address, stealth: StealthExt) -> Self {
        Self {
            value,
            asset_id: None,
            owner,
            stealth: Some(stealth),
        }
    }

    /// Construct an output with an explicit asset id and stealth extension.
    pub fn new_with_stealth(
        value: u64,
        asset_id: Option<AssetId>,
        owner: Address,
        stealth: StealthExt,
    ) -> Self {
        Self {
            value,
            asset_id,
            owner,
            stealth: Some(stealth),
        }
    }

    /// Whether this output carries the stealth extension.
    pub const fn is_stealth(&self) -> bool {
        self.stealth.is_some()
    }

    /// The stealth extension, or a default (all-zero) when absent.
    pub fn stealth_or_default(&self) -> StealthExt {
        self.stealth.unwrap_or_default()
    }
}

/// A transaction: it spends the outputs named by `inputs` and creates `outputs`.
///
/// An empty `inputs` marks a coinbase (issuance) transaction. `tag` is extra
/// committed bytes — for a coinbase it also disambiguates the id (see the module
/// docs) and can carry the producing block's height/label.
///
/// Transactions carry optional `n_lock_time` and `sequence` fields used by
/// script v2 opcodes CHECKLOCKTIMEVERIFY (BIP-65) and CHECKSEQUENCEVERIFY (BIP-112).
/// The sighash domain includes these so that lock-time-signed transactions are
/// bound to their lock time.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    tag: Vec<u8>,
    /// Lock time (BIP-65): a 32-bit value that, when non-zero, constrains when
    /// the transaction can be included. Used by CHECKLOCKTIMEVERIFY.
    n_lock_time: u32,
    /// Sequence number (BIP-112): a 32-bit value. When non-zero, CHECKSEQUENCEVERIFY
    /// constrains the relative lock time. The sighash covers it.
    sequence: u32,
}

impl Transaction {
    /// Construct a transaction with explicit inputs, outputs, and tag.
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        Self {
            inputs,
            outputs,
            tag,
            n_lock_time: 0,
            sequence: 0,
        }
    }

    /// Construct a transaction with explicit lock time and sequence.
    pub fn new_with_lock(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        tag: Vec<u8>,
        n_lock_time: u32,
        sequence: u32,
    ) -> Self {
        Self {
            inputs,
            outputs,
            tag,
            n_lock_time,
            sequence,
        }
    }

    /// A coinbase (issuance) transaction: no inputs, the given outputs and tag.
    ///
    /// The `tag` should be unique per coinbase (e.g. the block height/label) so
    /// two coinbases do not collide on id.
    pub fn coinbase(outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        Self {
            inputs: Vec::new(),
            outputs,
            tag,
            n_lock_time: 0,
            sequence: 0,
        }
    }

    /// Build a signed transaction spending `spends` (each an outpoint plus the
    /// keypair that owns it) to produce `outputs`.
    ///
    /// Single-sig spenders receive a 1-element witness stack `[sig_bytes]`.
    pub fn signed(spends: &[(OutPoint, &KeyPair)], outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        let inputs = spends
            .iter()
            .map(|(outpoint, _)| TxInput {
                outpoint: *outpoint,
                witness: Vec::new(),
            })
            .collect();
        let mut tx = Self {
            inputs,
            outputs,
            tag,
            n_lock_time: 0,
            sequence: 0,
        };
        let sighash = tx.sighash();
        for (i, (_, keypair)) in spends.iter().enumerate() {
            tx.inputs[i].witness = vec![keypair.sign(&sighash).to_vec()];
        }
        tx
    }

    /// Build a signed multisig transaction spending `outpoint` locked to `redeem_script`
    /// with signatures produced by `signers`.
    pub fn signed_multisig(
        outpoint: OutPoint,
        redeem_script: Vec<u8>,
        signers: &[&KeyPair],
        outputs: Vec<TxOutput>,
        tag: Vec<u8>,
    ) -> Self {
        let input = TxInput {
            outpoint,
            witness: Vec::new(),
        };
        let mut tx = Self {
            inputs: vec![input],
            outputs,
            tag,
            n_lock_time: 0,
            sequence: 0,
        };
        let sighash = tx.sighash();
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(signer.sign(&sighash).to_vec());
        }
        tx.inputs[0] = TxInput::multisig(outpoint, redeem_script, signatures);
        tx
    }

    /// An unsigned spend: witness stacks are empty. The wallet signs
    /// [`sighash`](Self::sighash) and attaches the result with
    /// [`attach_signature`](Self::attach_signature) or [`attach_witness`](Self::attach_witness).
    pub fn unsigned(outpoints: &[OutPoint], outputs: Vec<TxOutput>, tag: Vec<u8>) -> Self {
        Self {
            inputs: outpoints
                .iter()
                .map(|outpoint| TxInput {
                    outpoint: *outpoint,
                    witness: Vec::new(),
                })
                .collect(),
            outputs,
            tag,
            n_lock_time: 0,
            sequence: 0,
        }
    }

    /// Attach a single signature to input `index` (as a 1-item witness).
    pub fn attach_signature(&mut self, index: usize, signature: Sig) {
        if let Some(input) = self.inputs.get_mut(index) {
            input.witness = vec![signature.to_bytes().to_vec()];
        }
    }

    /// Attach a full witness stack to input `index`.
    pub fn attach_witness(&mut self, index: usize, witness: Vec<Vec<u8>>) {
        if let Some(input) = self.inputs.get_mut(index) {
            input.witness = witness;
        }
    }

    /// The transaction's inputs (empty for a coinbase).
    pub fn inputs(&self) -> &[TxInput] {
        &self.inputs
    }

    /// Mutable access to the transaction's inputs.
    pub fn inputs_mut(&mut self) -> &mut [TxInput] {
        &mut self.inputs
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    /// The transaction's tag bytes.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// The transaction's lock time (BIP-65).
    pub fn n_lock_time(&self) -> u32 {
        self.n_lock_time
    }

    /// The transaction's sequence number (BIP-112).
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Whether this is a coinbase (issuance) transaction — it has no inputs.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Compute the transaction fee from the current UTXO set.
    ///
    /// Returns `Some(input_sum - output_sum)` for a non-coinbase transaction
    /// when every input outpoint exists in `utxo`. Returns `Some(0)` for a
    /// coinbase. Returns `None` if any spent outpoint is missing from `utxo`.
    pub fn fee_with_utxo(&self, utxo: &crate::UtxoSet) -> Option<u64> {
        if self.is_coinbase() {
            return Some(0);
        }
        let mut input_sum = 0u64;
        for input in &self.inputs {
            let out = utxo.get(&input.outpoint)?;
            input_sum = input_sum.checked_add(out.value)?;
        }
        let output_sum: u64 = self.outputs.iter().map(|o| o.value).sum();
        Some(input_sum.saturating_sub(output_sum))
    }

    /// Fee rate in atoms per byte, or `None` if the fee cannot be computed.
    pub fn fee_rate_with_utxo(&self, utxo: &crate::UtxoSet) -> Option<u64> {
        let fee = self.fee_with_utxo(utxo)?;
        let size = self.encode().len();
        if size == 0 {
            return Some(0);
        }
        Some(fee / size as u64)
    }

    /// Serialise into `buf`.
    /// - With `with_signatures = true`: includes dynamic witness items (used for `id()` and block payload).
    /// - With `with_signatures = false`: completely omits witness vectors (used for `sighash()`).
    ///
    /// After the RFC-002 fields, each output writes a `stealth_flag` byte (0 = ordinary,
    /// 1 = stealth) followed by the 65-byte stealth extension (`R` 32B + `view_tag` 1B + `P`
    /// 32B) when present. After the outputs, the `n_lock_time` and `sequence` fields are
    /// written (8 bytes total), followed by the tag.
    fn encode_into(&self, buf: &mut Vec<u8>, with_signatures: bool) {
        buf.extend_from_slice(&(self.inputs.len() as u64).to_le_bytes());
        for input in &self.inputs {
            buf.extend_from_slice(input.outpoint.tx.as_bytes());
            buf.extend_from_slice(&input.outpoint.index.to_le_bytes());
            if with_signatures {
                buf.extend_from_slice(&(input.witness.len() as u64).to_le_bytes());
                for item in &input.witness {
                    buf.extend_from_slice(&(item.len() as u64).to_le_bytes());
                    buf.extend_from_slice(item);
                }
            }
        }
        buf.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            // asset_id: 1 byte flag (0 = None/native, 1 = Some) + 32 bytes if Some
            match output.asset_id {
                None => buf.push(0),
                Some(asset_id) => {
                    buf.push(1);
                    buf.extend_from_slice(asset_id.as_bytes());
                }
            }
            // stealth flag: 1 byte (0 = ordinary, 1 = stealth)
            if let Some(s) = output.stealth {
                buf.push(1);
                buf.extend_from_slice(&s.r);
                buf.push(s.view_tag);
                buf.extend_from_slice(&s.p);
            } else {
                buf.push(0);
            }
            buf.extend_from_slice(output.owner.as_bytes());
        }
        // n_lock_time (4 bytes) + sequence (4 bytes)
        buf.extend_from_slice(&self.n_lock_time.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&(self.tag.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.tag);
    }

    /// The canonical byte encoding (including signatures / witness).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf, true);
        buf
    }

    /// The signature hash: BLAKE3 over the witness-free encoding. Inputs sign
    /// this, and it is what [`crate::keys::verify`] checks each spend against.
    /// The sighash domain includes `n_lock_time` and `sequence` so signatures
    /// cover the lock time / sequence (BIP-65 / BIP-112 semantics).
    pub fn sighash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        self.encode_into(&mut buf, false);
        *blake3::hash(&buf).as_bytes()
    }

    /// The transaction id: BLAKE3 over the full (signed) encoding.
    pub fn id(&self) -> TxId {
        TxId(*blake3::hash(&self.encode()).as_bytes())
    }

    /// Decode a single transaction from its canonical byte encoding.
    ///
    /// This is the inverse of [`Transaction::encode`] and is used by the
    /// mobile FFI to round-trip a transaction "blob" (e.g. a partially-signed
    /// multisig spend) without wrapping it in a block payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let tx = reader.read_transaction()?;
        if reader.remaining() != 0 {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(tx)
    }
}

/// Errors from decoding a block payload back into transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended before a fully-formed value could be read.
    UnexpectedEof,
    /// Bytes remained after decoding the declared number of transactions.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEof => f.write_str("unexpected end of payload"),
            DecodeError::TrailingBytes => f.write_str("trailing bytes after payload"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode a list of transactions as a block payload: a length prefix followed by
/// each transaction's canonical encoding. Feed the result to
/// `kovanica_dag::Block`'s opaque `payload`.
pub fn encode_block_payload(txs: &[Transaction]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(txs.len() as u64).to_le_bytes());
    for tx in txs {
        tx.encode_into(&mut buf, true);
    }
    buf
}

/// Decode a block payload produced by [`encode_block_payload`].
pub fn decode_block_payload(bytes: &[u8]) -> Result<Vec<Transaction>, DecodeError> {
    let mut reader = Reader::new(bytes);
    // Smallest transaction encoding: inputs(8) + outputs(8) + n_lock_time+sequence(8)
    // = 24 bytes for an empty transaction.
    let count = reader.read_count(24)?;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        txs.push(reader.read_transaction()?);
    }
    if reader.remaining() != 0 {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(txs)
}

/// A minimal, bounds-checked cursor over the payload bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        if self.remaining() < N {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Read a length prefix, rejecting counts that cannot fit even at
    /// `min_element_bytes` each — so malformed input can't request a giant
    /// allocation before the bytes run out.
    fn read_count(&mut self, min_element_bytes: usize) -> Result<usize, DecodeError> {
        let n = self.read_u64()? as usize;
        if min_element_bytes > 0 && n > self.remaining() / min_element_bytes {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok(n)
    }

    fn read_transaction(&mut self) -> Result<Transaction, DecodeError> {
        // Minimum input size: 32 (tx) + 4 (index) + 8 (witness count) = 44 bytes.
        let n_inputs = self.read_count(44)?;
        let mut inputs = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let tx = TxId::from_bytes(self.read_array::<32>()?);
            let index = self.read_u32()?;
            // Minimum witness item size: 8 bytes length prefix.
            let n_witness = self.read_count(8)?;
            let mut witness = Vec::with_capacity(n_witness);
            for _ in 0..n_witness {
                let item_len = self.read_count(1)?;
                let item = self.read_array_dyn(item_len)?;
                witness.push(item);
            }
            inputs.push(TxInput {
                outpoint: OutPoint { tx, index },
                witness,
            });
        }
        // Minimum output size: 8 (value) + 1 (asset flag) + 1 (stealth flag)
        //    + 33 (owner) = 43 bytes for an ordinary native output.
        // When stealth flag is 1, add 65 bytes for the stealth extension.
        // When asset flag is 1, add 32 bytes for asset_id.
        let n_outputs = self.read_count(43)?;
        let mut outputs = Vec::with_capacity(n_outputs);
        for _ in 0..n_outputs {
            let value = self.read_u64()?;
            let asset_flag = self.read_array::<1>()?[0];
            let asset_id = if asset_flag == 0 {
                None
            } else {
                Some(AssetId::from_bytes(self.read_array::<32>()?))
            };
            // stealth_flag: 1 byte (0 = ordinary, 1 = stealth)
            let stealth_flag = self.read_array::<1>()?[0];
            let stealth = if stealth_flag == 1 {
                let r = self.read_array::<32>()?;
                let view_tag = self.read_array::<1>()?[0];
                let p = self.read_array::<32>()?;
                Some(StealthExt { r, view_tag, p })
            } else {
                None
            };
            let owner_bytes = self.read_array::<33>()?;
            let owner = Address::from_versioned_bytes(owner_bytes);
            outputs.push(TxOutput {
                value,
                asset_id,
                owner,
                stealth,
            });
        }
        // n_lock_time (4 bytes) + sequence (4 bytes)
        let n_lock_time = self.read_u32()?;
        let sequence = self.read_u32()?;
        let tag_len = self.read_count(1)?;
        let tag = self.read_array_dyn(tag_len)?;
        Ok(Transaction {
            inputs,
            outputs,
            tag,
            n_lock_time,
            sequence,
        })
    }

    fn read_array_dyn(&mut self, len: usize) -> Result<Vec<u8>, DecodeError> {
        if self.remaining() < len {
            return Err(DecodeError::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u64) -> Address {
        KeyPair::from_u64(seed).address()
    }

    #[test]
    fn id_and_sighash_are_deterministic() {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([9u8; 32]), 0);
        let tx = Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::native(5, addr(2))],
            b"t".to_vec(),
        );
        assert_eq!(tx.id(), tx.id());
        assert_eq!(tx.sighash(), tx.sighash());
    }

    #[test]
    fn sighash_ignores_signatures() {
        // Two transactions identical but for their signatures must share a
        // sighash (signatures sign the sighash, not vice-versa) yet differ in id.
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let a = Transaction::signed(&[(op, &KeyPair::from_u64(1))], vec![], b"x".to_vec());
        // Re-sign the same logical spend with a different key: same sighash input.
        let b = Transaction::signed(&[(op, &KeyPair::from_u64(2))], vec![], b"x".to_vec());
        assert_eq!(a.sighash(), b.sighash());
    }

    #[test]
    fn sighash_ignores_multisig_witness() {
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let kp1 = KeyPair::from_u64(10);
        let kp2 = KeyPair::from_u64(20);
        let script = vec![2u8, 2u8, 1, 2, 3];
        let outputs = vec![TxOutput::native(50, addr(3))];

        let tx1 = Transaction::signed_multisig(
            op,
            script.clone(),
            &[&kp1],
            outputs.clone(),
            b"m".to_vec(),
        );
        let tx2 = Transaction::signed_multisig(op, script.clone(), &[&kp2], outputs, b"m".to_vec());

        assert_eq!(tx1.sighash(), tx2.sighash());
        assert_ne!(tx1.id(), tx2.id());
    }

    #[test]
    fn payload_roundtrips() {
        let kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([7u8; 32]), 3);
        let coinbase = Transaction::coinbase(vec![TxOutput::native(50, addr(1))], b"h0".to_vec());
        let transfer = Transaction::signed(
            &[(op, &kp)],
            vec![TxOutput::native(20, addr(2)), TxOutput::native(30, addr(3))],
            Vec::new(),
        );
        let txs = vec![coinbase, transfer];
        let bytes = encode_block_payload(&txs);
        assert_eq!(decode_block_payload(&bytes).unwrap(), txs);
    }

    #[test]
    fn multisig_payload_roundtrips() {
        let kp1 = KeyPair::from_u64(1);
        let kp2 = KeyPair::from_u64(2);
        let op = OutPoint::new(TxId::from_bytes([7u8; 32]), 3);
        let script = vec![2u8, 2u8, 1, 2, 3];
        let multisig_tx = Transaction::signed_multisig(
            op,
            script,
            &[&kp1, &kp2],
            vec![TxOutput::native(100, Address::p2sh([0x33u8; 32]))],
            b"tag".to_vec(),
        );
        let bytes = encode_block_payload(std::slice::from_ref(&multisig_tx));
        let decoded = decode_block_payload(&bytes).unwrap();
        assert_eq!(decoded, vec![multisig_tx]);
    }

    #[test]
    fn empty_payload_roundtrips() {
        let bytes = encode_block_payload(&[]);
        assert_eq!(
            decode_block_payload(&bytes).unwrap(),
            Vec::<Transaction>::new()
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let kp = KeyPair::from_u64(1);
        let tx = Transaction::signed(
            &[(OutPoint::new(TxId::from_bytes([1u8; 32]), 0), &kp)],
            vec![TxOutput::native(5, addr(2))],
            Vec::new(),
        );
        let mut bytes = tx.encode();
        bytes.push(0xFF);
        assert!(Transaction::decode(&bytes).is_err());
    }

    #[test]
    fn lock_time_and_sequence_roundtrip() {
        let _kp = KeyPair::from_u64(1);
        let op = OutPoint::new(TxId::from_bytes([7u8; 32]), 3);
        let tx = Transaction::new_with_lock(
            vec![TxInput::single_sig(
                op,
                KeyPair::from_u64(1).sign(b"locktest"),
            )],
            vec![TxOutput::native(5, addr(2))],
            b"tag".to_vec(),
            500_000,
            1,
        );
        let bytes = encode_block_payload(&[tx]);
        let decoded = decode_block_payload(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].n_lock_time(), 500_000);
        assert_eq!(decoded[0].sequence(), 1);
    }

    #[test]
    fn sighash_covers_lock_time() {
        let op = OutPoint::new(TxId::from_bytes([1u8; 32]), 0);
        let tx_a = Transaction::new_with_lock(
            vec![TxInput::single_sig(op, [0u8; 64])],
            vec![],
            b"t".to_vec(),
            100,
            0,
        );
        let tx_b = Transaction::new_with_lock(
            vec![TxInput::single_sig(op, [0u8; 64])],
            vec![],
            b"t".to_vec(),
            200,
            0,
        );
        assert_ne!(tx_a.sighash(), tx_b.sighash());
    }

    #[test]
    fn stealth_output_encode_decode_roundtrip() {
        let scan_pk = [0xAAu8; 32];
        let spend_pk = [0xBBu8; 32];
        let stealth_addr = Address::stealth(scan_pk, spend_pk);
        let r = [0x11u8; 32];
        let view_tag = 0x42;
        let p = [0x22u8; 32];
        let stealth = StealthExt { r, view_tag, p };
        let output = TxOutput::stealth(100, stealth_addr, stealth);
        // Build a minimal tx containing just this output as a coinbase
        let tx = Transaction::coinbase(vec![output], b"stealth".to_vec());
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        assert_eq!(decoded.outputs().len(), 1);
        let out = decoded.outputs()[0];
        assert!(out.is_stealth());
        assert_eq!(out.value, 100);
        assert_eq!(out.owner, stealth_addr);
        let ext = out.stealth.unwrap();
        assert_eq!(ext.r, r);
        assert_eq!(ext.view_tag, view_tag);
        assert_eq!(ext.p, p);
    }

    #[test]
    fn stealth_output_with_asset_roundtrip() {
        let scan_pk = [0xCCu8; 32];
        let spend_pk = [0xDDu8; 32];
        let stealth_addr = Address::stealth(scan_pk, spend_pk);
        let asset_id = AssetId::from_bytes([0xEEu8; 32]);
        let r = [0x33u8; 32];
        let view_tag = 0x77;
        let p = [0x44u8; 32];
        let stealth = StealthExt { r, view_tag, p };
        let output = TxOutput::new_with_stealth(200, Some(asset_id), stealth_addr, stealth);
        let tx = Transaction::coinbase(vec![output], b"stealth-asset".to_vec());
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        let out = decoded.outputs()[0];
        assert!(out.is_stealth());
        assert_eq!(out.asset_id, Some(asset_id));
        let ext = out.stealth.unwrap();
        assert_eq!(ext.r, r);
        assert_eq!(ext.view_tag, view_tag);
        assert_eq!(ext.p, p);
    }

    #[test]
    fn ordinary_output_no_stealth_flag() {
        let kp = KeyPair::from_u64(1);
        let tx = Transaction::coinbase(vec![TxOutput::native(50, kp.address())], b"h".to_vec());
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        assert!(!decoded.outputs()[0].is_stealth());
    }

    #[test]
    fn stealth_flag_mismatch_rejected_decode() {
        // Hand-build a bytes blob where stealth_flag = 1 but no extension follows
        // (malformed). The decoder should return UnexpectedEof.
        let mut bytes = Vec::new();
        // 0 inputs
        bytes.extend_from_slice(&0u64.to_le_bytes());
        // 1 output: value=10, asset_flag=0, stealth_flag=1, then truncated
        bytes.extend_from_slice(&10u64.to_le_bytes());
        bytes.push(0); // asset_flag = native
        bytes.push(1); // stealth_flag = 1 (stealth), but no R/view_tag/P follows
        bytes.extend_from_slice(&([0x55u8; 32])); // owner (P2PK for simplicity)
        let result = Transaction::decode(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn coinbase_with_stealth_and_lock_time() {
        let scan_pk = [0x01u8; 32];
        let spend_pk = [0x02u8; 32];
        let stealth_addr = Address::stealth(scan_pk, spend_pk);
        let stealth = StealthExt {
            r: [0x03u8; 32],
            view_tag: 0x04,
            p: [0x05u8; 32],
        };
        let tx = Transaction::new_with_lock(
            Vec::new(),
            vec![TxOutput::stealth(1000, stealth_addr, stealth)],
            b"cb".to_vec(),
            1000,
            0,
        );
        // coinbase with lock_time
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        assert!(decoded.is_coinbase());
        assert_eq!(decoded.outputs().len(), 1);
        assert!(decoded.outputs()[0].is_stealth());
        assert_eq!(decoded.n_lock_time(), 1000);
    }

    #[test]
    fn txid_differs_with_stealth_output() {
        let scan_pk = [0x01u8; 32];
        let spend_pk = [0x02u8; 32];
        let stealth_addr = Address::stealth(scan_pk, spend_pk);
        let stealth_a = StealthExt {
            r: [0x11u8; 32],
            view_tag: 0x01,
            p: [0x22u8; 32],
        };
        let stealth_b = StealthExt {
            r: [0x33u8; 32],
            view_tag: 0x02,
            p: [0x44u8; 32],
        };
        let tx_a = Transaction::coinbase(
            vec![TxOutput::stealth(100, stealth_addr, stealth_a)],
            b"t".to_vec(),
        );
        let tx_b = Transaction::coinbase(
            vec![TxOutput::stealth(100, stealth_addr, stealth_b)],
            b"t".to_vec(),
        );
        assert_ne!(tx_a.id(), tx_b.id());
    }

    #[test]
    fn sighash_differs_with_stealth_output() {
        // Two identical transactions except for the stealth R value should have
        // different sighashes (the stealth extension is part of the encoding).
        let scan_pk = [0x11u8; 32];
        let spend_pk = [0x22u8; 32];
        let stealth_addr = Address::stealth(scan_pk, spend_pk);
        let stealth_a = StealthExt {
            r: [0xAAu8; 32],
            view_tag: 0x01,
            p: [0xBBu8; 32],
        };
        let stealth_b = StealthExt {
            r: [0xCCu8; 32],
            view_tag: 0x02,
            p: [0xBBu8; 32],
        };
        let tx_a = Transaction::coinbase(
            vec![TxOutput::stealth(100, stealth_addr, stealth_a)],
            b"t".to_vec(),
        );
        let tx_b = Transaction::coinbase(
            vec![TxOutput::stealth(100, stealth_addr, stealth_b)],
            b"t".to_vec(),
        );
        assert_ne!(tx_a.sighash(), tx_b.sighash());
    }
}

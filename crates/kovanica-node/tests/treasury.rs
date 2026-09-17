//! RFC-006 §5 treasury vesting test suite.
//!
//! Tests the genesis treasury vesting via RFC-005 vault composition: the
//! genesis coinbase emits the founder premine plus `tranches` vault outputs,
//! each locking `tranche_amount` behind an absolute-time vault.  Tranche k
//! (1-based) unlocks at height `k × tranche_interval`.
//!
//! Reference protocol: RFC-005 vault composition — the treasury is pure
//! composition of existing primitives (no new consensus rules).  The RFC-005
//! vault template (`unlock_height u32 LE || csv u32 LE || owner_pk 32B`) is
//! used with `csv = 0` (disabled).  Only the owner key may spend once the
//! absolute lock expires.

use kovanica_node::{Node, TreasuryGenesis};
use kovanica_state::vault::VaultScript;
use kovanica_state::{
    placeholder_treasury_key, Address, HalvingSchedule, KeyPair, Ledger, LedgerError,
    LedgerInsertError, OutPoint, Transaction, TxOutput, BLOCKS_PER_YEAR, DEFAULT_HALVING_ERA,
    RFC006_PREMINE, RFC006_TREASURY_TRANCHE, RFC006_TREASURY_TRANCHES,
};

/// One KVNC in atoms.
const K: u16 = 3;

/// The live kovanica-testnet genesis block id (RFC-006, placeholder treasury).
/// Verified against `GET https://explorer.kovanica.online/api/head` — the
/// placeholder derivation MUST reproduce this hash exactly (no testnet reset).
const LIVE_TESTNET_GENESIS: &str =
    "9565fc20cb465eec0198a65c07da6b825e4211c4060d581a2c7dac6c96bafc97";

// ---------------------------------------------------------------------------
// 1. Genesis with treasury emits premine + 10 vault tranches
// ---------------------------------------------------------------------------

#[test]
fn genesis_with_treasury_emits_premine_and_vault_tranches() {
    let founder_kp = KeyPair::from_u64(1);

    let mut node = Node::new();
    // Treasury inclusion is explicit: `Some(TreasuryGenesis::placeholder())`
    // opts the genesis coinbase into the RFC-006 premine + treasury vaults.
    let (genesis_id, founder) = node
        .genesis(
            K,
            100,
            RFC006_PREMINE,
            1,
            Some(TreasuryGenesis::placeholder()),
        )
        .expect("genesis with treasury");

    assert_eq!(founder, founder_kp.address());

    // Founder has the premine.
    assert_eq!(node.balance(&founder).unwrap(), u128::from(RFC006_PREMINE));

    // Each tranche is locked in a vault; verify balances and script shape.
    let mut total_vault_value: u64 = 0;
    for k in 1..=RFC006_TREASURY_TRANCHES {
        let owner_pk = placeholder_treasury_key(k);
        let unlock_height = k.saturating_mul(BLOCKS_PER_YEAR);
        let script = VaultScript::new(unlock_height, 0, owner_pk).expect("valid vault");
        assert_eq!(
            script.unlock_height(),
            unlock_height,
            "tranche {k} must unlock at k × BLOCKS_PER_YEAR"
        );
        assert_eq!(script.csv(), 0, "treasury vaults are pure CLTV");
        assert_eq!(script.owner_pk(), &owner_pk);
        let vault_balance = node.balance_of_vault(&script);
        assert_eq!(
            vault_balance, RFC006_TREASURY_TRANCHE,
            "tranche {k} must hold {RFC006_TREASURY_TRANCHE}"
        );
        total_vault_value += vault_balance;
    }

    // Total minted = premine + tranches × tranche_amount.
    let supply = u128::from(RFC006_PREMINE) + u128::from(total_vault_value);
    let expected_minted = u128::from(RFC006_PREMINE)
        + u128::from(RFC006_TREASURY_TRANCHE) * u128::from(RFC006_TREASURY_TRANCHES);
    assert_eq!(
        supply, expected_minted,
        "total supply must equal premine + tranches"
    );

    assert_ne!(genesis_id, kovanica_dag::BlockId::from_bytes([0u8; 32]));
}

// ---------------------------------------------------------------------------
// 2. Tranche release boundaries (ledger-level, small unlock height)
// ---------------------------------------------------------------------------

/// Helper: create a ledger with a single vault tranche at `unlock_height`,
/// returning the ledger, vault outpoint, vault script, and owner keypair.
fn treasury_vault_at(unlock_height: u32) -> (Ledger, OutPoint, VaultScript, KeyPair) {
    let owner_kp = KeyPair::from_u64(9999);
    let script =
        VaultScript::new(unlock_height, 0, *owner_kp.address().payload()).expect("valid vault");

    let coinbase = Transaction::coinbase(
        vec![
            TxOutput::native(100, KeyPair::from_u64(1).address()),
            TxOutput::native(500, script.address()),
        ],
        b"genesis".to_vec(),
    );
    let vault_coin = OutPoint::new(coinbase.id(), 1);
    let schedule = HalvingSchedule::new(1_000, DEFAULT_HALVING_ERA);
    let ledger = Ledger::new(K, schedule, &[coinbase]).expect("genesis");
    (ledger, vault_coin, script, owner_kp)
}

/// Extend a ledger by `n` empty blocks.
fn extend_chain(ledger: &mut Ledger, n: u64) {
    for _ in 0..n {
        ledger
            .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[])
            .unwrap();
    }
}

/// Build a vault spend (owner signature): witness = [template, owner_sig].
fn build_vault_spend(
    outpoint: OutPoint,
    script: &VaultScript,
    owner_kp: &KeyPair,
    to: Address,
) -> Transaction {
    let inputs = vec![TxInput::new(outpoint, Vec::new())];
    let outputs = vec![TxOutput::native(499, to)];
    let mut tx = Transaction::new(inputs, outputs, b"vault".to_vec());
    let sighash = tx.sighash();
    let sig = owner_kp.sign(&sighash);
    tx.inputs_mut()[0].witness = script.spend_witness(sig);
    tx
}

use kovanica_state::TxInput;

#[test]
fn tranche_not_spendable_one_before_unlock_height() {
    // unlock_height = 100: at block height 99 (one before), spend is rejected.
    let (mut ledger, vault_coin, script, owner_kp) = treasury_vault_at(100);
    extend_chain(&mut ledger, 98); // tip height = 98

    let spend = build_vault_spend(vault_coin, &script, &owner_kp, owner_kp.address());
    let err = ledger
        .insert(
            vec![ledger.dag().selected_tip()],
            1,
            0,
            0,
            std::slice::from_ref(&spend),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            LedgerInsertError::State(LedgerError::VaultAbsoluteNotReached { .. })
        ),
        "tranche must NOT be spendable one before unlock_height: got {err:?}"
    );
}

#[test]
fn tranche_spendable_at_unlock_height() {
    // unlock_height = 100: at block height 100 (the boundary), spend succeeds.
    let (mut ledger, vault_coin, script, owner_kp) = treasury_vault_at(100);
    extend_chain(&mut ledger, 99); // tip height = 99

    let spend = build_vault_spend(vault_coin, &script, &owner_kp, owner_kp.address());
    ledger
        .insert(vec![ledger.dag().selected_tip()], 1, 0, 0, &[spend])
        .expect("tranche must be spendable at unlock_height");

    let utxo = ledger.state(&ledger.dag().selected_tip()).unwrap();
    assert_eq!(utxo.balance(&owner_kp.address()), 499);
    assert_eq!(utxo.balance(&script.address()), 0);
}

// ---------------------------------------------------------------------------
// 3. Treasury keys + vault script shape
// ---------------------------------------------------------------------------

#[test]
fn treasury_keys_are_deterministic_placeholders() {
    for k in 1..=RFC006_TREASURY_TRANCHES {
        let pk1 = placeholder_treasury_key(k);
        let pk2 = placeholder_treasury_key(k);
        assert_eq!(pk1, pk2, "key must be deterministic for tranche {k}");
        assert_ne!(pk1, [0u8; 32], "key must not be zero for tranche {k}");
        // The placeholder derivation is the OLD pre-Phase-1 formula:
        // KeyPair::from_u64(0x7E45_0000 + k) — publicly derivable by design
        // (TESTNET-ONLY). This is what keeps the live testnet genesis stable.
        let expected = *KeyPair::from_u64(u64::from(0x7E45_0000u32 + k))
            .address()
            .payload();
        assert_eq!(
            pk1, expected,
            "placeholder key for tranche {k} must use the legacy derivation"
        );
    }
    // All tranche keys must differ.
    let keys: Vec<[u8; 32]> = (1..=RFC006_TREASURY_TRANCHES)
        .map(placeholder_treasury_key)
        .collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "tranches {}/{} must differ", i + 1, j + 1);
        }
    }
}

/// The placeholder-treasury genesis MUST reproduce the live testnet genesis
/// hash (9565fc20…) — the whole point of keeping the OLD placeholder
/// derivation. A divergence here means a testnet reset.
#[test]
fn genesis_with_placeholder_treasury_matches_live_testnet_genesis() {
    let mut node = Node::new();
    let (genesis_id, _founder) = node
        .genesis(
            K,
            10 * 100_000_000, // RFC-006 genesis subsidy (10 KVNC)
            RFC006_PREMINE,
            1, // live founder seed
            Some(TreasuryGenesis::placeholder()),
        )
        .expect("genesis with treasury");
    assert_eq!(
        genesis_id.to_hex(),
        LIVE_TESTNET_GENESIS,
        "placeholder-treasury genesis must equal the live testnet genesis"
    );
}

#[test]
fn tranche_vault_scripts_have_correct_unlock_heights() {
    for k in 1..=RFC006_TREASURY_TRANCHES {
        let owner_pk = placeholder_treasury_key(k);
        let unlock_height = k.saturating_mul(BLOCKS_PER_YEAR);
        let script = VaultScript::new(unlock_height, 0, owner_pk).expect("valid");
        assert_eq!(script.unlock_height(), unlock_height);
        assert_eq!(script.csv(), 0);
        assert_eq!(script.owner_pk(), &owner_pk);
    }
}

// ---------------------------------------------------------------------------
// 4. Genesis without treasury → only premine
// ---------------------------------------------------------------------------

#[test]
fn genesis_without_treasury_has_only_premine() {
    let mut node = Node::new();
    let (_genesis, founder) = node
        .genesis(K, 1_000, 1_000, 1, None) // explicit: no treasury vaults
        .expect("genesis without treasury");

    assert_eq!(node.balance(&founder).unwrap(), 1_000);
}

// ---------------------------------------------------------------------------
// 5. Treasury with a non-standard premine is rejected (explicit-flag guard)
// ---------------------------------------------------------------------------

#[test]
fn treasury_with_non_standard_premine_is_rejected() {
    let mut node = Node::new();
    // Treasury inclusion is explicit, and the premine is part of the consensus
    // genesis: asking for treasury with a non-standard premine must fail loudly
    // rather than silently minting the standard premine.
    let err = node
        .genesis(K, 100, 1_000, 1, Some(TreasuryGenesis::placeholder()))
        .expect_err("treasury with non-standard premine must be rejected");
    assert!(
        err.to_string().contains("RFC006_PREMINE"),
        "unexpected error: {err}"
    );
}

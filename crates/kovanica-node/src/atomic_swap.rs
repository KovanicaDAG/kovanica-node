//! Tier Nolan atomic swap orchestration — RFC-004.
//!
//! A pure library (no [`crate::Node`] dependency) that turns two parties'
//! parameters into the two HTLC templates that make a cross-party swap safe:
//!
//! ```text
//! 1. Alice generates preimage x, computes H = BLAKE3(x).
//! 2. Alice funds HTLC-A:  H, recipient=Bob, sender=Alice, timeout=T_A.
//! 3. Bob verifies HTLC-A on-chain (script hash, recipient=Bob, timeout=T_A).
//! 4. Bob funds HTLC-B:    H, recipient=Alice, sender=Bob, timeout=T_B < T_A.
//! 5. Alice redeems HTLC-B with x → gets asset_b; x revealed on-chain.
//! 6. Bob extracts x from HTLC-B's redeem witness, redeems HTLC-A with x.
//! 7. Fallback: Bob refunds HTLC-B after T_B; Alice refunds HTLC-A after T_A.
//! ```
//!
//! **Timeout ordering `T_B < T_A` is the safety invariant** — [`SwapSession::new`]
//! enforces it. The margin `T_A − T_B` is off-chain policy (recommend ≥ 2×
//! expected block propagation latency; on a DAG, height advances on the
//! selected chain, so the margin must cover gossip + linearization lag).
//!
//! Reference protocols: Tier Nolan atomic swap, Bitcoin HTLC (BIP-199),
//! Lightning Network (preimage revelation).

use kovanica_state::htlc::HtlcScript;
use kovanica_state::{AssetId, Transaction};

/// The two parties to a swap. `Alice` funds HTLC-A and redeems HTLC-B; `Bob`
/// funds HTLC-B and redeems HTLC-A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapRole {
    /// The party who funds HTLC-A (recipient of HTLC-B).
    Alice,
    /// The party who funds HTLC-B (recipient of HTLC-A).
    Bob,
}

/// The economic parameters of a swap: what each party puts in, and the two
/// refund heights. `timeout_a` is HTLC-A's refund height (Alice's leg),
/// `timeout_b` HTLC-B's (Bob's leg).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapParams {
    /// Value Alice locks in HTLC-A.
    pub amount_a: u64,
    /// Asset Alice locks in HTLC-A (`None` = native KVNC).
    pub asset_a: Option<AssetId>,
    /// Value Bob locks in HTLC-B.
    pub amount_b: u64,
    /// Asset Bob locks in HTLC-B (`None` = native KVNC).
    pub asset_b: Option<AssetId>,
    /// HTLC-A refund height (absolute block height).
    pub timeout_a: u32,
    /// HTLC-B refund height; must be `< timeout_a`.
    pub timeout_b: u32,
}

/// Why a [`SwapSession`] could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// `timeout_b >= timeout_a` — Bob's refund would unlock before Alice's,
    /// letting Bob take Alice's funds and still refund his own. The safety
    /// invariant of the Tier Nolan protocol.
    TimeoutOrdering,
    /// Both parties supplied the same public key — a swap needs two distinct
    /// parties.
    SameParty,
    /// One of the supplied public keys is not a valid Ed25519 point (or the
    /// derived template otherwise failed validation).
    InvalidKey(kovanica_state::HtlcScriptError),
}

impl core::fmt::Display for SwapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TimeoutOrdering => {
                f.write_str("timeout_b must be strictly less than timeout_a (T_B < T_A)")
            }
            Self::SameParty => f.write_str("alice and bob must be distinct parties"),
            Self::InvalidKey(e) => write!(f, "invalid swap key: {e}"),
        }
    }
}

impl std::error::Error for SwapError {}

/// A fully-specified swap: the shared preimage and the two HTLC templates.
///
/// `htlc_a` is the template Alice funds (recipient = Bob, sender = Alice);
/// `htlc_b` is the template Bob funds (recipient = Alice, sender = Bob). Both
/// commit to the same preimage hash, so the preimage that unlocks one unlocks
/// the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapSession {
    /// The shared preimage `x` (Alice's secret until she redeems HTLC-B).
    pub preimage: [u8; 32],
    /// `BLAKE3(preimage)` — committed to by both templates.
    pub preimage_hash: [u8; 32],
    /// HTLC-A: recipient = Bob, sender = Alice, timeout = `timeout_a`.
    pub htlc_a: HtlcScript,
    /// HTLC-B: recipient = Alice, sender = Bob, timeout = `timeout_b`.
    pub htlc_b: HtlcScript,
}

impl SwapSession {
    /// Construct a swap session from the economic parameters and the two
    /// parties' public keys.
    ///
    /// Enforces the safety invariant `timeout_b < timeout_a`
    /// ([`SwapError::TimeoutOrdering`]) and that the parties are distinct
    /// ([`SwapError::SameParty`]). The supplied keys must be valid Ed25519
    /// points ([`SwapError::InvalidKey`] otherwise).
    pub fn new(
        params: &SwapParams,
        alice_pk: [u8; 32],
        bob_pk: [u8; 32],
        preimage: [u8; 32],
    ) -> Result<Self, SwapError> {
        if params.timeout_b >= params.timeout_a {
            return Err(SwapError::TimeoutOrdering);
        }
        if alice_pk == bob_pk {
            return Err(SwapError::SameParty);
        }
        let preimage_hash = preimage_hash(&preimage);
        let htlc_a = HtlcScript::new(preimage_hash, bob_pk, alice_pk, params.timeout_a)
            .map_err(SwapError::InvalidKey)?;
        let htlc_b = HtlcScript::new(preimage_hash, alice_pk, bob_pk, params.timeout_b)
            .map_err(SwapError::InvalidKey)?;
        Ok(Self {
            preimage,
            preimage_hash,
            htlc_a,
            htlc_b,
        })
    }

    /// Bob's on-chain verification of HTLC-A before funding HTLC-B: the
    /// on-chain script must be exactly this session's HTLC-A template (all
    /// four fields — preimage hash, recipient, sender, timeout — plus the
    /// role). `role` selects which of the session's templates to compare
    /// against: [`SwapRole::Bob`] verifies HTLC-A (the leg *Bob* is the
    /// recipient of), [`SwapRole::Alice`] verifies HTLC-B.
    pub fn verify_against(&self, script: &HtlcScript, role: SwapRole) -> bool {
        let expected = match role {
            SwapRole::Alice => &self.htlc_b,
            SwapRole::Bob => &self.htlc_a,
        };
        script == expected
    }
}

/// Generate a fresh 32-byte preimage from the operating system's CSPRNG.
///
/// Off-chain only — the ledger never samples randomness, and tests inject a
/// fixed preimage via [`SwapSession::new`].
pub fn generate_preimage() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// `BLAKE3(preimage)` — the hash committed to by both HTLC templates.
pub fn preimage_hash(preimage: &[u8]) -> [u8; 32] {
    *blake3::hash(preimage).as_bytes()
}

/// Scan `tx`'s inputs for a **redeem** of `script` — a witness of exactly
/// three elements whose first element is the template bytes — and return the
/// revealed preimage (`witness[1]`).
///
/// This is the trustless preimage-revelation path: once Alice redeems HTLC-B
/// on-chain, Bob (or anyone) can read the preimage straight off the witness
/// and use it to redeem HTLC-A.
pub fn extract_preimage(tx: &Transaction, script: &HtlcScript) -> Option<Vec<u8>> {
    let script_bytes = script.bytes();
    tx.inputs().iter().find_map(|input| {
        if input.witness.len() == 3 && input.witness[0] == script_bytes {
            Some(input.witness[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_state::KeyPair;

    fn alice_bob() -> (KeyPair, KeyPair) {
        (KeyPair::from_u64(1), KeyPair::from_u64(2))
    }

    fn params() -> SwapParams {
        SwapParams {
            amount_a: 500,
            asset_a: None,
            amount_b: 400,
            asset_b: None,
            timeout_a: 3,
            timeout_b: 1,
        }
    }

    #[test]
    fn session_constructs_and_verifies() {
        let (alice, bob) = alice_bob();
        let session = SwapSession::new(
            &params(),
            *alice.address().payload(),
            *bob.address().payload(),
            [0x42u8; 32],
        )
        .unwrap();

        assert_eq!(session.preimage_hash, preimage_hash(&[0x42u8; 32]));
        // htlc_a: recipient = Bob, sender = Alice.
        assert_eq!(session.htlc_a.recipient_pk(), bob.address().payload());
        assert_eq!(session.htlc_a.sender_pk(), alice.address().payload());
        assert_eq!(session.htlc_a.timeout(), 3);
        // htlc_b: recipient = Alice, sender = Bob.
        assert_eq!(session.htlc_b.recipient_pk(), alice.address().payload());
        assert_eq!(session.htlc_b.sender_pk(), bob.address().payload());
        assert_eq!(session.htlc_b.timeout(), 1);

        // Bob verifies HTLC-A; Alice verifies HTLC-B.
        assert!(session.verify_against(&session.htlc_a, SwapRole::Bob));
        assert!(session.verify_against(&session.htlc_b, SwapRole::Alice));
        // Cross-role verification fails.
        assert!(!session.verify_against(&session.htlc_a, SwapRole::Alice));
        assert!(!session.verify_against(&session.htlc_b, SwapRole::Bob));
    }

    #[test]
    fn timeout_ordering_enforced() {
        let (alice, bob) = alice_bob();
        let mut p = params();
        p.timeout_b = p.timeout_a; // equal → rejected
        assert_eq!(
            SwapSession::new(
                &p,
                *alice.address().payload(),
                *bob.address().payload(),
                [0x42u8; 32],
            ),
            Err(SwapError::TimeoutOrdering)
        );
        p.timeout_b = p.timeout_a + 1; // greater → rejected
        assert_eq!(
            SwapSession::new(
                &p,
                *alice.address().payload(),
                *bob.address().payload(),
                [0x42u8; 32],
            ),
            Err(SwapError::TimeoutOrdering)
        );
    }

    #[test]
    fn same_party_rejected() {
        let (alice, _) = alice_bob();
        let pk = *alice.address().payload();
        assert_eq!(
            SwapSession::new(&params(), pk, pk, [0x42u8; 32]),
            Err(SwapError::SameParty)
        );
    }

    #[test]
    fn invalid_key_rejected() {
        let (alice, _) = alice_bob();
        // y=2 (bytes [0x02, 0, …, 0]) is NOT on the Ed25519 curve.
        let invalid = [0x02u8; 32];
        assert!(matches!(
            SwapSession::new(&params(), *alice.address().payload(), invalid, [0x42u8; 32],),
            Err(SwapError::InvalidKey(_))
        ));
    }

    #[test]
    fn extract_preimage_finds_redeem() {
        let (alice, bob) = alice_bob();
        let session = SwapSession::new(
            &params(),
            *alice.address().payload(),
            *bob.address().payload(),
            [0x42u8; 32],
        )
        .unwrap();

        // A redeem of htlc_b reveals the preimage in witness[1].
        let outpoint =
            kovanica_state::OutPoint::new(kovanica_state::TxId::from_bytes([1u8; 32]), 0);
        let input = kovanica_state::TxInput::new(
            outpoint,
            session
                .htlc_b
                .redeem_witness(&session.preimage, [0x11u8; 64]),
        );
        let tx = Transaction::new(
            vec![input],
            vec![kovanica_state::TxOutput::native(100, alice.address())],
            Vec::new(),
        );
        assert_eq!(
            extract_preimage(&tx, &session.htlc_b),
            Some(session.preimage.to_vec())
        );
        // A refund (2-element witness) is not a redeem.
        let refund_input =
            kovanica_state::TxInput::new(outpoint, session.htlc_b.refund_witness([0x22u8; 64]));
        let refund_tx = Transaction::new(
            vec![refund_input],
            vec![kovanica_state::TxOutput::native(100, bob.address())],
            Vec::new(),
        );
        assert_eq!(extract_preimage(&refund_tx, &session.htlc_b), None);
        // A redeem of a *different* script is not found.
        assert_eq!(extract_preimage(&tx, &session.htlc_a), None);
    }
}

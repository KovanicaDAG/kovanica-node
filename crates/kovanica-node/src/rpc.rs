//! The node's line RPC: one text command per line in, one line out.
//!
//! [`execute_line`] is a pure function of the node and the command string — it
//! returns the response rather than doing any I/O — so the whole protocol is
//! unit-testable without a socket or a process. The binary ([`crate`]'s `main`)
//! wires it to stdin/stdout (`serve`) or replays a scripted `demo`.
//!
//! Every response begins with `ok` or `err`. Commands:
//!
//! ```text
//! help                                list commands
//! genesis <k> <subsidy> <amount> <seed>   create the genesis ledger
//! address <seed>                      the address for an actor seed
//! balance <seed|addr-hex>             spendable balance
//! send <from-seed> <amount> <to-seed> transfer, as a new block on the tips
//! tips                                current tip block ids
//! tip                                 selected (heaviest) tip
//! len                                 number of blocks
//! save <path> / load <path>          snapshot persistence
//! checkpoint <path> / load_checkpoint <path>  finality checkpoint persistence
//! ```

use kovanica_state::{Address, HtlcScript, KeyPair, OutPoint, TxId, VaultScript};

use crate::node::Node;

/// The help text listing every command.
pub const HELP: &str = "commands: help | genesis <k> <subsidy> <amount> <seed> | \
genesis_finality <k> <subsidy> <amount> <seed> <finality_depth> | \
address <seed> | balance <seed|addr-hex> | send <from-seed> <amount> <to-seed> | \
pool <from-seed> <amount> <to-seed> | produce | pending | tips | tip | len | \
staking [vrf-pk-hex] | save <path> | load <path> | checkpoint <path> | load_checkpoint <path> | \
htlc_create <from-seed> <amount> <recipient-pk-hex> <preimage-hash-hex> <timeout> | \
htlc_redeem <from-seed> <outpoint-tx-hex> <outpoint-index> <script-hex> <preimage-hex> <to-addr> | \
htlc_refund <from-seed> <outpoint-tx-hex> <outpoint-index> <script-hex> <to-addr> | \
htlc_balance <script-hex> | \
vault_create <from-seed> <amount> <unlock-height> <csv> <owner-pk-hex> | \
vault_release <from-seed> <outpoint-tx-hex> <outpoint-index> <script-hex> <to-addr> | \
vault_balance <script-hex>";

/// Run one command line against `node`, returning the response line. Never
/// panics on bad input; malformed commands produce an `err ...` response.
pub fn execute_line(node: &mut Node, line: &str) -> String {
    match run(node, line) {
        Ok(msg) if msg.is_empty() => "ok".to_string(),
        Ok(msg) => format!("ok {msg}"),
        Err(e) => format!("err {e}"),
    }
}

fn run(node: &mut Node, line: &str) -> Result<String, String> {
    let mut tokens = line.split_whitespace();
    let Some(cmd) = tokens.next() else {
        return Ok(String::new()); // blank line
    };
    let args: Vec<&str> = tokens.collect();

    match cmd {
        "help" => Ok(HELP.to_string()),

        "genesis" => {
            let [k, subsidy, amount, seed] = fixed::<4>(&args)?;
            let (genesis, founder) = node
                .genesis(
                    u16_arg(k)?,
                    u64_arg(subsidy)?,
                    u64_arg(amount)?,
                    u64_arg(seed)?,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!("genesis {genesis} founder {founder}"))
        }

        "genesis_finality" => {
            let [k, subsidy, amount, seed, finality_depth] = fixed::<5>(&args)?;
            let (genesis, founder) = node
                .genesis_with_finality(
                    u16_arg(k)?,
                    u64_arg(subsidy)?,
                    u64_arg(amount)?,
                    u64_arg(seed)?,
                    u64_arg(finality_depth)?,
                    u64::MAX,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!("genesis {genesis} founder {founder}"))
        }

        "address" => {
            let [seed] = fixed::<1>(&args)?;
            Ok(Node::address(u64_arg(seed)?).to_string())
        }

        "balance" => {
            let [target] = fixed::<1>(&args)?;
            let addr = parse_target(target)?;
            Ok(node.balance(&addr).map_err(|e| e.to_string())?.to_string())
        }

        "send" => {
            let [from, amount, to] = fixed::<3>(&args)?;
            let sent = node
                .send(u64_arg(from)?, u64_arg(amount)?, u64_arg(to)?)
                .map_err(|e| e.to_string())?;
            Ok(format!("block {} tx {}", sent.block, sent.tx))
        }

        "pool" => {
            let [from, amount, to] = fixed::<3>(&args)?;
            let tx = node
                .pool(u64_arg(from)?, u64_arg(amount)?, u64_arg(to)?)
                .map_err(|e| e.to_string())?;
            Ok(format!("tx {tx}"))
        }

        "produce" => {
            let [] = fixed::<0>(&args)?;
            match node.produce_block().map_err(|e| e.to_string())? {
                Some(block) => Ok(format!("block {block}")),
                None => Ok("empty".to_string()),
            }
        }

        "pending" => {
            let [] = fixed::<0>(&args)?;
            Ok(node.pending_count().to_string())
        }

        "tips" => {
            let tips = node.tips().map_err(|e| e.to_string())?;
            Ok(tips
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(" "))
        }

        "tip" => Ok(node.selected_tip().map_err(|e| e.to_string())?.to_string()),

        // Read-only staking summary: hybrid status, this node's validator key,
        // and bonded stakes (total, plus optionally one key's) at the tip view.
        "staking" => {
            let mut out = format!(
                "hybrid={} total_stake={}",
                node.hybrid_enabled(),
                node.total_stake().map_err(|e| e.to_string())?
            );
            if let Some(pk) = node.validator_public_key() {
                out.push_str(&format!(" validator={}", hex::encode(pk.as_bytes())));
            }
            if let [pk_hex] = args[..] {
                let mut pk = [0u8; 32];
                hex::decode_to_slice(pk_hex, &mut pk)
                    .map_err(|e| format!("bad vrf-pk-hex: {e}"))?;
                out.push_str(&format!(
                    " stake_of={}",
                    node.stake_of(&pk).map_err(|e| e.to_string())?
                ));
            }
            Ok(out)
        }

        "htlc_create" => {
            let [from, amount, recipient_pk_hex, preimage_hash_hex, timeout] = fixed::<5>(&args)?;
            let kp = KeyPair::from_u64(u64_arg(from)?);
            let mut recipient_pk = [0u8; 32];
            hex::decode_to_slice(recipient_pk_hex, &mut recipient_pk)
                .map_err(|e| format!("bad recipient-pk-hex: {e}"))?;
            let mut preimage_hash = [0u8; 32];
            hex::decode_to_slice(preimage_hash_hex, &mut preimage_hash)
                .map_err(|e| format!("bad preimage-hash-hex: {e}"))?;
            let info = node
                .create_htlc(
                    &kp,
                    u64_arg(amount)?,
                    None,
                    recipient_pk,
                    preimage_hash,
                    u32_arg(timeout)?,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "{} {} {}",
                info.tx_id,
                hex::encode(info.script.bytes()),
                info.address
            ))
        }

        "htlc_redeem" => {
            let [from, outpoint_tx_hex, outpoint_index, script_hex, preimage_hex, to_addr] =
                fixed::<6>(&args)?;
            let kp = KeyPair::from_u64(u64_arg(from)?);
            let outpoint = parse_outpoint(outpoint_tx_hex, outpoint_index)?;
            let script = parse_htlc_script(script_hex)?;
            let preimage =
                hex::decode(preimage_hex).map_err(|e| format!("bad preimage-hex: {e}"))?;
            let to = Address::parse(to_addr).map_err(|e| e.to_string())?;
            let tx_id = node
                .redeem_htlc(&kp, outpoint, &script, &preimage, to)
                .map_err(|e| e.to_string())?;
            Ok(tx_id.to_string())
        }

        "htlc_refund" => {
            let [from, outpoint_tx_hex, outpoint_index, script_hex, to_addr] = fixed::<5>(&args)?;
            let kp = KeyPair::from_u64(u64_arg(from)?);
            let outpoint = parse_outpoint(outpoint_tx_hex, outpoint_index)?;
            let script = parse_htlc_script(script_hex)?;
            let to = Address::parse(to_addr).map_err(|e| e.to_string())?;
            let tx_id = node
                .refund_htlc(&kp, outpoint, &script, to)
                .map_err(|e| e.to_string())?;
            Ok(tx_id.to_string())
        }

        "htlc_balance" => {
            let [script_hex] = fixed::<1>(&args)?;
            let script = parse_htlc_script(script_hex)?;
            Ok(node.balance_of_htlc(&script).to_string())
        }

        "vault_create" => {
            let [from, amount, unlock_height, csv, owner_pk_hex] = fixed::<5>(&args)?;
            let kp = KeyPair::from_u64(u64_arg(from)?);
            let mut owner_pk = [0u8; 32];
            hex::decode_to_slice(owner_pk_hex, &mut owner_pk)
                .map_err(|e| format!("bad owner-pk-hex: {e}"))?;
            let info = node
                .create_vault(
                    &kp,
                    u64_arg(amount)?,
                    u32_arg(unlock_height)?,
                    u32_arg(csv)?,
                    owner_pk,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "{} {} {}",
                info.tx_id,
                hex::encode(info.script.bytes()),
                info.address
            ))
        }

        "vault_release" => {
            let [from, outpoint_tx_hex, outpoint_index, script_hex, to_addr] = fixed::<5>(&args)?;
            let kp = KeyPair::from_u64(u64_arg(from)?);
            let outpoint = parse_outpoint(outpoint_tx_hex, outpoint_index)?;
            let script = parse_vault_script(script_hex)?;
            let to = Address::parse(to_addr).map_err(|e| e.to_string())?;
            let tx_id = node
                .release_vault(&kp, outpoint, &script, to)
                .map_err(|e| e.to_string())?;
            Ok(tx_id.to_string())
        }

        "vault_balance" => {
            let [script_hex] = fixed::<1>(&args)?;
            let script = parse_vault_script(script_hex)?;
            Ok(node.balance_of_vault(&script).to_string())
        }

        "len" => Ok(node.block_count().map_err(|e| e.to_string())?.to_string()),

        "save" => {
            let [path] = fixed::<1>(&args)?;
            node.save(path).map_err(|e| e.to_string())?;
            Ok(format!("saved {path}"))
        }

        "load" => {
            let [path] = fixed::<1>(&args)?;
            node.load(path).map_err(|e| e.to_string())?;
            Ok("loaded".to_string())
        }

        "checkpoint" => {
            let [path] = fixed::<1>(&args)?;
            node.save_checkpoint(path).map_err(|e| e.to_string())?;
            Ok(format!("checkpoint saved {path}"))
        }

        "load_checkpoint" => {
            let [path] = fixed::<1>(&args)?;
            node.load_checkpoint(path).map_err(|e| e.to_string())?;
            Ok("loaded".to_string())
        }

        other => Err(format!("unknown command '{other}' (try help)")),
    }
}

/// Require exactly `N` arguments, returning them as a fixed array of slices.
fn fixed<'a, const N: usize>(args: &[&'a str]) -> Result<[&'a str; N], String> {
    if args.len() != N {
        return Err(format!("expected {N} argument(s), got {}", args.len()));
    }
    Ok(core::array::from_fn(|i| args[i]))
}

fn u64_arg(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|_| format!("'{s}' is not a number"))
}

fn u16_arg(s: &str) -> Result<u16, String> {
    s.parse::<u16>()
        .map_err(|_| format!("'{s}' is not a small number"))
}

fn u32_arg(s: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| format!("'{s}' is not a number"))
}

/// Parse an outpoint from a transaction-id hex string and an output index.
fn parse_outpoint(tx_hex: &str, index: &str) -> Result<OutPoint, String> {
    let mut tx = [0u8; 32];
    hex::decode_to_slice(tx_hex, &mut tx).map_err(|e| format!("bad outpoint-tx-hex: {e}"))?;
    Ok(OutPoint::new(TxId::from_bytes(tx), u32_arg(index)?))
}

/// Parse a 100-byte HTLC template from hex.
fn parse_htlc_script(script_hex: &str) -> Result<HtlcScript, String> {
    let bytes = hex::decode(script_hex).map_err(|e| format!("bad script-hex: {e}"))?;
    HtlcScript::parse(&bytes).map_err(|e| e.to_string())
}

/// Parse a 40-byte vault template from hex.
fn parse_vault_script(script_hex: &str) -> Result<VaultScript, String> {
    let bytes = hex::decode(script_hex).map_err(|e| format!("bad script-hex: {e}"))?;
    VaultScript::parse(&bytes).map_err(|e| e.to_string())
}

/// A balance target is either an address (Base58, versioned/legacy hex) or an actor seed.
fn parse_target(token: &str) -> Result<Address, String> {
    if let Ok(addr) = Address::parse(token) {
        Ok(addr)
    } else {
        Ok(Node::address(u64_arg(token)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_unknown() {
        let mut node = Node::new();
        assert_eq!(execute_line(&mut node, ""), "ok");
        assert_eq!(execute_line(&mut node, "   "), "ok");
        assert!(execute_line(&mut node, "frobnicate").starts_with("err unknown command"));
    }

    #[test]
    fn arg_errors_do_not_panic() {
        let mut node = Node::new();
        assert!(execute_line(&mut node, "genesis 3 1000").starts_with("err expected 4"));
        assert!(execute_line(&mut node, "genesis x 1 1 1").starts_with("err"));
        assert!(execute_line(&mut node, "balance 1").starts_with("err")); // no ledger yet
    }
}

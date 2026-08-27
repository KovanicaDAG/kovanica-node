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

use kovanica_state::Address;

use crate::node::Node;

/// The help text listing every command.
pub const HELP: &str = "commands: help | genesis <k> <subsidy> <amount> <seed> | \
genesis_finality <k> <subsidy> <amount> <seed> <finality_depth> | \
address <seed> | balance <seed|addr-hex> | send <from-seed> <amount> <to-seed> | \
pool <from-seed> <amount> <to-seed> | produce | pending | tips | tip | len | \
staking [vrf-pk-hex] | save <path> | load <path> | checkpoint <path> | load_checkpoint <path>";

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

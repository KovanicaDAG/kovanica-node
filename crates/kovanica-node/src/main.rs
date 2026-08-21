//! * `kovanica-node` (or `kovanica-node serve`) — a REPL: read one command per
//!   line from stdin, print the response to stdout. `quit`/`exit` ends it.
//! * `kovanica-node demo` — replay a scripted end-to-end scenario, printing each
//!   command and its response, so the whole stack can be exercised in one run.
//! * `kovanica-node explorer [addr]` — self-hosted BlockDAG explorer (JSON API +
//!   UI) on `addr`, default `0.0.0.0:8080`. The engine is this process; the
//!   page only renders it.

use std::io::{self, BufRead, Write};
use kovanica_node::{rpc, Node};

// Dodajemo naš novi mrežni modul
mod network;
use futures::StreamExt;

fn main() {
    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        None | Some("serve") => serve(),
        Some("demo") => demo(),
        Some("explorer") => {
            let addr = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "0.0.0.0:8080".into());
            
            // Pokrećemo P2P mrežni čvor asinkrono u pozadini preko tokio runtime-a
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    if let Ok(mut swarm) = network::setup_swarm() {
                        // Slušamo na P2P portu 30333
                        swarm.listen_on("/ip4/0.0.0.0/tcp/30333".parse().unwrap()).unwrap();
                        println!("📡 P2P mrežni sloj uspješno pokrenut na portu 30333");
                        
                        loop {
                            match swarm.select_next_some().await {
                                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                                    println!("📡 Kovanica P2P sluša na: {}", address);
                                }
                                libp2p::swarm::SwarmEvent::Behaviour(network::KovanicaBehaviourEvent::Mdns(
                                    libp2p::mdns::Event::Discovered(list),
                                )) => {
                                    for (peer_id, multiaddr) in list {
                                        println!("🔍 Pronađen peer preko mDNS-a: {} na adresi {}", peer_id, multiaddr);
                                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                });
            });

            // Pokrećemo standardni explorer/API poslužitelj na predloženoj adresi
            if let Err(e) = kovanica_node::serve_explorer(&addr) {
                eprintln!("explorer failed: {e}");
                std::process::exit(1);
            }
        }
        Some("help") | Some("-h") | Some("--help") => {
            println!("usage: kovanica-node [serve|demo|explorer [addr]]");
            println!("  serve     read commands from stdin (default)");
            println!("  demo      run a scripted end-to-end scenario");
            println!("  explorer  self-hosted UI + JSON API (default 0.0.0.0:8080) + P2P Node");
            println!("            env: KOVANICA_DATA  KOVANICA_MINE=0|1  KOVANICA_FAUCET=0|1");
            println!("                 KOVANICA_ALLOW_RESET=0|1  KOVANICA_OPERATOR=0|1");
            println!("                 KOVANICA_LISTEN=0.0.0.0:9000");
            println!("                 KOVANICA_PEERS=host:9000,host2:9000");
            println!("                 KOVANICA_POW=0|1  (default 1, consensus hash target)");
            println!();
            println!("{}", rpc::HELP);
        }
        Some(other) => {
            eprintln!("unknown mode '{other}' (use: serve | demo | explorer | help)");
            std::process::exit(2);
        }
    }
}

/// Read commands from stdin, print one response line each.
fn serve() {
    let mut node = Node::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "kovanica-node ready — type `help`, `quit` to exit");
    let _ = stdout.flush();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed == "quit" || trimmed == "exit" {
            break;
        }
        let response = rpc::execute_line(&mut node, trimmed);
        if writeln!(stdout, "{response}").is_err() {
            break;
        }
        let _ = stdout.flush();
    }
}

/// Replay a fixed scenario, printing a transcript.
fn demo() {
    let mut node = Node::new();
    let script = [
        "genesis 3 1000 500 1",
        "balance 1",
        "send 1 200 2",
        "balance 1",
        "balance 2",
        "pool 2 50 3",
        "pending",
        "produce",
        "pending",
        "balance 2",
        "balance 3",
        "tip",
        "len",
    ];
    for cmd in script {
        println!("> {cmd}");
        println!("{}", rpc::execute_line(&mut node, cmd));
    }
}

use libp2p::{
    gossipsub, mdns, swarm::NetworkBehaviour,
    identity, noise, tcp, yamux, PeerId, Swarm, SwarmBuilder,
};
use std::error::Error;
use std::time::Duration;

#[derive(NetworkBehaviour)]
pub struct KovanicaBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub fn setup_swarm() -> Result<Swarm<KovanicaBehaviour>, Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("🚀 Inicijaliziran Kovanica P2P Node. Peer ID: {}", local_peer_id);

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .build()
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;
        
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;

    let behaviour = KovanicaBehaviour { gossipsub, mdns };

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

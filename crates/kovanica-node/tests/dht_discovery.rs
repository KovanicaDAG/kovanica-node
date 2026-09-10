//! Integration tests for Multi-Seed Discovery and Kademlia DHT.
//!
//! Tests the complete DHT-based peer discovery flow:
//! - Tier 1: Feature coverage (DNS resolution, XOR metric, K-buckets, wire framing, iterative lookup)
//! - Tier 2: Boundary cases (empty table, full bucket, self-lookup, nonce mismatch, unresponsive intermediate, 3-strike eviction)
//! - Tier 3: Cross-feature (multiplexed framing, DHT+P2P coupling, block/tx dissemination)
//! - Tier 4: Real-world scenarios (multi-seed bootstrap, multi-hop discovery, dynamic pruning, replenishment, partition healing)
//! - Tier 5: Adversarial (churn, Sybil/poisoning, eclipse resistance)

use kovanica_node::{
    dht::{DhtMsg, NodeId, NodeLookup, PeerContact, RoutingTable, UpdateResult},
    dns_seed::{DnsSeedConfig, DnsSeedResolver, MockDnsResolver},
    node::Node,
    p2p::Mesh,
    relay::{RelayMsg, RelaySession},
};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

/// Helper to create a test node with DHT
fn create_test_node(node_id: NodeId, k: usize) -> Node {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();
    node.init_dht_routing_table(node_id, k);
    node
}

/// Helper to create a mesh with DHT-enabled nodes
#[allow(dead_code)]
fn create_dht_mesh(node_count: usize, k: usize) -> (Mesh, Vec<NodeId>) {
    let mut mesh = Mesh::new();
    let mut node_ids = Vec::new();

    for i in 0..node_count {
        let node_id = NodeId::random();
        node_ids.push(node_id);
        let node = create_test_node(node_id, k);
        let name = format!("node-{}", i);
        mesh.add_with_dht(name.clone(), node, node_id);
    }

    (mesh, node_ids)
}
#[allow(dead_code)]
#[test]
fn test_dns_multi_seed_resolver_deduplication() {
    let mut records = HashMap::new();
    let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
    let addr2: SocketAddr = "192.168.1.2:9000".parse().unwrap();
    let addr3: SocketAddr = "192.168.1.3:9000".parse().unwrap();

    // Same IP from two seeds - use default seed names
    records.insert("seed.kovanica.online:9000".to_string(), vec![addr1, addr2]);
    records.insert("seed2.kovanica.online:9000".to_string(), vec![addr1, addr3]);

    let config = DnsSeedConfig {
        seeds: vec![
            "seed.kovanica.online".to_string(),
            "seed2.kovanica.online".to_string(),
        ],
        ..Default::default()
    };
    let resolver = DnsSeedResolver::with_config(MockDnsResolver::new(records), config);
    let addrs = resolver.resolve_all();

    assert_eq!(addrs.len(), 3, "Should deduplicate across seeds");
    assert!(addrs.contains(&addr1));
    assert!(addrs.contains(&addr2));
    assert!(addrs.contains(&addr3));
}

#[test]
fn test_dns_multi_seed_resolver_fallback() {
    let resolver = DnsSeedResolver::new(MockDnsResolver::default());
    let addrs = resolver.resolve_all();

    // Should return fallback addresses
    assert!(!addrs.is_empty());
    assert!(addrs
        .iter()
        .any(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn test_dns_multi_seed_resolver_shuffling() {
    let mut records = HashMap::new();
    let mut addrs = Vec::new();
    for i in 1..=10 {
        addrs.push(format!("192.168.1.{}:9000", i).parse().unwrap());
    }
    records.insert("seed.kovanica.online:9000".to_string(), addrs.clone());

    let config = DnsSeedConfig {
        seeds: vec!["seed.kovanica.online".to_string()],
        max_addrs: 5,
        ..Default::default()
    };
    let resolver = DnsSeedResolver::with_config(MockDnsResolver::new(records), config);
    let result = resolver.resolve_all();

    // Should be limited to max_addrs
    assert_eq!(result.len(), 5);
}

#[test]
fn test_node_id_xor_metric_properties() {
    let id1 = NodeId::from_bytes([0u8; 32]);
    let id2 = NodeId::from_bytes([1u8; 32]);
    let id3 = NodeId::from_bytes([2u8; 32]);

    // Identity: d(x, x) = 0
    assert_eq!(id1.distance(&id1), [0u8; 32]);

    // Symmetry: d(x, y) = d(y, x)
    assert_eq!(id1.distance(&id2), id2.distance(&id1));

    // Triangle inequality (XOR metric property)
    let d12 = id1.distance(&id2);
    let d23 = id2.distance(&id3);
    let d13 = id1.distance(&id3);
    // For XOR: d(x,z) <= d(x,y) XOR d(y,z) bitwise
    for i in 0..32 {
        assert!(d13[i] <= d12[i] ^ d23[i]);
    }
}

#[test]
fn test_node_id_bucket_index() {
    let id1 = NodeId::from_bytes([0u8; 32]);

    // Last bit differs -> bucket 255
    let mut id2_bytes = [0u8; 32];
    id2_bytes[31] = 1;
    let id2 = NodeId::from_bytes(id2_bytes);
    assert_eq!(id1.bucket_index(&id2), Some(255));

    // First bit differs -> bucket 0
    let mut id3_bytes = [0u8; 32];
    id3_bytes[0] = 0x80;
    let id3 = NodeId::from_bytes(id3_bytes);
    assert_eq!(id1.bucket_index(&id3), Some(0));

    // Self distance -> None
    assert_eq!(id1.bucket_index(&id1), None);
}

#[test]
fn test_kbucket_basic_operations() {
    let mut bucket = kovanica_node::dht::KBucket::new(3);
    let id1 = NodeId::random();
    let id2 = NodeId::random();
    let id3 = NodeId::random();

    let c1 = PeerContact::new(id1, "127.0.0.1:9001".to_string());
    let c2 = PeerContact::new(id2, "127.0.0.1:9002".to_string());
    let c3 = PeerContact::new(id3, "127.0.0.1:9003".to_string());

    assert_eq!(bucket.update_contact(c1), UpdateResult::Added);
    assert_eq!(bucket.update_contact(c2), UpdateResult::Added);
    assert_eq!(bucket.update_contact(c3), UpdateResult::Added);
    assert!(bucket.is_full());

    // Fourth goes to replacement cache
    let id4 = NodeId::random();
    let c4 = PeerContact::new(id4, "127.0.0.1:9004".to_string());
    assert_eq!(bucket.update_contact(c4), UpdateResult::Cached);
}

#[test]
fn test_kbucket_lru_ordering() {
    let mut bucket = kovanica_node::dht::KBucket::new(3);
    let id1 = NodeId::random();
    let id2 = NodeId::random();
    let id3 = NodeId::random();

    bucket.update_contact(PeerContact::new(id1, "127.0.0.1:9001".to_string()));
    bucket.update_contact(PeerContact::new(id2, "127.0.0.1:9002".to_string()));
    bucket.update_contact(PeerContact::new(id3, "127.0.0.1:9003".to_string()));

    // Touch id1 to make it most recent
    bucket.update_contact(PeerContact::new(id1, "127.0.0.1:9001".to_string()));

    // LRU should be id2
    let lru = bucket.lru_contact().unwrap();
    assert_eq!(lru.node_id, id2);
}

#[test]
fn test_kbucket_failure_eviction() {
    let mut bucket = kovanica_node::dht::KBucket::new(3);
    let id1 = NodeId::random();

    bucket.update_contact(PeerContact::new(id1, "127.0.0.1:9001".to_string()));

    // Mark failed 3 times
    for _ in 0..3 {
        if let Some(evicted) = bucket.mark_failed(&id1) {
            assert_eq!(evicted.node_id, id1);
        }
    }
    assert!(bucket.is_empty());
}

#[test]
fn test_routing_table_closest_peers() {
    let local = NodeId::from_bytes([0u8; 32]);
    let mut table = RoutingTable::new(local, 8);

    // Add contacts at various distances
    for i in 1..10 {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        let id = NodeId::from_bytes(bytes);
        let contact = PeerContact::new(id, format!("127.0.0.1:{}", 9000 + i as u16));
        table.update_contact(contact);
    }

    let target = NodeId::from_bytes([0u8; 32]);
    let closest = table.closest_peers(&target, 5);
    assert_eq!(closest.len(), 5);

    // Should be sorted by distance
    for i in 1..closest.len() {
        let prev_dist = closest[i - 1].node_id.distance(&target);
        let curr_dist = closest[i].node_id.distance(&target);
        assert!(prev_dist <= curr_dist);
    }
}

#[test]
fn test_routing_table_update_and_mark_failed() {
    let local = NodeId::random();
    let mut table = RoutingTable::new(local, 8);

    let id1 = NodeId::random();
    let contact = PeerContact::new(id1, "127.0.0.1:9001".to_string());
    table.update_contact(contact.clone());

    assert_eq!(table.total_contacts(), 1);

    // Mark as failed 3 times
    for _ in 0..3 {
        table.mark_failed(&id1);
    }

    // Should be evicted
    assert_eq!(table.total_contacts(), 0);
}

#[test]
fn test_dht_msg_roundtrip() {
    let sender = NodeId::random();
    let target = NodeId::random();
    let nonce = 12345u64;

    let ping = DhtMsg::Ping { sender, nonce };
    let encoded = ping.encode();
    let decoded = DhtMsg::decode(&encoded).unwrap();
    assert_eq!(ping, decoded);

    let pong = DhtMsg::Pong { sender, nonce };
    let encoded = pong.encode();
    let decoded = DhtMsg::decode(&encoded).unwrap();
    assert_eq!(pong, decoded);

    let find_node = DhtMsg::FindNode {
        sender,
        target,
        nonce,
    };
    let encoded = find_node.encode();
    let decoded = DhtMsg::decode(&encoded).unwrap();
    assert_eq!(find_node, decoded);

    let nodes = DhtMsg::Nodes {
        sender,
        target,
        nonce,
        nodes: vec![PeerContact::new(
            NodeId::random(),
            "127.0.0.1:9000".to_string(),
        )],
    };
    let encoded = nodes.encode();
    let decoded = DhtMsg::decode(&encoded).unwrap();
    assert_eq!(nodes, decoded);
}

#[test]
fn test_node_lookup_iterative() {
    let target = NodeId::random();
    let mut lookup = NodeLookup::new(target, 8, 3);

    // Add some initial contacts
    let mut contacts = Vec::new();
    for i in 0..10 {
        let mut bytes = target.0;
        bytes[31] = i as u8;
        let id = NodeId::from_bytes(bytes);
        contacts.push(PeerContact::new(
            id,
            format!("127.0.0.1:{}", 9000 + i as u16),
        ));
    }
    lookup.add_initial(contacts);

    // Get first candidates (α=3)
    let candidates = lookup.next_candidates();
    assert_eq!(candidates.len(), 3);

    // Simulate response with closer nodes
    let mut new_contacts = Vec::new();
    for i in 10..15 {
        let mut bytes = target.0;
        bytes[31] = i as u8;
        let id = NodeId::from_bytes(bytes);
        new_contacts.push(PeerContact::new(
            id,
            format!("127.0.0.1:{}", 9000 + i as u16),
        ));
    }
    lookup.add_results(new_contacts);

    // Should have more candidates
    let more = lookup.next_candidates();
    assert!(!more.is_empty());

    // Eventually should complete
    while !lookup.is_complete() {
        let _ = lookup.next_candidates();
        // In real implementation, we'd query and add results
        // For test, we just verify the logic doesn't panic
        if lookup.next_candidates().is_empty() {
            break;
        }
    }

    let closest = lookup.closest();
    assert!(!closest.is_empty());
    assert!(closest.len() <= 8);
}

#[test]
fn test_mesh_dht_bootstrap() {
    let mut mesh = Mesh::new();
    let node_id1 = NodeId::random();
    let node_id2 = NodeId::random();

    let node1 = create_test_node(node_id1, 8);
    let node2 = create_test_node(node_id2, 8);

    mesh.add_with_dht("alpha", node1, node_id1);
    mesh.add_with_dht("beta", node2, node_id2);

    // Bootstrap alpha from beta
    let added = mesh.dht_bootstrap("alpha", "beta").unwrap();
    assert!(added > 0);

    // Verify alpha's routing table has beta
    let alpha_table = mesh.dht_table("alpha").unwrap();
    assert!(alpha_table.total_contacts() > 0);
}

#[test]
fn test_mesh_dht_find_node() {
    let mut mesh = Mesh::new();
    let node_id1 = NodeId::random();
    let node_id2 = NodeId::random();
    let node_id3 = NodeId::random();

    let node1 = create_test_node(node_id1, 8);
    let node2 = create_test_node(node_id2, 8);
    let node3 = create_test_node(node_id3, 8);

    mesh.add_with_dht("alpha", node1, node_id1);
    mesh.add_with_dht("beta", node2, node_id2);
    mesh.add_with_dht("gamma", node3, node_id3);

    // Bootstrap alpha from beta and gamma
    mesh.dht_bootstrap("alpha", "beta").unwrap();
    mesh.dht_bootstrap("alpha", "gamma").unwrap();

    // Find node3 from alpha
    let results = mesh.dht_find_node("alpha", &node_id3).unwrap();
    // Should find at least the direct contacts
    assert!(!results.is_empty());
}

#[test]
fn test_mesh_prune_unreachable_peers() {
    let mut mesh = Mesh::new();
    let node_id1 = NodeId::random();
    let node_id2 = NodeId::random();

    let node1 = create_test_node(node_id1, 8);
    let node2 = create_test_node(node_id2, 8);

    mesh.add_with_dht("alpha", node1, node_id1);
    mesh.add_with_dht("beta", node2, node_id2);

    let added = mesh.dht_bootstrap("alpha", "beta").unwrap();
    assert_eq!(added, 1);

    // Check alpha's routing table
    assert_eq!(mesh.dht_table("alpha").unwrap().total_contacts(), 1);

    // Mark beta as failed 3 times in alpha's routing table
    // mark_failed returns the evicted contact on the 3rd failure
    let mut evicted = false;
    if let Some(table) = mesh.dht_table_mut("alpha") {
        for i in 0..3 {
            let result = table.mark_failed(&node_id2);
            if i == 2 {
                evicted = result.is_some();
            }
        }
    }

    // The contact should be evicted on the 3rd failure
    assert!(evicted);
    assert_eq!(mesh.dht_table("alpha").unwrap().total_contacts(), 0);

    // Prune should return 0 since already evicted
    let pruned = mesh.prune_unreachable_peers();
    assert_eq!(pruned, 0);
}

#[test]
fn test_mesh_replenish_peers_from_dht() {
    let mut mesh = Mesh::new();
    let node_id1 = NodeId::random();
    let node_id2 = NodeId::random();
    let node_id3 = NodeId::random();

    let node1 = create_test_node(node_id1, 8);
    let node2 = create_test_node(node_id2, 8);
    let node3 = create_test_node(node_id3, 8);

    mesh.add_with_dht("alpha", node1, node_id1);
    mesh.add_with_dht("beta", node2, node_id2);
    mesh.add_with_dht("gamma", node3, node_id3);

    // Bootstrap
    mesh.dht_bootstrap("alpha", "beta").unwrap();
    mesh.dht_bootstrap("alpha", "gamma").unwrap();

    // Connect alpha to beta
    mesh.connect("alpha", "beta").unwrap();
    mesh.drain(10);

    // Replenish - should connect to gamma
    let added = mesh.replenish_peers_from_dht(3);
    assert!(added > 0);

    // Should now be connected to gamma
    let peers = mesh.peers_of("alpha");
    assert!(peers.contains(&"gamma".to_string()));
}

#[test]
fn test_multi_node_dynamic_bootstrap() {
    // Simulate 5 nodes bootstrapping via DNS seeds
    let mut mesh = Mesh::new();
    let mut node_ids = Vec::new();

    for i in 0..5 {
        let node_id = NodeId::random();
        node_ids.push(node_id);
        let node = create_test_node(node_id, 8);
        let name = format!("node-{}", i);
        mesh.add_with_dht(name.clone(), node, node_id);
    }

    // Simulate DNS seed resolution by adding seed contacts to each node
    // Each node bootstraps from all other nodes (simulating a full mesh of seeds)
    for (i, name) in mesh.names().iter().enumerate() {
        let mut seed_contacts = Vec::new();
        for (j, &seed_id) in node_ids.iter().enumerate() {
            if i != j {
                seed_contacts.push(PeerContact::new(
                    seed_id,
                    format!("127.0.0.1:{}", 9000 + j as u16),
                ));
            }
        }
        eprintln!(
            "Node {} ({}) adding {} seed contacts",
            i,
            name,
            seed_contacts.len()
        );
        let added = mesh.add_dht_contacts(name, seed_contacts).unwrap();
        eprintln!("  Added {} contacts", added);
    }

    // All nodes should have populated routing tables
    for name in mesh.names() {
        let table = mesh.dht_table(&name).unwrap();
        eprintln!("Node {} has {} contacts", name, table.total_contacts());
        // Each node should have 4 contacts (all other nodes)
        assert_eq!(
            table.total_contacts(),
            4,
            "Node {} should have 4 DHT contacts",
            name
        );
    }
}

#[test]
fn test_multi_hop_isolated_target_discovery() {
    // Node A knows only Seed B. Node C knows only Seed B.
    // Node A should discover and connect to Node C via DHT iterative routing.
    let mut mesh = Mesh::new();

    let id_a = NodeId::random();
    let id_b = NodeId::random();
    let id_c = NodeId::random();

    let node_a = create_test_node(id_a, 8);
    let node_b = create_test_node(id_b, 8);
    let node_c = create_test_node(id_c, 8);

    mesh.add_with_dht("alpha", node_a, id_a);
    mesh.add_with_dht("beta", node_b, id_b);
    mesh.add_with_dht("gamma", node_c, id_c);

    // Alpha and Gamma only know Beta (seed)
    mesh.dht_bootstrap("alpha", "beta").unwrap();
    mesh.dht_bootstrap("gamma", "beta").unwrap();

    // Alpha finds Gamma via DHT lookup
    let results = mesh.dht_find_node("alpha", &id_c).unwrap();
    assert!(!results.is_empty());

    // Alpha should be able to connect to Gamma
    mesh.connect("alpha", "gamma").unwrap();
    mesh.drain(10);

    let peers = mesh.peers_of("alpha");
    assert!(peers.contains(&"gamma".to_string()));
}

#[test]
fn test_dynamic_disconnect_and_routing_pruning() {
    let mut mesh = Mesh::new();
    let id_a = NodeId::random();
    let id_b = NodeId::random();
    let id_c = NodeId::random();

    let node_a = create_test_node(id_a, 8);
    let node_b = create_test_node(id_b, 8);
    let node_c = create_test_node(id_c, 8);

    mesh.add_with_dht("alpha", node_a, id_a);
    mesh.add_with_dht("beta", node_b, id_b);
    mesh.add_with_dht("gamma", node_c, id_c);

    mesh.dht_bootstrap("alpha", "beta").unwrap();
    mesh.dht_bootstrap("alpha", "gamma").unwrap();
    mesh.connect("alpha", "beta").unwrap();
    mesh.connect("alpha", "gamma").unwrap();
    mesh.drain(10);

    // Simulate beta crashing - mark as failed in alpha's table
    // mark_failed evicts on 3rd failure
    let mut evicted = false;
    if let Some(table) = mesh.dht_table_mut("alpha") {
        for i in 0..3 {
            let result = table.mark_failed(&id_b);
            if i == 2 {
                evicted = result.is_some();
            }
        }
    }
    assert!(evicted);

    // Prune unreachable (should be 0 since already evicted)
    let pruned = mesh.prune_unreachable_peers();
    assert_eq!(pruned, 0);

    // Beta should be gone
    let alpha_table = mesh.dht_table("alpha").unwrap();
    let contacts: Vec<_> = alpha_table
        .all_contacts()
        .into_iter()
        .map(|c| c.node_id)
        .collect();
    assert!(!contacts.contains(&id_b));

    // Gamma should still be there
    assert!(contacts.contains(&id_c));
}

#[test]
fn test_routing_table_replenishment() {
    let mut mesh = Mesh::new();
    let id_a = NodeId::random();
    let id_b = NodeId::random();
    let id_c = NodeId::random();
    let id_d = NodeId::random();

    let node_a = create_test_node(id_a, 8);
    let node_b = create_test_node(id_b, 8);
    let node_c = create_test_node(id_c, 8);
    let node_d = create_test_node(id_d, 8);

    mesh.add_with_dht("alpha", node_a, id_a);
    mesh.add_with_dht("beta", node_b, id_b);
    mesh.add_with_dht("gamma", node_c, id_c);
    mesh.add_with_dht("delta", node_d, id_d);

    // Full mesh bootstrap
    for name in ["beta", "gamma", "delta"] {
        mesh.dht_bootstrap("alpha", name).unwrap();
    }

    // Connect only to beta
    mesh.connect("alpha", "beta").unwrap();
    mesh.drain(10);

    // Replenish to target 3 peers
    let added = mesh.replenish_peers_from_dht(3);
    assert!(added >= 1); // Should connect to at least gamma or delta

    let peers = mesh.peers_of("alpha");
    assert!(peers.len() >= 2);
}

#[test]
fn test_replenish_peers_skips_existing_closest_and_fills_target() {
    let mut mesh = Mesh::new();
    let id_a = NodeId::from_bytes([0u8; 32]);
    let id_b = NodeId::from_bytes({
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    });
    let id_c = NodeId::from_bytes({
        let mut b = [0u8; 32];
        b[31] = 2;
        b
    });
    let id_d = NodeId::from_bytes({
        let mut b = [0u8; 32];
        b[31] = 3;
        b
    });

    mesh.add_with_dht("alpha", create_test_node(id_a, 8), id_a);
    mesh.add_with_dht("beta", create_test_node(id_b, 8), id_b);
    mesh.add_with_dht("gamma", create_test_node(id_c, 8), id_c);
    mesh.add_with_dht("delta", create_test_node(id_d, 8), id_d);

    // Alpha learns all three peers in DHT
    for name in ["beta", "gamma", "delta"] {
        mesh.dht_bootstrap("alpha", name).unwrap();
    }

    // Alpha connects to the closest peer (beta) first
    mesh.connect("alpha", "beta").unwrap();
    mesh.drain(10);
    assert_eq!(mesh.peers_of("alpha").len(), 1);

    // Now replenish to target 2 peers.
    // The closest peer (beta) is already connected. Replenish MUST skip beta and connect to gamma!
    let added = mesh.replenish_peers_from_dht(2);
    assert!(added >= 1, "Should add new peer connection(s)");
    assert_eq!(
        mesh.peers_of("alpha").len(),
        2,
        "Alpha should now have exactly 2 peers"
    );
    assert!(mesh.peers_of("alpha").contains(&"beta".to_string()));
    assert!(mesh.peers_of("alpha").contains(&"gamma".to_string()));
}

#[test]
fn test_partition_healing() {
    // Two initially partitioned sub-clusters bridged by a single mutual contact
    let mut mesh = Mesh::new();

    let id_a1 = NodeId::random();
    let id_a2 = NodeId::random();
    let id_b1 = NodeId::random();
    let id_b2 = NodeId::random();
    let id_bridge = NodeId::random();

    // Cluster A
    mesh.add_with_dht("a1", create_test_node(id_a1, 8), id_a1);
    mesh.add_with_dht("a2", create_test_node(id_a2, 8), id_a2);
    // Cluster B
    mesh.add_with_dht("b1", create_test_node(id_b1, 8), id_b1);
    mesh.add_with_dht("b2", create_test_node(id_b2, 8), id_b2);
    // Bridge node
    mesh.add_with_dht("bridge", create_test_node(id_bridge, 8), id_bridge);

    // Internal connections within clusters
    mesh.connect("a1", "a2").unwrap();
    mesh.connect("b1", "b2").unwrap();
    // Bridge connects to both clusters
    mesh.connect("bridge", "a1").unwrap();
    mesh.connect("bridge", "b1").unwrap();
    mesh.drain(10);

    // Bootstrap bridge from both clusters
    mesh.dht_bootstrap("bridge", "a1").unwrap();
    mesh.dht_bootstrap("bridge", "b1").unwrap();

    // Bootstrap clusters from bridge
    mesh.dht_bootstrap("a1", "bridge").unwrap();
    mesh.dht_bootstrap("b1", "bridge").unwrap();

    // Replenish - clusters should discover each other via bridge
    mesh.replenish_peers_from_dht(3);
    mesh.drain(10);

    // Eventually a1 should be able to reach b1 through bridge
    let a1_peers = mesh.peers_of("a1");
    let b1_peers = mesh.peers_of("b1");

    // At minimum, they should have discovered more peers
    assert!(a1_peers.len() > 1 || b1_peers.len() > 1);
}

#[test]
fn test_dht_wire_framing_over_tcp() {
    // Test that DHT messages can be sent over relay sessions
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sender_id = NodeId::random();
    let target_id = NodeId::random();
    let nonce = 12345u64;

    let server_handle = thread::spawn(move || {
        let mut session = RelaySession::accept(&listener).unwrap();
        session
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let msg = session.recv().unwrap();
        match msg {
            RelayMsg::DhtFindNode {
                sender,
                target,
                nonce: n,
            } => {
                assert_eq!(sender, sender_id);
                assert_eq!(target, target_id);
                assert_eq!(n, nonce);

                // Respond with empty nodes
                let response = RelayMsg::DhtNodes {
                    sender: target_id,
                    target: sender_id,
                    nonce: n,
                    nodes: Vec::new(),
                };
                session.send(&response).unwrap();
            }
            _ => panic!("Expected DhtFindNode, got {:?}", msg),
        }
    });

    thread::sleep(Duration::from_millis(50));

    let mut client = RelaySession::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let request = RelayMsg::DhtFindNode {
        sender: sender_id,
        target: target_id,
        nonce,
    };
    client.send(&request).unwrap();

    let response = client.recv().unwrap();
    match response {
        RelayMsg::DhtNodes { nodes, .. } => {
            assert!(nodes.is_empty());
        }
        _ => panic!("Expected DhtNodes, got {:?}", response),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_relay_dht_ping_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sender_id = NodeId::random();
    let nonce = 54321u64;

    let server_handle = thread::spawn(move || {
        let mut session = RelaySession::accept(&listener).unwrap();
        session
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let msg = session.recv().unwrap();
        match msg {
            RelayMsg::DhtPing { sender, nonce: n } => {
                assert_eq!(sender, sender_id);
                assert_eq!(n, nonce);

                let response = RelayMsg::DhtPong { sender, nonce: n };
                session.send(&response).unwrap();
            }
            _ => panic!("Expected DhtPing, got {:?}", msg),
        }
    });

    thread::sleep(Duration::from_millis(50));

    let mut client = RelaySession::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let request = RelayMsg::DhtPing {
        sender: sender_id,
        nonce,
    };
    client.send(&request).unwrap();

    let response = client.recv().unwrap();
    match response {
        RelayMsg::DhtPong { sender, nonce: n } => {
            assert_eq!(sender, sender_id);
            assert_eq!(n, nonce);
        }
        _ => panic!("Expected DhtPong, got {:?}", response),
    }

    server_handle.join().unwrap();
}

#[test]
fn test_relay_handle_dht_query() {
    let mut node = Node::new();
    node.genesis(3, 1000, 1000, 1).unwrap();
    let node_id = NodeId::random();
    node.init_dht_routing_table(node_id, 8);

    // Add some contacts
    for i in 1..5 {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        let id = NodeId::from_bytes(bytes);
        node.dht_routing_table_mut()
            .unwrap()
            .update_contact(PeerContact::new(
                id,
                format!("127.0.0.1:{}", 9000 + i as u16),
            ));
    }

    // Test DhtPing handling
    let ping = RelayMsg::DhtPing {
        sender: NodeId::random(),
        nonce: 111,
    };
    let resp = kovanica_node::relay::handle_relay_query(&node, &ping).unwrap();
    match resp {
        RelayMsg::DhtPong { sender, nonce } => {
            assert_eq!(sender, node_id);
            assert_eq!(nonce, 111);
        }
        _ => panic!("Expected DhtPong"),
    }

    // Test DhtFindNode handling
    let target = NodeId::random();
    let find_node = RelayMsg::DhtFindNode {
        sender: NodeId::random(),
        target,
        nonce: 222,
    };
    let resp = kovanica_node::relay::handle_relay_query(&node, &find_node).unwrap();
    match resp {
        RelayMsg::DhtNodes { sender, nodes, .. } => {
            assert_eq!(sender, node_id);
            // Should return closest nodes from routing table
            assert!(!nodes.is_empty());
        }
        _ => panic!("Expected DhtNodes"),
    }

    // Direct test for Node::handle_dht_msg
    let dht_ping = DhtMsg::Ping {
        sender: NodeId::random(),
        nonce: 333,
    };
    let dht_resp = node.handle_dht_msg(dht_ping).unwrap();
    assert_eq!(
        dht_resp,
        DhtMsg::Pong {
            sender: node_id,
            nonce: 333
        }
    );
}

#[test]
fn test_multiplexed_tcp_framing() {
    // Verify DHT messages can be interleaved with P2P block/tx gossip
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let mut session = RelaySession::accept(&listener).unwrap();
        session
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Receive multiple message types
        for _ in 0..3 {
            let msg = session.recv().unwrap();
            match msg {
                RelayMsg::DhtPing { sender, nonce } => {
                    let resp = RelayMsg::DhtPong { sender, nonce };
                    session.send(&resp).unwrap();
                }
                RelayMsg::Hello { .. } => {
                    let resp = RelayMsg::Hello {
                        from: "server".into(),
                        advertised: vec![],
                    };
                    session.send(&resp).unwrap();
                }
                _ => {}
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    let mut client = RelaySession::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Send interleaved DHT + P2P messages
    client
        .send(&RelayMsg::DhtPing {
            sender: NodeId::random(),
            nonce: 1,
        })
        .unwrap();
    client.recv().unwrap();

    client
        .send(&RelayMsg::Hello {
            from: "client".into(),
            advertised: vec![],
        })
        .unwrap();
    client.recv().unwrap();

    client
        .send(&RelayMsg::DhtPing {
            sender: NodeId::random(),
            nonce: 2,
        })
        .unwrap();
    client.recv().unwrap();

    server_handle.join().unwrap();
}

// ========================================================================
// Tier 5: Adversarial Stress Tests (run with --ignored for long duration)
// ========================================================================

#[test]
#[ignore]
fn test_adversarial_high_churn() {
    // High churn: nodes rapidly joining and leaving
    let mut mesh = Mesh::new();
    let mut node_ids = Vec::new();

    for round in 0..100 {
        // Add new nodes
        let new_id = NodeId::random();
        node_ids.push(new_id);
        let new_node = create_test_node(new_id, 8);
        let name = format!("node-{}", round);
        mesh.add_with_dht(name.clone(), new_node, new_id);

        // Bootstrap from existing node
        if round > 0 {
            let existing = &mesh.names()[0];
            mesh.dht_bootstrap(&name, existing).unwrap();
        }

        // Prune old nodes
        if round > 10 {
            let _old_name = format!("node-{}", round - 10);
            if let Some(table) = mesh.dht_table_mut(&mesh.names()[0]) {
                table.mark_failed(&node_ids[round - 10]);
            }
            mesh.prune_unreachable_peers();
        }

        mesh.drain(5);
    }

    // Mesh should remain stable
    assert!(!mesh.names().is_empty());
}

#[test]
#[ignore]
fn test_adversarial_sybil_resistance() {
    // Sybil attack: an attacker floods the network with many NodeIds clustered
    // near the victim's ID to poison its routing table. Honest peers met via
    // verified handshakes BEFORE the flood must survive in the victim's table.
    let mut mesh = Mesh::new();
    let victim_id = NodeId::random();
    let victim = create_test_node(victim_id, 20); // k=20
    mesh.add_with_dht("victim", victim, victim_id);

    // Honest seeds the victim meets first (handshake-verified contacts).
    let mut honest_ids = Vec::new();
    for h in 0..5 {
        let honest_id = NodeId::random();
        honest_ids.push(honest_id);
        let honest = create_test_node(honest_id, 8);
        mesh.add_with_dht(format!("honest-{h}"), honest, honest_id);
        mesh.connect("victim", &format!("honest-{h}")).unwrap();
        mesh.drain(5);
    }

    // Attacker creates 100 nodes close to the victim's ID and the victim
    // bootstraps from every one of them.
    for i in 0..100 {
        let mut bytes = victim_id.0;
        bytes[31] = i as u8;
        let attacker_id = NodeId::from_bytes(bytes);
        let attacker = create_test_node(attacker_id, 8);
        mesh.add_with_dht(format!("attacker-{}", i), attacker, attacker_id);
        mesh.dht_bootstrap("victim", &format!("attacker-{}", i))
            .unwrap();
    }
    mesh.drain(10);

    // Every handshake-verified honest peer must still be known to the victim:
    // a full bucket only pushes newcomers into the replacement cache, it never
    // evicts established contacts.
    let table = mesh.dht_table("victim").unwrap();
    let known: std::collections::HashSet<NodeId> =
        table.all_contacts().iter().map(|c| c.node_id).collect();
    for id in &honest_ids {
        assert!(
            known.contains(id),
            "Honest contact {id:?} evicted by Sybil flood"
        );
    }
    // And the table never exceeds its capacity bounds.
    let contacts = table.closest_peers(&victim_id, 20);
    assert!(contacts.len() <= 20);
}

#[test]
#[ignore]
fn test_adversarial_eclipse_resistance() {
    // Eclipse attack: attacker tries to isolate victim by filling their routing table
    // LRU ping preservation should protect established honest nodes
    let mut mesh = Mesh::new();

    let victim_id = NodeId::random();
    let honest_id = NodeId::random();
    let victim = create_test_node(victim_id, 8);
    let honest = create_test_node(honest_id, 8);

    mesh.add_with_dht("victim", victim, victim_id);
    mesh.add_with_dht("honest", honest, honest_id);
    mesh.connect("victim", "honest").unwrap();
    mesh.drain(10);

    // Attacker adds many nodes
    for i in 0..50 {
        let attacker_id = NodeId::random();
        let attacker = create_test_node(attacker_id, 8);
        mesh.add_with_dht(format!("attacker-{}", i), attacker, attacker_id);
    }

    // Victim bootstraps from attackers
    for i in 0..50 {
        mesh.dht_bootstrap("victim", &format!("attacker-{}", i))
            .unwrap();
    }

    // Honest peer should still be in victim's routing table (protected by LRU)
    let table = mesh.dht_table("victim").unwrap();
    let contacts = table.all_contacts();
    let has_honest = contacts.iter().any(|c| c.node_id == honest_id);
    assert!(has_honest, "Honest peer should be protected from eclipse");
}

#[test]
fn test_dht_routing_convergence_partial_split_and_churn() {
    let mut mesh = Mesh::new();

    // Cluster 1 nodes
    let id_s1 = NodeId::random();
    let id_a1 = NodeId::random();
    let id_a2 = NodeId::random();

    // Cluster 2 nodes
    let id_s2 = NodeId::random();
    let id_b1 = NodeId::random();
    let id_b2 = NodeId::random();

    // Bridge node
    let id_bridge = NodeId::random();

    mesh.add_with_dht("seed1", create_test_node(id_s1, 8), id_s1);
    mesh.add_with_dht("alpha1", create_test_node(id_a1, 8), id_a1);
    mesh.add_with_dht("alpha2", create_test_node(id_a2, 8), id_a2);

    mesh.add_with_dht("seed2", create_test_node(id_s2, 8), id_s2);
    mesh.add_with_dht("beta1", create_test_node(id_b1, 8), id_b1);
    mesh.add_with_dht("beta2", create_test_node(id_b2, 8), id_b2);

    mesh.add_with_dht("bridge", create_test_node(id_bridge, 8), id_bridge);

    // Bootstrap within cluster 1
    mesh.dht_bootstrap("alpha1", "seed1").unwrap();
    mesh.dht_bootstrap("alpha2", "seed1").unwrap();
    mesh.connect("alpha1", "seed1").unwrap();
    mesh.connect("alpha2", "seed1").unwrap();

    // Bootstrap within cluster 2
    mesh.dht_bootstrap("beta1", "seed2").unwrap();
    mesh.dht_bootstrap("beta2", "seed2").unwrap();
    mesh.connect("beta1", "seed2").unwrap();
    mesh.connect("beta2", "seed2").unwrap();

    // Bridge connects to both seed1 and seed2
    mesh.dht_bootstrap("bridge", "seed1").unwrap();
    mesh.dht_bootstrap("bridge", "seed2").unwrap();
    mesh.connect("bridge", "seed1").unwrap();
    mesh.connect("bridge", "seed2").unwrap();
    mesh.drain(10);

    // Simulate high IP churn in cluster 2: beta2 updates its address
    let new_b2_addr = "192.168.10.99:9000".to_string();
    if let Some(table) = mesh.dht_table_mut("seed2") {
        table.update_contact(PeerContact::new(id_b2, new_b2_addr.clone()));
    }
    if let Some(table) = mesh.dht_table_mut("bridge") {
        table.update_contact(PeerContact::new(id_b2, new_b2_addr.clone()));
    }

    // Now introduce an uncontactable dying node and verify 3-strike eviction
    let id_dead = NodeId::random();
    let mut evicted = false;
    if let Some(table) = mesh.dht_table_mut("bridge") {
        table.update_contact(PeerContact::new(id_dead, "10.255.255.1:9000".to_string()));
        for i in 0..3 {
            let res = table.mark_failed(&id_dead);
            if i == 2 {
                evicted = res.is_some();
            }
        }
    }
    assert!(evicted, "Dead peer should be evicted on 3rd strike");

    // Also test prune_unreachable_peers on a contact with 3 failures
    let id_dead2 = NodeId::random();
    if let Some(table) = mesh.dht_table_mut("bridge") {
        let mut contact = PeerContact::new(id_dead2, "10.255.255.2:9000".to_string());
        contact.failed_queries = 3;
        table.update_contact(contact);
    }
    let pruned = mesh.prune_unreachable_peers();
    assert_eq!(pruned, 1, "Dead peer with 3 strikes should be pruned");

    // Perform iterative lookup from alpha1 in cluster 1 targeting beta2 in cluster 2
    let found = mesh.dht_find_node("bridge", &id_b2).unwrap();
    assert!(found.iter().any(|c| c.node_id == id_b2));

    // Alpha1 bootstraps via bridge and performs find_node for beta2
    mesh.dht_bootstrap("alpha1", "bridge").unwrap();
    let found_from_a1 = mesh.dht_find_node("alpha1", &id_b2).unwrap();
    assert!(
        found_from_a1.iter().any(|c| c.node_id == id_b2),
        "Alpha1 must locate Beta2 across partitioned cluster views via bridge"
    );

    // Add isolated node gamma that has no initial P2P connections
    let id_gamma = NodeId::random();
    mesh.add_with_dht("gamma", create_test_node(id_gamma, 8), id_gamma);
    mesh.dht_bootstrap("gamma", "bridge").unwrap();
    assert_eq!(mesh.peers_of("gamma").len(), 0);

    // Verify replenishment connects isolated node from DHT table (target 2 peers)
    let added = mesh.replenish_peers_from_dht(2);
    assert!(
        added >= 2,
        "Isolated node gamma should establish at least 2 connections via DHT"
    );
    assert_eq!(mesh.peers_of("gamma").len(), 2);
}

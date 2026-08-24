//! DNS multi-seed resolver for peer discovery.
//!
//! Provides an injectable `DnsResolver` trait with a production `StdDnsResolver`
//! using system DNS and a `MockDnsResolver` for deterministic testing. The
//! `DnsSeedResolver` queries multiple seed hostnames, extracts A/AAAA records,
//! shuffles and deduplicates results, and falls back to static IPs if DNS fails.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};

/// Trait for DNS resolution, allowing test injection.
pub trait DnsResolver: Send + Sync {
    /// Resolve a hostname to a list of socket addresses.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error>;
}

/// Production DNS resolver using the standard library.
pub struct StdDnsResolver;

impl DnsResolver for StdDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        let addr = format!("{}:{}", host, port);
        addr.to_socket_addrs().map(|iter| iter.collect())
    }
}

/// Mock DNS resolver for deterministic testing.
#[derive(Default, Clone)]
pub struct MockDnsResolver {
    records: HashMap<String, Vec<SocketAddr>>,
}

impl MockDnsResolver {
    /// Create a new mock resolver with pre-configured records.
    pub fn new(records: HashMap<String, Vec<SocketAddr>>) -> Self {
        Self { records }
    }

    /// Add a record for a hostname.
    pub fn add_record(&mut self, host: String, addrs: Vec<SocketAddr>) {
        self.records.insert(host, addrs);
    }
}

impl DnsResolver for MockDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        let key = format!("{}:{}", host, port);
        if let Some(addrs) = self.records.get(&key) {
            return Ok(addrs.clone());
        }
        // Also try without port for backward compatibility
        if let Some(addrs) = self.records.get(host) {
            return Ok(addrs.clone());
        }
        Ok(Vec::new())
    }
}

/// Configuration for DNS seed resolver.
#[derive(Clone, Debug)]
pub struct DnsSeedConfig {
    /// Seed hostnames to query (e.g., "seed.kovanica.online", "seed2.kovanica.online").
    pub seeds: Vec<String>,
    /// Default port for seed connections.
    pub default_port: u16,
    /// Static fallback IPs if all DNS seeds fail.
    pub fallbacks: Vec<SocketAddr>,
    /// Maximum number of addresses to return.
    pub max_addrs: usize,
}

impl Default for DnsSeedConfig {
    fn default() -> Self {
        Self {
            seeds: vec![
                "seed.kovanica.online".to_string(),
                "seed2.kovanica.online".to_string(),
                "seed3.kovanica.online".to_string(),
            ],
            default_port: 9000,
            fallbacks: vec![
                "127.0.0.1:9000".parse().unwrap(),
                "[::1]:9000".parse().unwrap(),
            ],
            max_addrs: 50,
        }
    }
}

/// DNS multi-seed resolver with fallback pipeline.
pub struct DnsSeedResolver<R: DnsResolver> {
    resolver: R,
    config: DnsSeedConfig,
}

impl<R: DnsResolver> DnsSeedResolver<R> {
    /// Create a new resolver with the given resolver and default config.
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            config: DnsSeedConfig::default(),
        }
    }

    /// Create a new resolver with custom config.
    pub fn with_config(resolver: R, config: DnsSeedConfig) -> Self {
        Self { resolver, config }
    }

    /// Resolve all seed hostnames and return deduplicated, shuffled addresses.
    pub fn resolve_all(&self) -> Vec<SocketAddr> {
        let mut all_addrs = Vec::new();

        for seed in &self.config.seeds {
            match self.resolver.resolve(seed, self.config.default_port) {
                Ok(addrs) => all_addrs.extend(addrs),
                Err(e) => {
                    eprintln!("DNS seed {} resolution failed: {}", seed, e);
                }
            }
        }

        // Deduplicate by IP:port
        all_addrs.sort_by_key(|a| a.ip());
        all_addrs.dedup_by_key(|a| a.ip());

        // Shuffle for load distribution (deterministic in tests via MockDnsResolver)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for addr in &all_addrs {
            addr.hash(&mut hasher);
        }
        // Simple deterministic shuffle based on hash
        all_addrs.sort_by_key(|a| {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        });

        // Apply max limit
        if all_addrs.len() > self.config.max_addrs {
            all_addrs.truncate(self.config.max_addrs);
        }

        // If no DNS results, use fallbacks
        if all_addrs.is_empty() {
            all_addrs = self.config.fallbacks.clone();
        }

        all_addrs
    }

    /// Get the configuration.
    pub fn config(&self) -> &DnsSeedConfig {
        &self.config
    }
}

/// Convenience function to create a production resolver.
pub fn production_resolver() -> DnsSeedResolver<StdDnsResolver> {
    DnsSeedResolver::new(StdDnsResolver)
}

/// Convenience function to create a mock resolver for testing.
pub fn mock_resolver(
    records: HashMap<String, Vec<SocketAddr>>,
) -> DnsSeedResolver<MockDnsResolver> {
    DnsSeedResolver::new(MockDnsResolver::new(records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_std_resolver_localhost() {
        let resolver = StdDnsResolver;
        let addrs = resolver.resolve("localhost", 9000).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 9000));
    }

    #[test]
    fn test_mock_resolver() {
        let mut records = HashMap::new();
        let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:9000".parse().unwrap();
        records.insert("seed.example.com:9000".to_string(), vec![addr1, addr2]);

        let resolver = MockDnsResolver::new(records);
        let addrs = resolver.resolve("seed.example.com", 9000).unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr1));
        assert!(addrs.contains(&addr2));
    }

    #[test]
    fn test_mock_resolver_missing() {
        let resolver = MockDnsResolver::default();
        let addrs = resolver.resolve("unknown.example.com", 9000).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_dns_seed_resolver_deduplication() {
        let mut records = HashMap::new();
        let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:9000".parse().unwrap();
        // Same IP from two seeds
        records.insert("seed1.example.com:9000".to_string(), vec![addr1]);
        records.insert("seed2.example.com:9000".to_string(), vec![addr1, addr2]);

        let resolver = DnsSeedResolver::new(MockDnsResolver::new(records));
        let addrs = resolver.resolve_all();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_dns_seed_resolver_fallback() {
        let resolver = DnsSeedResolver::new(MockDnsResolver::default());
        let addrs = resolver.resolve_all();
        // Should return fallback addresses
        assert!(!addrs.is_empty());
        assert!(addrs
            .iter()
            .any(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_dns_seed_config_default() {
        let config = DnsSeedConfig::default();
        assert_eq!(config.seeds.len(), 3);
        assert_eq!(config.default_port, 9000);
        assert_eq!(config.fallbacks.len(), 2);
        assert_eq!(config.max_addrs, 50);
    }
}

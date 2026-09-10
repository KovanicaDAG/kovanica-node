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

/// Parse hostname/IP and port from a seed host string that may include explicit ports
/// or IPv6 bracket formatting.
pub(crate) fn parse_host_port(host: &str, default_port: u16) -> (String, u16) {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return (String::new(), default_port);
    }

    // Bracketed IPv6: "[::1]:9000" or "[::1]"
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((ipv6, port_str)) = rest.split_once("]:") {
            let port = port_str.parse::<u16>().unwrap_or(default_port);
            return (ipv6.to_string(), port);
        } else if let Some(ipv6) = rest.strip_suffix(']') {
            return (ipv6.to_string(), default_port);
        }
    }

    // Direct IP address without brackets (IPv4 e.g. "127.0.0.1" or IPv6 e.g. "2001:db8::1" or "::1")
    if let Ok(_ip) = trimmed.parse::<std::net::IpAddr>() {
        return (trimmed.to_string(), default_port);
    }

    // Host with explicit port e.g. "seed.kovanica.online:9000" or "127.0.0.1:9000"
    if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':') {
            if p.is_empty() {
                return (h.to_string(), default_port);
            }
            if let Ok(port_num) = p.parse::<u16>() {
                return (h.to_string(), port_num);
            }
        }
    }

    // Default: raw hostname (e.g. "seed.kovanica.online", "localhost")
    (trimmed.to_string(), default_port)
}

/// Production DNS resolver using the standard library.
pub struct StdDnsResolver;

impl DnsResolver for StdDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        let (h, p) = parse_host_port(host, port);
        (h.as_str(), p).to_socket_addrs().map(|iter| iter.collect())
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
        let (h, p) = parse_host_port(host, port);
        if let Some(addrs) = self.records.get(host) {
            return Ok(addrs.clone());
        }
        let key_normalized = format!("{}:{}", h, p);
        if let Some(addrs) = self.records.get(&key_normalized) {
            return Ok(addrs.clone());
        }
        if h.contains(':') {
            let key_bracketed = format!("[{}]:{}", h, p);
            if let Some(addrs) = self.records.get(&key_bracketed) {
                return Ok(addrs.clone());
            }
            let key_bracketed_host = format!("[{}]", h);
            if let Some(addrs) = self.records.get(&key_bracketed_host) {
                return Ok(addrs.clone());
            }
        }
        if let Some(addrs) = self.records.get(&h) {
            return Ok(addrs.clone());
        }
        let key_default = format!("{}:{}", host, port);
        if let Some(addrs) = self.records.get(&key_default) {
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
        all_addrs.sort_by_key(|a| (a.ip(), a.port()));
        all_addrs.dedup_by_key(|a| (a.ip(), a.port()));

        // Shuffle for load distribution (deterministic in tests via MockDnsResolver)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        all_addrs.sort_by_key(|a| {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        });

        // If no DNS results, use fallbacks
        if all_addrs.is_empty() {
            all_addrs = self.config.fallbacks.clone();
        }

        // Apply max limit
        if all_addrs.len() > self.config.max_addrs {
            all_addrs.truncate(self.config.max_addrs);
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
    fn test_std_resolver_with_port() {
        let resolver = StdDnsResolver;
        let addrs = resolver.resolve("127.0.0.1:9000", 9000).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 9000));
    }

    #[test]
    fn test_mock_resolver_with_port_in_query() {
        let mut records = HashMap::new();
        let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        records.insert("seed.example.com".to_string(), vec![addr1]);

        let resolver = MockDnsResolver::new(records);
        let addrs = resolver.resolve("seed.example.com:9000", 9000).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr1);
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("seed.example.com", 9000),
            ("seed.example.com".into(), 9000)
        );
        assert_eq!(
            parse_host_port("seed.example.com:8000", 9000),
            ("seed.example.com".into(), 8000)
        );
        assert_eq!(
            parse_host_port("127.0.0.1", 9000),
            ("127.0.0.1".into(), 9000)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:8080", 9000),
            ("127.0.0.1".into(), 8080)
        );
        assert_eq!(parse_host_port("::1", 9000), ("::1".into(), 9000));
        assert_eq!(parse_host_port("[::1]", 9000), ("::1".into(), 9000));
        assert_eq!(parse_host_port("[::1]:8080", 9000), ("::1".into(), 8080));
        assert_eq!(
            parse_host_port("2001:db8::1", 9000),
            ("2001:db8::1".into(), 9000)
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]:7000", 9000),
            ("2001:db8::1".into(), 7000)
        );
    }

    #[test]
    fn test_std_resolver_ipv6_bracketed_with_port() {
        let resolver = StdDnsResolver;
        let addrs = resolver.resolve("[::1]:9000", 9000).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 9000 && a.is_ipv6()));
    }

    #[test]
    fn test_std_resolver_ipv6_raw() {
        let resolver = StdDnsResolver;
        let addrs = resolver.resolve("::1", 9000).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.port() == 9000 && a.is_ipv6()));
    }

    #[test]
    fn test_dns_seed_config_default() {
        let config = DnsSeedConfig::default();
        assert_eq!(config.seeds.len(), 3);
        assert_eq!(config.default_port, 9000);
        assert_eq!(config.fallbacks.len(), 2);
        assert_eq!(config.max_addrs, 50);
    }

    #[test]
    fn test_parse_host_port_trailing_colon() {
        assert_eq!(
            parse_host_port("seed.example.com:", 9000),
            ("seed.example.com".into(), 9000)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:", 9000),
            ("127.0.0.1".into(), 9000)
        );
    }

    #[test]
    fn test_mock_resolver_ipv6_bracketed_record() {
        let mut records = HashMap::new();
        let addr1: SocketAddr = "[::1]:9000".parse().unwrap();
        records.insert("[::1]:9000".to_string(), vec![addr1]);

        let resolver = MockDnsResolver::new(records);
        let addrs = resolver.resolve("::1", 9000).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr1);
    }
}

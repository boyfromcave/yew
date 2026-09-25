//! Server configuration and channel construction (plan §3.5): TLS (`rustls`, system roots)
//! everywhere but regtest, where `plain` selects `http://`; an optional pinned certificate
//! (`ca_pem`) replaces the system roots; the default endpoint table (`docs/release.md`).

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use super::NetError;
use crate::params::Network;

/// A default endpoint the app offers (plan §3.5, §8 Q4; `docs/release.md` "Default endpoints").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultServer {
    /// `host:port`.
    pub address: &'static str,
    /// Plain HTTP/2 (regtest only).
    pub plain: bool,
}

/// The default endpoints per network. **Mainnet is empty on purpose**: the owner supplies the
/// public `lightwalletd-dd` endpoints (plan §8 Q4, `docs/release.md` §4) and nothing ships
/// until then — the app then asks for a server instead of trusting one nobody has vetted.
/// Testnet is empty for the same reason until the ≥ 4-week testnet run has a host. Regtest
/// is the local devnet.
pub fn default_servers(network: Network) -> &'static [DefaultServer] {
    match network {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[DefaultServer {
            address: "127.0.0.1:9067",
            plain: true,
        }],
    }
}

/// A light-client server endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    /// Host name or IP.
    pub host: String,
    /// TCP port (lightwalletd's default is 9067).
    pub port: u16,
    /// `true` for plain HTTP/2 without TLS (regtest only; [`Server::parse_for`] refuses it
    /// elsewhere, and so does every caller through it).
    pub plain: bool,
    /// A pinned certificate (PEM, the server's own self-signed certificate or its private
    /// CA): when set it is the *only* trust anchor, the system roots are not consulted. `None`
    /// = system roots. Ignored when `plain`.
    pub ca_pem: Option<String>,
}

impl Server {
    /// Parse `host:port`. The host is a DNS name, an IPv4 address or a bracketed IPv6 address:
    /// anything that could reshape the URI (`/`, `?`, `#`, `@`, whitespace) is refused.
    pub fn parse(s: &str, plain: bool) -> Result<Server, String> {
        let s = s.trim();
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("expected host:port, got {s}"))?;
        let port: u16 = port.parse().map_err(|_| format!("bad port in {s}"))?;
        if host.is_empty() {
            return Err(format!("empty host in {s}"));
        }
        let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        let ok = match bare {
            Some(v6) => !v6.is_empty() && v6.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
            None => host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'),
        };
        if !ok {
            return Err(format!(
                "bad host in {s}: letters, digits, '-' and '.' only"
            ));
        }
        Ok(Server {
            host: host.to_string(),
            port,
            plain,
            ca_pem: None,
        })
    }

    /// [`Server::parse`] for `network`: `plain` is refused outside regtest (plan §3.5, "TLS
    /// required outside regtest"). Every caller that knows the network goes through here.
    pub fn parse_for(network: Network, s: &str, plain: bool) -> Result<Server, String> {
        if plain && network != Network::Regtest {
            return Err(format!(
                "A plain (non-TLS) connection is refused on {}.",
                network.chain_name()
            ));
        }
        Server::parse(s, plain)
    }

    /// Pin `pem` as the only trust anchor (see [`Server::ca_pem`]).
    pub fn with_ca_pem(mut self, pem: Option<String>) -> Server {
        self.ca_pem = pem.filter(|p| !p.trim().is_empty());
        self
    }

    /// The URI the channel connects to.
    pub fn uri(&self) -> String {
        let scheme = if self.plain { "http" } else { "https" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    /// Open the channel: `h2` over `rustls` with the platform's native roots — or, when a
    /// certificate is pinned, that certificate alone — unless `plain`.
    pub async fn connect(&self) -> Result<Channel, NetError> {
        let mut endpoint = Endpoint::from_shared(self.uri())
            .map_err(|e| NetError::Config(format!("invalid endpoint {}: {e}", self.uri())))?;
        endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(15));
        if !self.plain {
            let tls = match &self.ca_pem {
                Some(pem) => ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem)),
                None => ClientTlsConfig::new().with_native_roots(),
            };
            endpoint = endpoint.tls_config(tls)?;
        }
        Ok(endpoint.connect().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_uri() {
        let s = Server::parse("127.0.0.1:9167", true).unwrap();
        assert_eq!(s.uri(), "http://127.0.0.1:9167");
        let t = Server::parse("lwd.example.org:443", false).unwrap();
        assert_eq!(t.uri(), "https://lwd.example.org:443");
        assert!(Server::parse("nohost", true).is_err());
        assert!(Server::parse(":9067", true).is_err());
        assert!(Server::parse("h:notaport", true).is_err());
        // Hosts that would reshape the URI are refused; IPv6 in brackets is accepted.
        for bad in [
            "a/b:1", "a?x:1", "u@h:1", "h#f:1", "a b:1", "[]:1", "[::1:1",
        ] {
            assert!(Server::parse(bad, false).is_err(), "{bad}");
        }
        assert_eq!(
            Server::parse("[::1]:9067", true).unwrap().uri(),
            "http://[::1]:9067"
        );
        assert_eq!(
            Server::parse(" h.example:1 ", false).unwrap().host,
            "h.example"
        );
    }

    #[test]
    fn plain_is_regtest_only_and_pins_are_kept() {
        assert!(Server::parse_for(Network::Mainnet, "h:1", true).is_err());
        assert!(Server::parse_for(Network::Testnet, "h:1", true).is_err());
        assert!(Server::parse_for(Network::Regtest, "h:1", true).is_ok());
        assert!(Server::parse_for(Network::Mainnet, "h:1", false).is_ok());
        let s = Server::parse("h:1", false)
            .unwrap()
            .with_ca_pem(Some("-----BEGIN CERTIFICATE-----".into()));
        assert!(s.ca_pem.is_some());
        assert!(Server::parse("h:1", false)
            .unwrap()
            .with_ca_pem(Some("  ".into()))
            .ca_pem
            .is_none());
        assert!(default_servers(Network::Mainnet).is_empty());
        assert!(default_servers(Network::Testnet).is_empty());
        assert_eq!(
            default_servers(Network::Regtest)[0].address,
            "127.0.0.1:9067"
        );
    }
}

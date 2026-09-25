//! Server configuration and channel construction (plan §3.5): TLS (`rustls`, system roots)
//! everywhere but regtest, where `plain` selects `http://`.

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use super::NetError;

/// A light-client server endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    /// Host name or IP.
    pub host: String,
    /// TCP port (lightwalletd's default is 9067).
    pub port: u16,
    /// `true` for plain HTTP/2 without TLS (regtest only; refused on mainnet by the caller).
    pub plain: bool,
}

impl Server {
    /// Parse `host:port`.
    pub fn parse(s: &str, plain: bool) -> Result<Server, String> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("expected host:port, got {s}"))?;
        let port: u16 = port.parse().map_err(|_| format!("bad port in {s}"))?;
        if host.is_empty() {
            return Err(format!("empty host in {s}"));
        }
        Ok(Server {
            host: host.to_string(),
            port,
            plain,
        })
    }

    /// The URI the channel connects to.
    pub fn uri(&self) -> String {
        let scheme = if self.plain { "http" } else { "https" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    /// Open the channel: `h2` over `rustls` with the platform's native roots unless `plain`.
    pub async fn connect(&self) -> Result<Channel, NetError> {
        let mut endpoint = Endpoint::from_shared(self.uri())
            .map_err(|e| NetError::Config(format!("invalid endpoint {}: {e}", self.uri())))?;
        endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(15));
        if !self.plain {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
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
    }
}

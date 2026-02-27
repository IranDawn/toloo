//! Pluggable transports (§9, §D.13.4).
//!
//! Defines the `PluggableTransport` trait and stub implementations for
//! obfs4 and meek. These stubs return `Err` at runtime — actual
//! implementations require external crates (obfs4, meek).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// Trait combining async read and write for use in trait objects.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// A bidirectional async stream (read + write).
pub type TransportStream = Pin<Box<dyn AsyncReadWrite + Send + Unpin>>;

/// Trait for pluggable transport wrappers.
///
/// A pluggable transport wraps a raw TCP connection to disguise traffic.
/// Implementations should handle the transport-specific handshake and
/// return a stream that reads/writes plaintext.
pub trait PluggableTransport: Send + Sync {
    /// Transport name (e.g. "obfs4", "meek").
    fn name(&self) -> &str;

    /// Wrap an outbound connection through this transport.
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>>;

    /// Accept an inbound connection through this transport.
    /// `raw` is the already-accepted TCP stream.
    fn accept(
        &self,
        raw: TransportStream,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>>;
}

/// Stub obfs4 transport. Returns errors until a real implementation is provided.
pub struct Obfs4Stub;

impl PluggableTransport for Obfs4Stub {
    fn name(&self) -> &str {
        "obfs4"
    }

    fn connect(
        &self,
        _addr: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "obfs4 transport not yet implemented",
            ))
        })
    }

    fn accept(
        &self,
        _raw: TransportStream,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "obfs4 transport not yet implemented",
            ))
        })
    }
}

/// Stub meek (HTTP domain-fronting) transport.
pub struct MeekStub;

impl PluggableTransport for MeekStub {
    fn name(&self) -> &str {
        "meek"
    }

    fn connect(
        &self,
        _addr: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "meek transport not yet implemented",
            ))
        })
    }

    fn accept(
        &self,
        _raw: TransportStream,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<TransportStream>> + Send>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "meek transport not yet implemented",
            ))
        })
    }
}

/// Registry of available pluggable transports.
pub struct TransportRegistry {
    transports: Vec<Box<dyn PluggableTransport>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Create a registry with the built-in stubs.
    pub fn with_stubs() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(Obfs4Stub));
        reg.register(Box::new(MeekStub));
        reg
    }

    pub fn register(&mut self, transport: Box<dyn PluggableTransport>) {
        self.transports.push(transport);
    }

    pub fn get(&self, name: &str) -> Option<&dyn PluggableTransport> {
        self.transports.iter().find(|t| t.name() == name).map(|t| t.as_ref())
    }

    pub fn names(&self) -> Vec<&str> {
        self.transports.iter().map(|t| t.name()).collect()
    }
}

impl Default for TransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_with_stubs_has_both_transports() {
        let reg = TransportRegistry::with_stubs();
        assert_eq!(reg.names().len(), 2);
        assert!(reg.get("obfs4").is_some());
        assert!(reg.get("meek").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[tokio::test]
    async fn obfs4_stub_returns_unsupported() {
        let stub = Obfs4Stub;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let result = stub.connect(addr).await;
        let err = result.err().expect("expected error");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn meek_stub_returns_unsupported() {
        let stub = MeekStub;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let result = stub.connect(addr).await;
        let err = result.err().expect("expected error");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}

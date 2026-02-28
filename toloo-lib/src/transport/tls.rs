//! Self-signed TLS certificate generation for relay server endpoints (wss, https).
//!
//! Each relay generates a fresh certificate at start-up. The certificate's
//! SHA-256 fingerprint is included in the endpoint descriptor (`extra.cert_fp`)
//! so connecting peers can pin it instead of relying on a CA chain.

use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

/// Generate a fresh self-signed TLS certificate for `hostname` and return:
/// - a ready-to-use `TlsAcceptor`
/// - the certificate DER bytes (for the invite URI's `extra.cert_der` field)
/// - the SHA-256 fingerprint as a lowercase hex string (for pinning)
///
/// The certificate includes SANs for `hostname`, plus `localhost` and
/// `127.0.0.1` so local testing always works without separate flags.
pub fn make_self_signed_acceptor(
    hostname: &str,
) -> Result<(TlsAcceptor, Vec<u8>, String), String> {
    // Build Subject Alternative Names — always include loopback addresses.
    let mut sans = vec![hostname.to_owned()];
    if hostname != "localhost"  { sans.push("localhost".to_owned()); }
    if hostname != "127.0.0.1"  { sans.push("127.0.0.1".to_owned()); }

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(sans).map_err(|e| format!("rcgen: {e}"))?;

    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der:  Vec<u8> = signing_key.serialize_der();

    // SHA-256 fingerprint (hex) for client-side pinning.
    let fingerprint = format!("{:x}", Sha256::digest(&cert_der));

    // Build rustls ServerConfig.
    let cert_chain  = vec![CertificateDer::from(cert_der.clone())];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let server_config = ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("rustls cert: {e}"))?;

    Ok((TlsAcceptor::from(Arc::new(server_config)), cert_der, fingerprint))
}

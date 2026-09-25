// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! TLS configuration for the gRPC listener.
//!
//! The daemon terminates TLS itself (rustls, TLS 1.3 only, ALPN `h2`) in the
//! accept loop (`listener.rs`), so that the handshake runs with a timeout off
//! the accept path and the verified client certificate can be turned into a
//! client identity.
//!
//! Client authentication (mTLS) is mandatory unless the configuration opts
//! out explicitly (`allow_no_client_auth`, H4-17). Certificate revocation
//! lists may be given as PEM or DER, several files are accepted, expired
//! CRLs are rejected, and the lists are re-read periodically (H4-18).

use rustls::pki_types::CertificateRevocationListDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use std::sync::{Arc, RwLock};

/// Inputs needed to (re)build the rustls server configuration.
#[derive(Clone, Debug)]
pub struct TlsSettings {
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: Option<String>,
    pub client_crl_paths: Vec<String>,
}

/// Holds the current `ServerConfig`; swapped atomically on CRL reload.
pub struct TlsState {
    settings: TlsSettings,
    current: RwLock<Arc<ServerConfig>>,
}

impl TlsState {
    pub fn new(settings: TlsSettings) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let cfg = load_tls_config(&settings)?;
        Ok(Arc::new(Self {
            settings,
            current: RwLock::new(Arc::new(cfg)),
        }))
    }

    /// The configuration to use for the next handshake.
    pub fn current(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Rebuild the configuration (re-reading CRLs). On failure the previous
    /// configuration stays active; with `enforce_revocation_expiration` an
    /// outdated CRL still fails closed once it expires.
    pub fn reload(&self) {
        match load_tls_config(&self.settings) {
            Ok(cfg) => {
                *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(cfg);
                tracing::info!("TLS configuration reloaded (CRLs refreshed)");
            }
            Err(e) => {
                tracing::error!(error = %e, "TLS configuration reload failed; keeping previous")
            }
        }
    }

    pub fn has_crls(&self) -> bool {
        !self.settings.client_crl_paths.is_empty()
    }
}

/// Parse one CRL file, PEM (one or more `X509 CRL` blocks) or DER.
fn read_crls(path: &str) -> Result<Vec<CertificateRevocationListDer<'static>>, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read CRL file '{}': {}", path, e))?;
    let trimmed = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &data[i..])
        .unwrap_or(&[]);
    if trimmed.starts_with(b"-----BEGIN") {
        let crls: Vec<_> = rustls_pemfile::crls(&mut BufReader::new(&data[..]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse PEM CRL '{}': {}", path, e))?;
        if crls.is_empty() {
            return Err(format!("No X509 CRL found in '{}'", path));
        }
        Ok(crls)
    } else {
        Ok(vec![CertificateRevocationListDer::from(data)])
    }
}

/// Build a rustls ServerConfig (TLS 1.3 only, ALPN h2).
pub fn load_tls_config(s: &TlsSettings) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(&s.cert_path)
        .map_err(|e| format!("Failed to open TLS cert '{}': {}", s.cert_path, e))?;
    let key_file = std::fs::File::open(&s.key_path).map_err(|e| {
        // Do not echo the key path at info level; it is in the config anyway.
        format!("Failed to open TLS key: {}", e)
    })?;

    let server_certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse TLS certs: {}", e))?;
    if server_certs.is_empty() {
        return Err("No certificate found in TLS cert file".into());
    }

    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("Failed to parse TLS key: {}", e))?
        .ok_or("No private key found in TLS key file")?;

    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let mut config = if let Some(ca_path) = &s.client_ca_path {
        let ca_file = std::fs::File::open(ca_path)
            .map_err(|e| format!("Failed to open client CA '{}': {}", ca_path, e))?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse client CA certs: {}", e))?;
        if ca_certs.is_empty() {
            return Err(format!("No CA certificate found in '{}'", ca_path).into());
        }
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed to add client CA cert: {}", e))?;
        }

        let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));
        if !s.client_crl_paths.is_empty() {
            let mut crls = Vec::new();
            for p in &s.client_crl_paths {
                crls.extend(read_crls(p)?);
            }
            verifier_builder = verifier_builder
                .with_crls(crls)
                // (H4-18) An expired CRL must not be trusted.
                .enforce_revocation_expiration();
        } else {
            tracing::warn!(
                "mTLS enabled without a CRL — revoked client certificates are accepted \
                 until they expire. Configure [daemon] tls_client_crl."
            );
        }
        let verifier = verifier_builder
            .build()
            .map_err(|e| format!("Failed to build client verifier: {}", e))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, key)
            .map_err(|e| format!("TLS config error: {}", e))?
    } else {
        tracing::error!(
            "Client certificate authentication is DISABLED (allow_no_client_auth = true). \
             Every TLS client is treated as an anonymous, per-connection principal."
        );
        builder
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .map_err(|e| format!("TLS config error: {}", e))?
    };

    config.alpn_protocols = vec![b"h2".to_vec()]; // gRPC requires HTTP/2
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crl_pem_without_blocks_is_rejected() {
        let dir = std::env::temp_dir().join(format!("craton-crl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("empty.pem");
        std::fs::write(
            &p,
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(read_crls(p.to_str().unwrap()).is_err());
        let d = dir.join("raw.der");
        std::fs::write(&d, [0x30u8, 0x00]).unwrap();
        assert_eq!(read_crls(d.to_str().unwrap()).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

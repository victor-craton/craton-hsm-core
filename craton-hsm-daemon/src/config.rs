// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Daemon configuration.
//!
//! The daemon reads a single TOML file. The `[daemon]` section is owned by
//! this crate; `[token]`, `[security]`, `[audit]` and `[algorithms]` are owned
//! by the core library (`HsmConfig`). Unknown keys in `[daemon]` and unknown
//! top-level sections are rejected (H4-17) so that a typo such as
//! `tls_clent_ca` cannot silently disable a security control.

use serde::{Deserialize, Deserializer};
use std::net::SocketAddr;

/// Upper bound for any single gRPC message the daemon accepts or emits.
pub const HARD_MAX_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;
/// Upper bound for the login/InitToken cooldown (H4-20).
pub const MAX_COOLDOWN_SECS: u64 = 86_400;

/// Configuration for the daemon, loaded from the `[daemon]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// PEM file with the CA certificate(s) used to verify client certificates
    /// (mutual TLS). Required unless `allow_no_client_auth = true` (H4-17).
    pub tls_client_ca: Option<String>,
    /// One path or a list of paths to Certificate Revocation Lists (PEM or
    /// DER) for client certificate validation. Only effective with
    /// `tls_client_ca`. CRLs are reloaded every `tls_client_crl_reload_secs`.
    #[serde(default, deserialize_with = "one_or_many")]
    pub tls_client_crl: Vec<String>,
    /// Interval for re-reading the CRL files (0 disables reloading).
    #[serde(default = "default_crl_reload_secs")]
    pub tls_client_crl_reload_secs: u64,
    /// Explicit opt-out of client certificate authentication. When false
    /// (the default) the daemon refuses to start with TLS but without
    /// `tls_client_ca`.
    #[serde(default)]
    pub allow_no_client_auth: bool,
    /// SHA-256 fingerprints (hex, optionally colon-separated) of client
    /// certificates that hold the administrator role. Only administrators may
    /// call InitToken, log in as SO or call InitPin (H4-02, H4-11).
    #[serde(default)]
    pub admin_client_cert_sha256: Vec<String>,
    /// Development only: in plaintext loopback mode (`allow_insecure`), treat
    /// every local connection as an administrator. Default false.
    #[serde(default)]
    pub insecure_loopback_admin: bool,
    /// Maximum allowed length for GenerateRandom requests (bytes).
    #[serde(default = "default_max_random_length")]
    pub max_random_length: u32,
    /// Maximum allowed data length for Digest requests (bytes).
    #[serde(default = "default_max_digest_length")]
    pub max_digest_length: u32,
    /// Maximum decoded size of one inbound gRPC message (bytes).
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: u32,
    /// Maximum encoded size of one outbound gRPC message (bytes).
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u32,
    /// Allow running without TLS on a loopback address. Development only.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Failed PIN attempts per (client, slot, role) before the daemon imposes
    /// a cooldown. 0 disables the daemon throttle (token counters still apply).
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    /// Cooldown in seconds after `max_login_attempts` failures (<= 1 day).
    #[serde(default = "default_login_cooldown_secs")]
    pub login_cooldown_secs: u64,
    /// Maximum number of simultaneously open client connections (TCP accepted,
    /// including connections still in the TLS handshake).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Maximum simultaneous connections from a single source IP address.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    /// Maximum number of in-flight requests across all connections. Excess
    /// requests are rejected immediately with UNAVAILABLE (load shedding).
    #[serde(default = "default_max_inflight_requests")]
    pub max_inflight_requests: u32,
    /// HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS and per-connection in-flight
    /// request limit.
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    /// Per-request timeout in seconds (1..=600).
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Deadline for completing the TLS handshake (1..=120 seconds).
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Close connections that have not issued an RPC for this long
    /// (seconds, 0 disables). Sessions opened on a closed connection are
    /// closed as well.
    #[serde(default = "default_connection_idle_timeout_secs")]
    pub connection_idle_timeout_secs: u64,
    /// Maximum connection lifetime in seconds (0 = unlimited). Note that
    /// sessions are bound to the connection that opened them.
    #[serde(default)]
    pub max_connection_age_secs: u64,
    /// HTTP/2 keepalive PING interval in seconds (0 disables).
    #[serde(default = "default_http2_keepalive_interval_secs")]
    pub http2_keepalive_interval_secs: u64,
    /// HTTP/2 keepalive PING ack timeout in seconds.
    #[serde(default = "default_http2_keepalive_timeout_secs")]
    pub http2_keepalive_timeout_secs: u64,
    /// Maximum open sessions per client identity (H4-10).
    #[serde(default = "default_max_sessions_per_client")]
    pub max_sessions_per_client: u32,
    /// Sessions unused for this many seconds are closed (0 disables).
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
    /// Maximum live objects created through the daemon per client identity.
    #[serde(default = "default_max_objects_per_client")]
    pub max_objects_per_client: u32,
    /// Maximum concurrently executing CPU-bound operations (PIN hashing, key
    /// generation, signing, ...). 0 = number of available CPUs.
    #[serde(default)]
    pub max_blocking_tasks: u32,
    /// Optional plaintext listener that serves ONLY `grpc.health.v1.Health`
    /// (for kubelet / Docker health probes, which cannot present client
    /// certificates). Example: "0.0.0.0:5697". Disabled when unset.
    pub health_bind: Option<String>,
}

fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

fn default_bind() -> String {
    "127.0.0.1:5696".to_string()
}
fn default_crl_reload_secs() -> u64 {
    300
}
fn default_max_random_length() -> u32 {
    65_536
}
fn default_max_digest_length() -> u32 {
    1_048_576 - 1024
}
fn default_max_request_bytes() -> u32 {
    1_048_576
}
fn default_max_response_bytes() -> u32 {
    4 * 1_048_576
}
fn default_max_login_attempts() -> u32 {
    5
}
fn default_login_cooldown_secs() -> u64 {
    60
}
fn default_max_connections() -> u32 {
    128
}
fn default_max_connections_per_ip() -> u32 {
    32
}
fn default_max_inflight_requests() -> u32 {
    32
}
fn default_max_concurrent_streams() -> u32 {
    16
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_handshake_timeout_secs() -> u64 {
    10
}
fn default_connection_idle_timeout_secs() -> u64 {
    300
}
fn default_http2_keepalive_interval_secs() -> u64 {
    30
}
fn default_http2_keepalive_timeout_secs() -> u64 {
    10
}
fn default_max_sessions_per_client() -> u32 {
    16
}
fn default_session_idle_timeout_secs() -> u64 {
    900
}
fn default_max_objects_per_client() -> u32 {
    1024
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            tls_client_crl: Vec::new(),
            tls_client_crl_reload_secs: default_crl_reload_secs(),
            allow_no_client_auth: false,
            admin_client_cert_sha256: Vec::new(),
            insecure_loopback_admin: false,
            max_random_length: default_max_random_length(),
            max_digest_length: default_max_digest_length(),
            max_request_bytes: default_max_request_bytes(),
            max_response_bytes: default_max_response_bytes(),
            allow_insecure: false,
            max_login_attempts: default_max_login_attempts(),
            login_cooldown_secs: default_login_cooldown_secs(),
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            max_inflight_requests: default_max_inflight_requests(),
            max_concurrent_streams: default_max_concurrent_streams(),
            request_timeout_secs: default_request_timeout_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            connection_idle_timeout_secs: default_connection_idle_timeout_secs(),
            max_connection_age_secs: 0,
            http2_keepalive_interval_secs: default_http2_keepalive_interval_secs(),
            http2_keepalive_timeout_secs: default_http2_keepalive_timeout_secs(),
            max_sessions_per_client: default_max_sessions_per_client(),
            session_idle_timeout_secs: default_session_idle_timeout_secs(),
            max_objects_per_client: default_max_objects_per_client(),
            max_blocking_tasks: 0,
            health_bind: None,
        }
    }
}

/// Normalise a certificate fingerprint: strip `:`/whitespace, lowercase, and
/// require exactly 64 hex digits (SHA-256).
pub fn normalize_fingerprint(fp: &str) -> Result<String, String> {
    let cleaned: String = fp
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "admin_client_cert_sha256 entry '{}' is not a SHA-256 hex fingerprint",
            fp
        ));
    }
    Ok(cleaned)
}

impl DaemonConfig {
    /// Returns true if the bind address is a loopback IP address.
    /// Only parsed IP addresses are trusted, never hostnames.
    pub fn is_loopback_bind(&self) -> bool {
        match self.bind.parse::<SocketAddr>() {
            Ok(addr) => addr.ip().is_loopback(),
            Err(_) => false,
        }
    }

    /// Validate value ranges and cross-field consistency (H4-17, H4-20).
    pub fn validate(&self) -> Result<(), String> {
        let mut errs: Vec<String> = Vec::new();

        if self.bind.parse::<SocketAddr>().is_err() {
            errs.push(format!(
                "bind '{}' must be an IP:port socket address",
                self.bind
            ));
        }
        if let Some(h) = &self.health_bind {
            if h.parse::<SocketAddr>().is_err() {
                errs.push(format!("health_bind '{}' must be an IP:port", h));
            }
        }

        match (&self.tls_cert, &self.tls_key) {
            (Some(_), Some(_)) => {
                if self.tls_client_ca.is_none() && !self.allow_no_client_auth {
                    errs.push(
                        "tls_client_ca is required (mutual TLS). Set allow_no_client_auth = true \
                         only if you explicitly accept unauthenticated TLS clients"
                            .to_string(),
                    );
                }
                if self.tls_client_ca.is_none() && !self.tls_client_crl.is_empty() {
                    errs.push("tls_client_crl requires tls_client_ca".to_string());
                }
            }
            (None, None) => {
                if !self.allow_insecure {
                    errs.push(
                        "TLS not configured: set tls_cert and tls_key, or allow_insecure = true \
                         (loopback development only)"
                            .to_string(),
                    );
                } else if !self.is_loopback_bind() {
                    errs.push(format!(
                        "allow_insecure = true is only permitted on loopback addresses \
                         (127.0.0.1 / [::1]); bind '{}' is not loopback",
                        self.bind
                    ));
                }
            }
            _ => errs.push("tls_cert and tls_key must be set together".to_string()),
        }
        if self.insecure_loopback_admin && self.tls_cert.is_some() {
            errs.push("insecure_loopback_admin is only valid without TLS".to_string());
        }
        for fp in &self.admin_client_cert_sha256 {
            if let Err(e) = normalize_fingerprint(fp) {
                errs.push(e);
            }
        }
        if !self.admin_client_cert_sha256.is_empty() && self.tls_client_ca.is_none() {
            errs.push("admin_client_cert_sha256 requires mutual TLS (tls_client_ca)".to_string());
        }

        let mut range = |name: &str, v: u64, lo: u64, hi: u64| {
            if v < lo || v > hi {
                errs.push(format!("{} = {} is out of range [{}, {}]", name, v, lo, hi));
            }
        };
        let hard_max = u64::from(HARD_MAX_MESSAGE_BYTES);
        range(
            "max_request_bytes",
            self.max_request_bytes.into(),
            4096,
            hard_max,
        );
        range(
            "max_response_bytes",
            self.max_response_bytes.into(),
            4096,
            hard_max,
        );
        // Leave headroom for protobuf framing.
        range(
            "max_random_length",
            self.max_random_length.into(),
            1,
            u64::from(self.max_response_bytes).saturating_sub(1024),
        );
        range(
            "max_digest_length",
            self.max_digest_length.into(),
            1,
            u64::from(self.max_request_bytes).saturating_sub(512),
        );
        range(
            "login_cooldown_secs",
            self.login_cooldown_secs,
            1,
            MAX_COOLDOWN_SECS,
        );
        range(
            "max_login_attempts",
            self.max_login_attempts.into(),
            0,
            1000,
        );
        range("max_connections", self.max_connections.into(), 1, 65_536);
        range(
            "max_connections_per_ip",
            self.max_connections_per_ip.into(),
            1,
            self.max_connections.into(),
        );
        range(
            "max_inflight_requests",
            self.max_inflight_requests.into(),
            1,
            4096,
        );
        range(
            "max_concurrent_streams",
            self.max_concurrent_streams.into(),
            1,
            1024,
        );
        range("request_timeout_secs", self.request_timeout_secs, 1, 600);
        range(
            "handshake_timeout_secs",
            self.handshake_timeout_secs,
            1,
            120,
        );
        range(
            "connection_idle_timeout_secs",
            self.connection_idle_timeout_secs,
            0,
            86_400,
        );
        range(
            "max_connection_age_secs",
            self.max_connection_age_secs,
            0,
            30 * 86_400,
        );
        range(
            "http2_keepalive_interval_secs",
            self.http2_keepalive_interval_secs,
            0,
            3600,
        );
        range(
            "http2_keepalive_timeout_secs",
            self.http2_keepalive_timeout_secs,
            1,
            600,
        );
        range(
            "max_sessions_per_client",
            self.max_sessions_per_client.into(),
            1,
            10_000,
        );
        range(
            "session_idle_timeout_secs",
            self.session_idle_timeout_secs,
            0,
            7 * 86_400,
        );
        range(
            "max_objects_per_client",
            self.max_objects_per_client.into(),
            1,
            10_000,
        );
        range(
            "max_blocking_tasks",
            self.max_blocking_tasks.into(),
            0,
            1024,
        );
        range(
            "tls_client_crl_reload_secs",
            self.tls_client_crl_reload_secs,
            0,
            86_400,
        );

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

/// Full config file structure. `[daemon]` is parsed here; the other sections
/// are parsed (and validated) by the core `HsmConfig` and only accepted here
/// so that unknown top-level sections are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default, rename = "token")]
    _token: Option<toml::Value>,
    #[serde(default, rename = "security")]
    _security: Option<toml::Value>,
    #[serde(default, rename = "audit")]
    _audit: Option<toml::Value>,
    #[serde(default, rename = "algorithms")]
    _algorithms: Option<toml::Value>,
}

impl FullConfig {
    /// Parse and validate config from a TOML string.
    pub fn parse(contents: &str) -> Result<Self, String> {
        let cfg: FullConfig =
            toml::from_str(contents).map_err(|e| format!("invalid configuration: {}", e))?;
        cfg.daemon.validate()?;
        Ok(cfg)
    }

    /// Load config from a TOML file path (fail-closed: a missing or invalid
    /// file is an error).
    pub fn load(path: &str) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::parse(&contents).map_err(|e| {
                format!(
                    "Config '{}': {}. Refusing to start with potentially incorrect settings.",
                    path, e
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
                "Config file '{}' not found. Create an explicit config file with \
                 TLS settings (tls_cert, tls_key, tls_client_ca) in the [daemon] section.",
                path
            )),
            Err(e) => Err(format!("Failed to read config '{}': {}", path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn shipped_example_config_is_valid() {
        let text = include_str!("../craton_hsm.example.toml");
        FullConfig::parse(text).unwrap();
        let core: craton_hsm::config::config::HsmConfig = toml::from_str(text).unwrap();
        core.validate().unwrap();
    }

    #[test]
    fn unknown_daemon_key_is_rejected() {
        let err = FullConfig::parse(
            "[daemon]\ntls_cert = \"c\"\ntls_key = \"k\"\ntls_clent_ca = \"ca\"\n",
        )
        .unwrap_err();
        assert!(err.contains("tls_clent_ca"), "{}", err);
    }

    #[test]
    fn unknown_top_level_section_is_rejected() {
        let err = FullConfig::parse("[deamon]\nbind = \"127.0.0.1:1\"\n").unwrap_err();
        assert!(err.contains("deamon"), "{}", err);
    }

    #[test]
    fn mtls_required_by_default() {
        let err = FullConfig::parse("[daemon]\ntls_cert = \"c\"\ntls_key = \"k\"\n").unwrap_err();
        assert!(err.contains("tls_client_ca is required"), "{}", err);
        FullConfig::parse(
            "[daemon]\ntls_cert = \"c\"\ntls_key = \"k\"\nallow_no_client_auth = true\n",
        )
        .unwrap();
        FullConfig::parse(
            "[daemon]\ntls_cert = \"c\"\ntls_key = \"k\"\ntls_client_ca = \"ca\"\n\
             tls_client_crl = [\"a.crl\", \"b.crl\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn insecure_only_on_loopback() {
        FullConfig::parse("[daemon]\nallow_insecure = true\n").unwrap();
        let err = FullConfig::parse("[daemon]\nallow_insecure = true\nbind = \"0.0.0.0:5696\"\n")
            .unwrap_err();
        assert!(err.contains("loopback"), "{}", err);
        assert!(FullConfig::parse("[daemon]\n").is_err());
    }

    #[test]
    fn numeric_ranges_are_validated() {
        for bad in [
            "request_timeout_secs = 0",
            "max_connections = 0",
            "max_inflight_requests = 0",
            "login_cooldown_secs = 9999999999",
            "max_digest_length = 16777216",
            "max_random_length = 99999999",
        ] {
            let toml = format!("[daemon]\nallow_insecure = true\n{}\n", bad);
            assert!(FullConfig::parse(&toml).is_err(), "accepted: {}", bad);
        }
    }

    #[test]
    fn core_sections_are_accepted_and_fingerprints_normalised() {
        let toml = format!(
            "[token]\nlabel = \"x\"\n[security]\n[audit]\n[algorithms]\n\
             [daemon]\ntls_cert = \"c\"\ntls_key = \"k\"\ntls_client_ca = \"ca\"\n\
             admin_client_cert_sha256 = [\"{}\"]\n",
            FP.to_ascii_uppercase()
        );
        let cfg = FullConfig::parse(&toml).unwrap();
        assert_eq!(
            normalize_fingerprint(&cfg.daemon.admin_client_cert_sha256[0]).unwrap(),
            FP
        );
        assert!(normalize_fingerprint("abc").is_err());
    }
}

//! Holds the current bearer token in memory and re-fetches it from the
//! vault-proxy local socket on a configurable interval (default 5 min)
//! or on demand when the upstream returns 401. Token is wrapped in
//! `secrecy::SecretString` and exposed only at the point of header
//! serialization in `http_client.rs`.
//!
//! Wave 3 Task 8 stub. Filled in by Task 9.

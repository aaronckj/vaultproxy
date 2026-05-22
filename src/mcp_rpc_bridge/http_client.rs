//! Streamable-HTTP / SSE client talking to the upstream MCP endpoint.
//! Injects the bearer token from `HeaderInjector` into the
//! `Authorization` header on every outgoing request. On HTTP 401, forces
//! a token refresh and retries the request once.
//!
//! Wave 3 Task 8 stub. Filled in by Task 11.

//! Stdio JSON-RPC server facing the local MCP client. Reads framed
//! requests from stdin, dispatches via `http_client.rs` to the upstream
//! MCP, writes responses to stdout. Tracing logs go to stderr only
//! (stdout is reserved for the JSON-RPC payload stream).
//!
//! Wave 3 Task 8 stub. Filled in by Task 10.

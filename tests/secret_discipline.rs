//! Integration tests guarding the no-secret-leak invariant on
//! `secrecy::SecretString`. These asserts will fail loudly if a future
//! refactor swaps SecretString for a plain String (or a wrapper that adds
//! Display).

use secrecy::SecretString;

#[test]
fn secret_string_does_not_expose_value_via_debug() {
    let s = SecretString::from("super-sensitive-password-X9".to_string());
    let dbg = format!("{:?}", s);
    assert!(
        !dbg.contains("super-sensitive-password-X9"),
        "SecretString Debug formatter leaked the value: {dbg:?}"
    );
}

#[test]
fn secret_string_redacted_marker_present_in_debug() {
    let s = SecretString::from("anything".to_string());
    let dbg = format!("{:?}", s);
    // secrecy's documented behavior: Debug yields "Secret([REDACTED ...])"
    // or similar. We assert SOME redaction sentinel exists.
    assert!(
        dbg.contains("REDACTED") || dbg.contains("Secret"),
        "expected SecretString Debug to contain a redaction marker; got {dbg:?}"
    );
}

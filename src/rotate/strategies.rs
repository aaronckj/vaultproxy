//! Rotation strategy implementations for each supported service.

use serde::Serialize;

// -------------------------------------------------------------------------- //
// Result type                                                                  //
// -------------------------------------------------------------------------- //

/// Outcome of a single rotation attempt.
#[derive(Debug, Serialize)]
pub struct RotationResult {
    pub service: String,
    pub status: String,
    pub message: String,
}

// -------------------------------------------------------------------------- //
// Strategies                                                                   //
// -------------------------------------------------------------------------- //

/// Sonarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_sonarr() -> RotationResult {
    RotationResult {
        service: "sonarr".to_string(),
        status: "unsupported".to_string(),
        message: "Sonarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

/// Radarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_radarr() -> RotationResult {
    RotationResult {
        service: "radarr".to_string(),
        status: "unsupported".to_string(),
        message: "Radarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

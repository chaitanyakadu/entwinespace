use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JWTClaims {
    AccessToken(AccessClaims),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject
    pub sub: String,
    /// JWT ID
    pub jti: Uuid,
    /// Issued time
    pub iat: i64,
    /// Expiration time
    pub exp: i64,
    /// Username
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AccessTokenState {
    Expired,
    Invalid,
    Valid,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ValidateRefreshTokenMethod {
    Username,
    RefreshTokenHash,
}

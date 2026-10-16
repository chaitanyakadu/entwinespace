use axum::response::{Redirect, Response};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use sqlx::types::{Uuid, time::OffsetDateTime};

#[derive(Serialize, Deserialize)]
pub enum ServerStatus {
    Starting,
    Active,
    Closing,
    Inactive,
}

#[derive(Serialize, Deserialize)]
pub struct GetHealthResponse {
    pub timestamp: DateTime<Local>,
    pub success: bool,
    pub server: String,
    pub status: ServerStatus,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetOauthRedirectUri {
    pub redirect_url: String,
}

// for more info - https://developers.google.com/identity/protocols/oauth2/web-server#handlingresponse
#[derive(Debug, Serialize, Deserialize)]
pub struct GetSignupCallbackParams {
    pub code: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OauthUriParams {
    pub redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleOauthToken {
    pub access_token: String,
    pub expires_in: i32,
    pub scope: String,
    pub id_token: String,
    pub token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshOauthTokenResponse {
    pub access_token: String,
    pub expires_in: i32,
    pub scope: String,
    pub token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Userinfo {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub family_name: Option<String>,
    pub picture: String,
    pub given_name: Option<String>,
}

pub enum RouteResponse {
    Response(Response),
    Redirect(Redirect),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsernameAvailableParams {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupCredentials {
    pub id: String,
    pub username: String,
    pub password: String,
    pub name: String,
    pub contact: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteAccountParams {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncKeyPair {
    pub private: String,
    pub public: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokensClaims {
    pub sub: String,
    pub company: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSessionsParams {
    pub limit: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionsList {
    pub id: Uuid,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub user_agent: Option<String>,
    pub created_by_ip: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSessionsParams {
    pub token_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub username: String,
    pub password: String,
    pub name: String,

    pub email_hash: String,
    pub email_encrypted: Vec<u8>,
    pub contact_hash: Option<String>,
    pub contact_encrypted: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "lowercase")]
pub enum AuthProvider {
    Gmail,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OauthIdentity {
    pub user_id: Uuid,
    pub provider: AuthProvider,
    pub is_verified: bool,
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub user_id: Uuid,

    pub token_hash: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub replaces_by_token_id: Option<String>,

    pub user_agent: Option<String>,
    pub created_by_ip: String,
    pub last_used_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RefreshTokenState {
    Expired,
    Revoked,
    Valid,
    Invalid,
}

/// Standard API response code
/// Useful for success or failure cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponseCode {
    Success,
    Failure,
}

/// Standard API response code for middleware
/// Used by ensure_guest and ensure_authenticated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponseCodeEnsureAuth {
    Authenticated,
    Unauthenticated,
    ServerError,
}

/// Used for authentication response
/// login, callback, credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponseCodeAuth {
    UserAlreadyExists,
    NewUser,
    InvalidCredentials,
    ServerError,
    Success,
}

/// Standard API response
/// provide standard API json response to any query
///
/// arguments
/// <P, Q, R> => P: ApiCode, Q: Payload, R: Issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<C, P, I> {
    pub status: bool,
    pub code: C,
    pub payload: Option<P>,
    pub issue: Option<I>,
}

/// Standard API response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponsePayload {
    pub msg: String,
}

/// Standard API response issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponseIssue {
    pub msg: String,
}

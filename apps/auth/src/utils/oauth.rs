use app_schema::config::GoogleOAuthConfig;
use axum::response::Response;
use reqwest::{StatusCode, Url};
use crate::schema::{
    routes::{GoogleOauthToken, RefreshOauthTokenResponse, Userinfo},
};
use serde_json::json;
use tracing::{debug, warn};

use crate::utils::routes::server_error_response_api;

/// Generate oauth redirect uri
pub fn oauth_redirect_uri(config: &GoogleOAuthConfig, redirect_uri: &str) -> Result<Url, Response> {
    debug!("generating oauth redirect uri");
    let url = "https://accounts.google.com/o/oauth2/v2/auth";
    let params = [
        ("client_id", config.client_id.clone()),
        ("response_type", "code".to_string()),
        ("scope", "openid profile email".to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("access_type", "offline".to_string()),
    ];
    let redirect_uri: Url = reqwest::Url::parse_with_params(url, &params).map_err(|e| {
        warn!(
            error = ?e,
            data = ?json!({
                "url": "accounts.google.com/o/oauth2/v2/auth"
            }),
            "Failed to parse userinfo url"
        );
        server_error_response_api()
    })?;

    Ok(redirect_uri)
}

/// Exchange authorization code for refresh and access token
/// returns Result<GoogleOauthToken, StatusCode>
///
/// refer - https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
pub async fn exchange_auth_code(
    code: &str,
    redirect_uri: &str,
    config: &GoogleOAuthConfig,
) -> Result<GoogleOauthToken, Response> {
    debug!("exchange authorization code for refresh and access tokens");
    let client = reqwest::Client::new();
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form::<Vec<(&str, String)>>(&vec![
            ("code", code.to_string()),
            ("client_id", config.client_id.clone()),
            ("client_secret", config.client_secret.clone()),
            ("redirect_uri", redirect_uri.to_string()),
            ("grant_type", "authorization_code".to_string()),
        ])
        .send()
        .await
        .map_err(|e| {
            warn!(
                error = ?e,
                data = ?json!({
                    "url": "oauth2.googleapis.com/token"
                }),
                "Oauth token error"
            );
            server_error_response_api()
        })?;
    let status = res.status();

    if status != StatusCode::OK {
        debug!(
            status_code = ?status,
            "/token endpoint returns invalid status code"
        );
        return Err(server_error_response_api());
    }

    let oauth_tokens: GoogleOauthToken = res.json().await.map_err(|e| {
        warn!(
            error = ?e,
            "failed to deserialize the response as json of type GoogleOauthToken"
        );
        server_error_response_api()
    })?;

    Ok(oauth_tokens)
}

/// Call google apis to access the information(Userinfo)
///
/// refer - https://developers.google.com/identity/protocols/oauth2/scopes#oauth2
pub async fn call_google_apis(
    google_oauth_tokens: &GoogleOauthToken,
) -> Result<Userinfo, Response> {
    debug!("request for userinfo");
    let client = reqwest::Client::new();
    let params: Vec<(&str, String)> =
        vec![("access_token", google_oauth_tokens.access_token.to_owned())];

    let userinfo_url =
        reqwest::Url::parse_with_params("https://www.googleapis.com/oauth2/v2/userinfo", params)
            .map_err(|e| {
                warn!(
                    error = ?e,
                    data = ?json!({
                        "url": "www.googleapis.com/oauth2/v2/userinfo"
                    }),
                    "Failed to parse userinfo url"
                );
                server_error_response_api()
            })?;
    let res = client.get(userinfo_url).send().await.map_err(|e| {
        warn!(
            error = ?e,
            data = ?json!({
                "url": "www.googleapis.com/oauth2/v2/userinfo",
                "error": "GET"
            }),
            "Error occured while sending the request"
        );
        server_error_response_api()
    })?;

    let status = res.status();
    if status != StatusCode::OK {
        debug!(
            status_code = ?status,
            "/userinfo endpoint returns invalid status code"
        );
        return Err(server_error_response_api());
    }

    let userinfo: Userinfo = res.json().await.map_err(|e| {
        warn!(
            error = ?e,
            data = ?json!({
                "url": "www.googleapis.com/oauth2/v2/userinfo",
                "method": "GET",
                "status": status.to_string()
            }),
            "Response body is not in JSON format"
        );
        server_error_response_api()
    })?;

    Ok(userinfo)
}

// todo - the database should also store the oauth access and refresh token
/// Refresh an access token
pub async fn refresh_token(
    refresh_token: &str,
    config: &GoogleOAuthConfig,
) -> Result<RefreshOauthTokenResponse, Response> {
    debug!("refresh the oauth access token");
    let client = reqwest::Client::new();
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form::<Vec<(&str, String)>>(&vec![
            ("client_id", config.client_id.clone()),
            ("client_secret", config.client_secret.clone()),
            ("refresh_token", refresh_token.to_string()),
            ("grant_type", "refresh_token".to_string()),
        ])
        .send()
        .await
        .map_err(|e| {
            warn!(
                error = ?e,
                data = ?json!({
                    "url": "oauth2.googleapis.com/token"
                }),
                "Oauth token error"
            );
            server_error_response_api()
        })?;
    let status = res.status();

    if status != StatusCode::OK {
        debug!(
            status_code = ?status,
            "/token endpoint returns invalid status code"
        );
        return Err(server_error_response_api());
    }

    let token: RefreshOauthTokenResponse = res.json().await.map_err(|e| {
        warn!(
            error = ?e,
            data = ?json!({
                "url": "oauth2.googleapis.com/token"
            }),
            "failed to deserialize the response as json of type RefreshOauthTokenResponse"
        );
        server_error_response_api()
    })?;

    Ok(token)
}

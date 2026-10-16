use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::HeaderValue,
    response::{IntoResponse, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use jsonwebtoken::Header;
use reqwest::{StatusCode, header};
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseCodeEnsureAuth, ApiResponseIssue,
        ApiResponsePayload, RefreshTokenState,
    },
    security::{AccessClaims, JWTClaims, ValidateRefreshTokenMethod},
};
use sqlx::Error as SqlxError;
use time::{Duration, OffsetDateTime};
use tracing::{debug, warn};
use crate::utils::{
    routes::server_error_response_api,
    security::{decode_jwt_for_username, generate_jwt, generate_sha2_hash},
};
use uuid::Uuid;

use crate::api::database::refresh_token::validate_refresh_token;

/*
curl --location --request PUT 'http://localhost:3000/auth/sessions/refresh-token' \
--header 'Cookie: refresh_token=123; access_token=123;'
*/
pub async fn refresh_token(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let config = &app_state.config;

    let access_token = match jar.get("access_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };
    let refresh_token = match jar.get("refresh_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };
    let refresh_token_hash = generate_sha2_hash(&refresh_token);

    let username =
        decode_jwt_for_username(&access_token, &config.security.jwt_secret).map_err(|_| {
            let response_code = ApiResponseCode::Failure;
            let response_payload = ApiResponsePayload {
                msg: "Invalid credentials! Kindly check the access token.".to_string(),
            };
            let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> = ApiResponse {
                code: response_code,
                status: false,
                payload: Some(response_payload),
                issue: None,
            };
            (StatusCode::UNAUTHORIZED, Json(api_response)).into_response()
        })?;

    let db = &app_state.pool;

    let refresh_token_state = validate_refresh_token(
        &refresh_token_hash,
        ValidateRefreshTokenMethod::RefreshTokenHash,
        &db,
    )
    .await
    .map_err(|e| match e {
        SqlxError::InvalidArgument(_) => {
            let response_code = ApiResponseCode::Failure;
            let response_payload = ApiResponsePayload {
                msg: "Invalid credentials! Kindly check the header cookies.".to_string(),
            };
            let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> = ApiResponse {
                code: response_code,
                status: false,
                payload: Some(response_payload),
                issue: None,
            };
            (StatusCode::FORBIDDEN, Json(api_response)).into_response()
        }
        _ => server_error_response_api(),
    })?;

    if !matches!(refresh_token_state, RefreshTokenState::Valid) {
        debug!(
            username = ?username,
            "the refresh token was either expired or revoked"
        );
        return Ok(unauthenticated_and_return());
    }

    let header = Header::default();
    let jti = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let access_claims = AccessClaims {
        sub: "".to_string(),
        jti,
        iat: now.unix_timestamp(),
        exp: (now + Duration::minutes(60)).unix_timestamp(),
        username,
    };
    let jwt_claims = JWTClaims::AccessToken(access_claims);
    let new_access_token =
        generate_jwt(jwt_claims, &config.security.jwt_secret, header).map_err(|e| {
            debug!(
                error = ?e,
                "failed to generate jsonwebtoken"
            );
            server_error_response_api()
        })?;

    let mut response = StatusCode::OK.into_response();

    let access = Cookie::build(("access_token", new_access_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build();

    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&access.to_string()).map_err(|e| {
            warn!(error = ?e, "Failed to create access token cookie");
            server_error_response_api()
        })?,
    );

    let refresh_token = Cookie::build(("refresh_token", refresh_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build();

    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&refresh_token.to_string()).map_err(|e| {
            warn!(error = ?e, "Failed to create refresh token cookie");
            server_error_response_api()
        })?,
    );

    Ok(response)
}

/// the user is unauthenticated and thus return a status code and json
fn unauthenticated_and_return() -> Response {
    debug!("the user is unauthenticated");
    let response_code = ApiResponseCodeEnsureAuth::Unauthenticated;
    let issue_payload = ApiResponseIssue {
        msg: "Kindly login to proceed.".to_string(),
    };
    let api_response: ApiResponse<ApiResponseCodeEnsureAuth, (), ApiResponseIssue> = ApiResponse {
        code: response_code,
        status: false,
        payload: None,
        issue: Some(issue_payload),
    };
    (StatusCode::UNAUTHORIZED, Json(api_response)).into_response()
}

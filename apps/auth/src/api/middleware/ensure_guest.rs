use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use crate::schema::app_state::AppState;
use crate::schema::{
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseCodeEnsureAuth, ApiResponsePayload,
        RefreshTokenState,
    },
    security::{AccessTokenState, ValidateRefreshTokenMethod},
};
use sqlx::Error as SqlxError;
use tracing::debug;
use crate::utils::{
    routes::server_error_response_api,
    security::{generate_sha2_hash, verify_access_token},
};

use crate::api::database::refresh_token::validate_refresh_token;

pub async fn ensure_guest(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let config = &state.config;
    let jar = CookieJar::from_headers(req.headers());

    let access_token = jar.get("access_token");

    if let Some(token) = access_token {
        let access_token_state =
            verify_access_token(&token.to_string(), &config.security.jwt_secret);
        if let AccessTokenState::Valid = access_token_state {
            return Ok(authenticated_and_return());
        };
    };

    let get_refresh_token = jar.get("refresh_token");

    let refresh_token = match get_refresh_token {
        None => return Ok(next.run(req).await),
        Some(v) => v.value(),
    };
    let refresh_token_hash = generate_sha2_hash(refresh_token);

    let db = &state.pool;
    let refresh_token_state: RefreshTokenState = validate_refresh_token(
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

    if matches!(refresh_token_state, RefreshTokenState::Valid) {
        debug!("The refresh token is valid and is neither expired nor revoked");
        return Ok(authenticated_and_return());
    }

    Ok(next.run(req).await)
}

/// the user is authenticated and thus return a status code and json
fn authenticated_and_return() -> Response {
    debug!("the user is authenticated");
    let response_code = ApiResponseCodeEnsureAuth::Unauthenticated;
    let response_payload = ApiResponsePayload {
        msg: "The user is already logged in.".to_string(),
    };
    let api_response: ApiResponse<ApiResponseCodeEnsureAuth, ApiResponsePayload, ()> =
        ApiResponse {
            code: response_code,
            status: false,
            payload: Some(response_payload),
            issue: None,
        };
    (StatusCode::FORBIDDEN, Json(api_response)).into_response()
}

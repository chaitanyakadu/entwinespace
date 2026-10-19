use std::sync::Arc;

use axum::{
    Json,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use crate::schema::app_state::AppState;
use crate::schema::{
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseCodeEnsureAuth, ApiResponseIssue,
        ApiResponsePayload, RefreshTokenState,
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

pub async fn ensure_authenticated(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let config = &state.config;
    let jar = CookieJar::from_headers(req.headers());

    let access_token = jar
        .get("access_token")
        .ok_or_else(|| unauthenticated_and_return())?
        .value();
    let access_token_state = verify_access_token(&access_token, &config.auth_service.access_token_jwt_secret);
    if matches!(access_token_state, AccessTokenState::Valid) {
        return Ok(next.run(req).await);
    };

    let refresh_token = jar
        .get("refresh_token")
        .ok_or_else(|| unauthenticated_and_return())?
        .value();
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

    if !matches!(refresh_token_state, RefreshTokenState::Valid) {
        debug!("The refresh token is either expired or revoked");
        return Ok(unauthenticated_and_return());
    }

    Ok(next.run(req).await)
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

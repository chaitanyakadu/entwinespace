use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use crate::schema::{
    app_state::AppState,
    routes::{ApiResponse, ApiResponseCode, ApiResponsePayload},
};
use sqlx::Error as SqlxError;
use tracing::debug;
use crate::utils::{routes::server_error_response_api, security::generate_sha2_hash};

use crate::api::database::refresh_token::revoke_refresh_token;

// get the refresh token and hash it
// revoke the token
pub async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let refresh_token = match jar.get("refresh_token") {
        Some(v) => v.value().to_owned(),
        None => {
            debug!("Refresh token is missing");
            return Ok(StatusCode::SEE_OTHER.into_response());
        }
    };
    let hashed_refresh_token = generate_sha2_hash(&refresh_token);

    let db = &state.pool;
    revoke_refresh_token(&hashed_refresh_token, &db)
        .await
        .map_err(|e| match e {
            SqlxError::InvalidArgument(_) => {
                let response_code = ApiResponseCode::Failure;
                let response_payload = ApiResponsePayload {
                    msg: "Invalid credentials! Kindly check the header cookies.".to_string(),
                };
                let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> =
                    ApiResponse {
                        code: response_code,
                        status: false,
                        payload: Some(response_payload),
                        issue: None,
                    };
                (StatusCode::FORBIDDEN, Json(api_response)).into_response()
            }
            _ => server_error_response_api(),
        })?;

    let mut response = StatusCode::OK.into_response();
    response.headers_mut().remove("Cookie");

    Ok(response)
}

use std::sync::Arc;

use axum::{
    Json,
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseIssue, ApiResponsePayload, DeleteAccountParams,
    },
};
use sqlx::Error as SqlxError;
use crate::utils::{
    abstract_body,
    routes::server_error_response_api,
    security::{decode_jwt_for_username, generate_sha2_hash},
};

use crate::api::database::{refresh_token::revoke_all_refresh_tokens, users::delete_user};

pub async fn delete_account(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
    mut req: Request,
) -> Result<Response, Response> {
    let config = &app_state.config;

    let (payload, _) = abstract_body::<DeleteAccountParams>(&mut req).await?;
    let password_hash = generate_sha2_hash(&payload.password);

    let access_token = match jar.get("access_token") {
        Some(v) => v.value().to_owned(),
        None => {
            let response_code = ApiResponseCode::Failure;
            let issue_payload = ApiResponseIssue {
                msg: "Kindly login to proceed.".to_string(),
            };
            let api_response: ApiResponse<ApiResponseCode, (), ApiResponseIssue> = ApiResponse {
                code: response_code,
                status: false,
                payload: None,
                issue: Some(issue_payload),
            };
            return Ok((StatusCode::UNAUTHORIZED, Json(api_response)).into_response());
        }
    };

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
    let user_id = delete_user(&username, &password_hash, &db)
        .await
        .map_err(|e| match e {
            SqlxError::InvalidArgument(_) => {
                let response_code = ApiResponseCode::Failure;
                let response_payload = ApiResponsePayload {
                    msg: "Invalid credentials!".to_string(),
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

    revoke_all_refresh_tokens(&user_id, &db)
        .await
        .map_err(|e| match e {
            SqlxError::InvalidArgument(_) => {
                let response_code = ApiResponseCode::Failure;
                let response_payload = ApiResponsePayload {
                    msg: "Invalid credentials!".to_string(),
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

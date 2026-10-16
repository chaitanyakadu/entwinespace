pub mod refresh;
pub mod restricted;

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseCodeEnsureAuth, ApiResponseIssue,
        ApiResponsePayload, GetSessionsParams, RevokeSessionsParams,
    },
};
use sqlx::Error as SqlxError;
use tracing::debug;
use crate::utils::{routes::server_error_response_api, security::generate_sha2_hash};

use crate::api::database::{
    auth::get_userid_using_refresh_token,
    refresh_token::{get_all_sessions, revoke_all_refresh_tokens, revoke_refresh_token},
};

/*
curl \
--location 'http://localhost:3000/auth/sessions?limit=10' \
--header 'Cookie: refresh_token=123; access_token=123;' \
--data ''
*/
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetSessionsParams>,
    jar: CookieJar,
) -> Result<Response, Response> {
    if params.limit > 10 {
        let response_code = ApiResponseCode::Failure;
        let issue_payload = ApiResponseIssue {
            msg: "Invalid paramters! Limit should be in the range of 1-10".to_string(),
        };
        let api_response: ApiResponse<ApiResponseCode, (), ApiResponseIssue> = ApiResponse {
            code: response_code,
            status: false,
            payload: None,
            issue: Some(issue_payload),
        };
        return Ok((StatusCode::BAD_REQUEST, Json(api_response)).into_response());
    }

    let refresh_token = match jar.get("refresh_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };
    let refresh_token_hash = generate_sha2_hash(&refresh_token);

    let db = &state.pool;
    let user_id = get_userid_using_refresh_token(&refresh_token_hash, &db)
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

    let sessions_list = get_all_sessions(&user_id, params.limit, &db).await.unwrap();

    Ok((StatusCode::OK, Json(sessions_list)).into_response())
}

pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RevokeSessionsParams>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let config = &state.config;

    let refresh_token = match jar.get("refresh_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };
    let refresh_token_hash = generate_sha2_hash(&refresh_token);

    let db = &state.pool;
    let user_id = get_userid_using_refresh_token(&refresh_token_hash, &db)
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

    revoke_refresh_token(&refresh_token_hash, &db)
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

    if user_id == params.token_id {
        let redirect_uri = format!("{}/login", &config.metadata.frontend_url);
        let mut response = Redirect::to(&redirect_uri).into_response();
        response.headers_mut().remove("Cookie");
        return Ok(response);
    }

    Ok(StatusCode::OK.into_response())
}

pub async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RevokeSessionsParams>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let config = &state.config;

    let refresh_token = match jar.get("refresh_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };
    let refresh_token_hash = generate_sha2_hash(&refresh_token);

    let db = &state.pool;
    let user_id = get_userid_using_refresh_token(&refresh_token_hash, &db)
        .await
        .unwrap();

    revoke_all_refresh_tokens(&user_id, &db).await.unwrap();

    if user_id == params.token_id {
        let redirect_uri = format!("{}/login", &config.metadata.frontend_url);
        let mut response = Redirect::to(&redirect_uri).into_response();
        response.headers_mut().remove("Cookie");
        return Ok(response);
    }

    Ok(StatusCode::OK.into_response())
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

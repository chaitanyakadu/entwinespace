use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use redis::{AsyncCommands, aio::MultiplexedConnection};
use reqwest::StatusCode;
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCode, ApiResponseIssue, ApiResponsePayload, GetSessionsParams,
        RevokeSessionsParams,
    },
};
use sqlx::Error as SqlxError;
use tracing::warn;
use crate::utils::routes::server_error_response_api;
use uuid::Uuid;

use crate::api::{
    database::refresh_token::{get_all_sessions, revoke_refresh_token_using_id},
    handlers::session::unauthenticated_and_return,
};

pub async fn get_session_restricted(
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

    let session_token = match jar.get("session_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };

    let mut redis_conn: MultiplexedConnection = state.get_redis_conn().await?;
    let key = format!("auth_manage_session:{}", &session_token);
    let user_id: String = redis_conn.get(&key).await.map_err(|e| {
        warn!(error = ?e, "Redis query error");
        server_error_response_api().into_response()
    })?;
    let user_id: Uuid = Uuid::parse_str(&user_id).map_err(|e| {
        warn!(
            error = ?e,
            "failed to parse a uuid from the string"
        );
        server_error_response_api()
    })?;

    let db = &state.pool;
    let sessions_list = get_all_sessions(&user_id, params.limit, &db).await.unwrap();

    Ok((StatusCode::OK, Json(sessions_list)).into_response())
}

pub async fn revoke_session_restricted(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RevokeSessionsParams>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let config = &state.config;

    let session_token = match jar.get("session_token") {
        Some(v) => v.value().to_owned(),
        None => {
            return Ok(unauthenticated_and_return());
        }
    };

    let mut redis_conn: MultiplexedConnection = state.get_redis_conn().await?;
    let key = format!("auth_manage_session:{}", &session_token);
    let user_id: String = redis_conn.get(&key).await.map_err(|e| {
        warn!(error = ?e, "Redis query error");
        server_error_response_api().into_response()
    })?;
    let user_id: Uuid = Uuid::parse_str(&user_id).map_err(|e| {
        warn!(
            error = ?e,
            "failed to parse the user_id uuid from the string"
        );
        server_error_response_api()
    })?;

    let db = &state.pool;

    revoke_refresh_token_using_id(&params.token_id, &db)
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
        let redirect_uri = format!("{}/login", &config.frontend_service.url);
        let mut response = Redirect::to(&redirect_uri).into_response();
        response.headers_mut().remove("Cookie");
        return Ok(response);
    }

    redis_conn.del::<_, ()>(&key).await.map_err(|e| {
        warn!(error = ?e, "Redis delete error");
        server_error_response_api().into_response()
    })?;

    Ok(StatusCode::OK.into_response())
}

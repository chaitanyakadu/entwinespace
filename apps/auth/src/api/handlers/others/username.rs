use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use redis::{AsyncCommands, aio::MultiplexedConnection};
use reqwest::StatusCode;

use crate::schema::{
    app_state::AppState,
    routes::{ApiResponse, ApiResponseCode, ApiResponsePayload, UsernameAvailableParams},
};
use tracing::warn;

use crate::api::database::users::verify_username_available;

pub async fn get_username_available(
    State(state): State<Arc<AppState>>,
    Query(params): Query<UsernameAvailableParams>,
) -> Result<Response, Response> {
    let mut redis_conn: MultiplexedConnection = state.get_redis_conn().await?;

    let key = format!("username_available:{}", &params.username);
    let value: Option<bool> = redis_conn.get(&key).await.map_err(|e| {
        warn!(error = ?e, "Redis query error");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    if let Some(cached) = value {
        if !cached {
            return Ok((StatusCode::OK, Json(false)).into_response());
        } else {
            return Ok((StatusCode::OK, Json(true)).into_response());
        }
    }

    let db = &state.pool;
    let is_username_available = verify_username_available(&params.username, &db)
        .await
        .map_err(|e| e.into_response())?;

    if !is_username_available {
        redis_conn
            .set_ex::<_, _, ()>(key, false, 120)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Redis set value error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        let response_code = ApiResponseCode::Success;
        let response_payload = ApiResponsePayload {
            msg: "The username is already taken.".to_string(),
        };
        let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> = ApiResponse {
            code: response_code,
            status: true,
            payload: Some(response_payload),
            issue: None,
        };
        Err((StatusCode::OK, Json(api_response)).into_response())
    } else {
        redis_conn
            .set_ex::<_, _, ()>(key, true, 120)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Redis set value error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        let response_code = ApiResponseCode::Success;
        let response_payload = ApiResponsePayload {
            msg: "The username is available.".to_string(),
        };
        let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> = ApiResponse {
            code: response_code,
            status: false,
            payload: Some(response_payload),
            issue: None,
        };
        Ok((StatusCode::OK, Json(api_response)).into_response())
    }
}

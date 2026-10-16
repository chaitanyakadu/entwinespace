use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;
use crate::schema::app_state::AppState;
use crate::schema::middleware::{TurnstilePayload, TurnstileVerify};
use serde_json::json;
use tracing::warn;

// collect turnstile token from params and verify
// for more info - https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
pub async fn ensure_turnstile_verification(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TurnstilePayload>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let config = &state.config;

    let client = reqwest::Client::new();
    let res = client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&json!({
            "secret": config.third_party.turnstile_key,
            "response": params.token
        }))
        .send()
        .await
        .map_err(|e| {
            warn!(
                error = ?e,
                data = ?json!({"url": "challenges.cloudflare.com/turnstile/v0/siteverify", "method": "POST"}
                ),
                "Request to cloudflare for token verification failed"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let status_code = res.status();
    let json: TurnstileVerify = res.json().await.map_err(|e| {
        warn!(
            error = ?e,
            data = ?json!(
                {
                    "status_code": status_code.to_string(),
                    "url": "challenges.cloudflare.com/turnstile/v0/siteverify",
                    "method": "POST"
                }
            ),
            "Cloudflare for token verification response body is not in JSON format"
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    if json.success == true {
        Ok(next.run(req).await)
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

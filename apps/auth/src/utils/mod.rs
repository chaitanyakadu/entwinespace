pub mod oauth;
pub mod routes;
pub mod security;

use axum::{
    body::{Bytes, to_bytes},
    extract::Request,
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;
use tracing::warn;

pub async fn abstract_body<T>(req: &mut Request) -> Result<(T, Bytes), Response>
where
    T: serde::de::DeserializeOwned,
{
    let req_body = std::mem::take(req.body_mut());
    let req_bytes = to_bytes(req_body, 1024 * 1024).await.unwrap();
    let payload: T = serde_json::from_slice(&req_bytes).map_err(|e| {
        warn!(eror = ?e, "Unexpected json structure");
        StatusCode::BAD_REQUEST.into_response()
    })?;
    Ok((payload, req_bytes))
}

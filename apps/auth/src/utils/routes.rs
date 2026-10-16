use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{any::type_name, sync::Arc};

use aes_gcm::aead::OsRng;
use axum::{
    Json,
    extract::Request,
    response::{IntoResponse, Redirect, Response},
};
use redis::{AsyncCommands, aio::MultiplexedConnection};
use reqwest::{StatusCode, Url};
use crate::schema::routes::{ApiResponse, ApiResponseCode, ApiResponsePayload, EncKeyPair};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use tracing::{debug, error, warn};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn handle_req_extensions<T>(req: &Request) -> Arc<T>
where
    T: Send + Sync + 'static,
{
    Arc::clone(
        req.extensions()
            .get::<Arc<T>>()
            .ok_or_else(|| {
                error!(
                    data = ?json!({
                        "type_name": type_name::<Arc<T>>()
                    }),
                    "Unable to handle request extension");
            })
            .unwrap(),
    )
}

pub fn generate_encryption_keys() -> EncKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    EncKeyPair {
        public: STANDARD.encode(public.as_bytes()),
        private: STANDARD.encode(secret.to_bytes()),
    }
}

pub async fn get_redis_value<T>(
    mut redis_conn: MultiplexedConnection,
    key: String,
) -> Result<T, Response>
where
    T: DeserializeOwned + Serialize,
{
    let userinfo_str: Option<String> = redis_conn.get(&key).await.map_err(|e| {
        warn!(error = ?e, "Redis query error");
        server_error_response_api().into_response()
    })?;
    match userinfo_str {
        Some(v) => {
            let json = serde_json::from_str::<T>(v.as_str()).map_err(|e| {
                warn!(error = ?e, "Failed to deserialize to struct {}", type_name::<T>());
                server_error_response_api().into_response()
            })?;
            Ok(json)
        }
        None => Err(StatusCode::UNAUTHORIZED.into_response()),
    }
}

/// Frontend redirection
/// redirects the user along with query params
/// the redirection is specifically to the frontend_uri only
pub fn frontend_redirect(
    endpoint: &str,
    query: Vec<(String, String)>,
    frontend_uri: &str,
) -> Result<Response, Response> {
    let mut url = Url::parse_with_params(frontend_uri, &query).map_err(|e| {
        debug!(
            endpoint = ?endpoint,
            query = ?query,
            error = ?e,
            "failed to parse absolute url and add query params"
        );
        server_error_response_api().into_response()
    })?;
    url.set_path(endpoint);

    let redirect = Redirect::to(url.as_str());
    Ok(redirect.into_response())
}

/// standard response api for internal server error
pub fn server_error_response_api() -> Response {
    debug!("standard response api for internal server error");
    let response_code = ApiResponseCode::Failure;
    let response_payload = ApiResponsePayload {
        msg: "Server Error! Kindly try again later.".to_string(),
    };
    let api_response: ApiResponse<ApiResponseCode, ApiResponsePayload, ()> = ApiResponse {
        code: response_code,
        status: false,
        payload: Some(response_payload),
        issue: None,
    };
    (StatusCode::INTERNAL_SERVER_ERROR, Json(api_response)).into_response()
}

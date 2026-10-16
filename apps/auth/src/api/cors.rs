use std::sync::Arc;

use axum::http::{HeaderValue, Method, header};
use crate::schema::app_state::AppState;
use tower_http::cors::CorsLayer;

pub fn get_cors(app_state: Arc<AppState>) -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
        .allow_origin(
            app_state
                .config
                .metadata
                .frontend_url
                .parse::<HeaderValue>()
                .unwrap(),
        )
}

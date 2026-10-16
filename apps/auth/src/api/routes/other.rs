use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{delete, get, post},
};
use crate::schema::app_state::AppState;

use crate::api::{
    handlers::others::{
        delete::delete_account, health::get_health, logout::logout,
        oauth_uri::get_oauth_redirect_uri, username::get_username_available,
    },
    middleware::{ensure_authenticated::ensure_authenticated, ensure_guest::ensure_guest},
};

pub fn routers(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(get_health))
        .route(
            "/oauth-uri",
            get(get_oauth_redirect_uri).layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                ensure_guest,
            )),
        )
        .route(
            "/username-available",
            get(get_username_available).layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                ensure_authenticated,
            )),
        )
        .route("/logout", post(logout))
        .route("/delete", delete(delete_account))
        .with_state(app_state)
}

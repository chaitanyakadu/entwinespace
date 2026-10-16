use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, post},
};
use crate::schema::app_state::AppState;

use crate::api::{
    handlers::signup::{callback::get_signup_callback, create_account::post_signup_credentials},
    middleware::{
        ensure_guest::ensure_guest, ensure_turnstile_verification::ensure_turnstile_verification,
    },
};

pub fn routers(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/callback",
            get(get_signup_callback).layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                ensure_guest,
            )),
        )
        .route(
            "/credentials",
            post(post_signup_credentials)
                .layer(middleware::from_fn_with_state(
                    Arc::clone(&app_state),
                    ensure_guest,
                ))
                .layer(middleware::from_fn_with_state(
                    Arc::clone(&app_state),
                    ensure_turnstile_verification,
                )),
        )
        .with_state(Arc::clone(&app_state))
}

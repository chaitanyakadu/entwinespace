use std::sync::Arc;

use axum::{Router, middleware, routing::get};
use crate::schema::app_state::AppState;

use crate::api::{
    handlers::login::callback::get_login_callback, middleware::ensure_guest::ensure_guest,
};

pub fn routers(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/callback",
            get(get_login_callback).layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                ensure_guest,
            )),
        )
        .with_state(Arc::clone(&app_state))
}

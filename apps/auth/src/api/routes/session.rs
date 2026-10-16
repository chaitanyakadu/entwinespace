use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, put},
};
use crate::schema::app_state::AppState;

use crate::api::{
    handlers::session::{
        get_session,
        refresh::refresh_token,
        restricted::{get_session_restricted, revoke_session_restricted},
        revoke_session,
    },
    middleware::ensure_authenticated::ensure_authenticated,
};

pub fn routers(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/sessions",
            get(get_session)
                .delete(revoke_session)
                .layer(middleware::from_fn_with_state(
                    Arc::clone(&app_state),
                    ensure_authenticated,
                )),
        )
        .route(
            "/sessions/refresh-token",
            put(refresh_token).layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                ensure_authenticated,
            )),
        )
        .route(
            "/manage-sessions",
            get(get_session_restricted).delete(revoke_session_restricted),
        )
        .with_state(Arc::clone(&app_state))
}

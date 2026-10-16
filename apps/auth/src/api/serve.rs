use std::sync::Arc;

use axum::{Router, middleware, routing::get};
use crate::schema::app_state::AppState;
use tracing::{error, info};

use crate::{
    api::{
        cors::get_cors,
        middleware::{logging::prometheus_logs, rate_limiter::rate_limit},
        routes::{login, other, session, signup},
    },
    prometheus::{UPTIME, metrics_handler},
};

pub async fn serve(app_state: Arc<AppState>) -> anyhow::Result<()> {
    let config = &app_state.config;

    let app = router(Arc::clone(&app_state));

    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        &config.metadata.hostname, &config.metadata.port
    ))
    .await
    .inspect_err(|e| error!(error = ?e))?;

    info!(
        "The authentication server is listening on {}:{}",
        &config.metadata.hostname, &config.metadata.port
    );

    UPTIME.inc();

    axum::serve(listener, app)
        // todo - implement graceful shutdown
        //.with_graceful_shutdown(signal)
        .await
        .inspect_err(|e| error!(error = ?e))?;

    UPTIME.dec();
    Ok(())
}

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .with_state(Arc::clone(&app_state))
        // health, oauth-uri, check-username, logout
        .nest("/auth", other::routers(Arc::clone(&app_state)))
        // callback, credentials
        .nest("/auth/signup", signup::routers(Arc::clone(&app_state)))
        // callback
        // todo - add credentails based login
        .nest("/auth/login", login::routers(Arc::clone(&app_state)))
        // session - get & delete, refresh token
        .nest("/auth", session::routers(Arc::clone(&app_state)))
        // todo - we should have a superuser/admin who can access restriced endpoints
        .route("/auth/metrics", get(metrics_handler))
        .layer(get_cors(Arc::clone(&app_state)))
        .layer(middleware::from_fn(prometheus_logs))
        .layer(middleware::from_fn(rate_limit))
}

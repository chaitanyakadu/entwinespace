use std::sync::Arc;

use axum::{Router, routing::get};
use tracing::{error, info};
use crate::schema::app_state::AppState;

pub async fn serve(app_state: Arc<AppState>) -> anyhow::Result<()> {
    let app = router(Arc::clone(&app_state));

    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        &app_state.config.backend_service.hostname, 
        &app_state.config.backend_service.port
    ))
    .await
    .inspect_err(|e| error!(error = ?e))?;

    info!(
        "The authentication server is listening on {}:{}",
        &app_state.config.backend_service.hostname, 
        &app_state.config.backend_service.port
    );

    axum::serve(listener, app)
        // todo - implement graceful shutdown
        //.with_graceful_shutdown(signal)
        .await
        .inspect_err(|e| error!(error = ?e))?;

    Ok(())
}

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .with_state(Arc::clone(&app_state))
        .route("/api/v1/health", get(|| async { "Hello, World!" }))
}

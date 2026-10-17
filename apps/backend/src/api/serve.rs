use axum::{Router, routing::get};
use tracing::{error, info};

pub async fn serve() -> anyhow::Result<()> {
    let app = router();

    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        "", ""
    ))
    .await
    .inspect_err(|e| error!(error = ?e))?;

    info!(
        "The authentication server is listening on {}:{}",
        "", ""
    );

    axum::serve(listener, app)
        // todo - implement graceful shutdown
        //.with_graceful_shutdown(signal)
        .await
        .inspect_err(|e| error!(error = ?e))?;

    Ok(())
}

pub fn router() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
}

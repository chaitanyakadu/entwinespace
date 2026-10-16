mod schema;
use std::sync::Arc;

use auth::api::serve::serve;
use dotenvy::dotenv;
use auth::schema::app_state::{AppState, Config};
use sqlx::PgPool;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    // initial setup
    // postgres pool, redis client and configs
    info!("Starting application");
    let config = Config::from_env();

    debug!("Connecting to PostgreSQL");
    let pool = PgPool::connect(&config.metadata.postgres_url)
        .await
        .inspect_err(|e| error!(error = ?e, "Failed to connect postgres database"))?;

    debug!("Creating Redis Client");
    let redis_client = redis::Client::open(&*config.metadata.redis_url)?;
    let redis_client = Arc::new(redis_client);

    debug!("Building the AppState");
    let app_state = Arc::new(AppState {
        redis_client,
        pool,
        config,
    });
    info!("Application initialization completed");

    serve(app_state).await.map_err(|e| {
        error!(
            error = ?e,
            "Error occured from the api serve function"
        );
        e
    })?;
    Ok(())
}

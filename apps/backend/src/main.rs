pub mod api;
pub mod schema;

use std::sync::Arc;

use api::serve::serve;
use schema::app_state::AppState;
use dotenvy::dotenv;
use sqlx::PgPool;
use tracing::{debug, error};
use tracing_subscriber::EnvFilter;
use app_schema::config::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = AppConfig::from_env()
        .inspect_err(|e| error!(error = ?e, "Failed to parse application configurations"))
        .unwrap();

    let pool = PgPool::connect(&config.database.url)
        .await
        .inspect_err(|e| error!(error = ?e, "Failed to connect postgres database"))?;

    debug!("Creating Redis Client");
    let redis_client = redis::Client::open(config.redis.url.to_string())?;
    let redis = Arc::new(redis_client);

    let app_state = Arc::new(AppState {
        redis_client: redis,
        pool,
        config
    });

    serve(app_state).await.map_err(|e| {
        error!(
            error = ?e,
            "Error occured from the api serve function"
        );
        e
    })?;

    Ok(())
}


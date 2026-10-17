pub mod api;

use api::serve::serve;
use dotenvy::dotenv;
use sqlx::PgPool;
use tracing::{debug, error};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let _pool = PgPool::connect("")
        .await
        .inspect_err(|e| error!(error = ?e, "Failed to connect postgres database"))?;

    debug!("Creating Redis Client");
    let _redis_client = redis::Client::open("")?;


    serve().await.map_err(|e| {
        error!(
            error = ?e,
            "Error occured from the api serve function"
        );
        e
    })?;

    Ok(())
}

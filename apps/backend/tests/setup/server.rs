use std::sync::Arc;

use app_schema::config::AppConfig;
use backend::{api::serve::router, schema::app_state::AppState};
use axum_test::TestServer;
use sqlx::PgPool;

pub async fn create_server() -> TestServer {
    let config = AppConfig::from_env()
        .unwrap();

    let pool = PgPool::connect(&config.database.url)
        .await
        .unwrap();

    let redis_client = redis::Client::open(config.redis.url.to_string())
        .unwrap();
    let redis = Arc::new(redis_client);

    let app_state = Arc::new(AppState {
        redis_client: redis,
        pool,
        config
    });

    let app = router(app_state);

    axum_test::TestServer::new(app)
}

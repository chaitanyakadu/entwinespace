use std::sync::Arc;

use auth::api::serve::router;
use axum_test::TestServer;
use auth::schema::app_state::{AppState, Config};
use sqlx::PgPool;

pub async fn create_server(config: Config, pool: PgPool) -> TestServer {
    let redis_client = redis::Client::open(&*config.metadata.redis_url).unwrap();
    let redis_client = Arc::new(redis_client);
    let app_state = Arc::new(AppState {
        redis_client,
        pool,
        config,
    });
    let app = router(Arc::clone(&app_state));

    axum_test::TestServer::new(app)
}

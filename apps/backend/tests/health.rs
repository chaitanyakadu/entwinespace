#[path = "./setup/server.rs"]
pub mod server;

use sqlx::PgPool;
use server::create_server;

#[sqlx::test(migrations = "../../packages/db/migrations")]
async fn health_check(_pool: PgPool) {
    let server = create_server().await;

    let response = server.get("/api/v1/health").await;
    assert_eq!(response.text(), "Hello, World!");
}

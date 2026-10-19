#[path = "../setup/database.rs"]
pub mod database;

#[path = "../setup/server.rs"]
pub mod server;

#[path = "../setup/config.rs"]
pub mod config;

use std::sync::Arc;

use reqwest::StatusCode;
use sqlx::PgPool;
use database::database_seeding;

use crate::profile::server::create_server;

#[sqlx::test(migrations = "../../packages/db/migrations")]
async fn space(pool: PgPool) {
    let db = Arc::new(pool);

    database_seeding(Arc::clone(&db))
        .await
        .unwrap();

    let url = format!("/api/v1/user/space?id={}", "12234");
    let response = create_server()
        .await
        .get(&url)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

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

use crate::{config::USERS, profile::server::create_server};

#[sqlx::test(migrations = "../../packages/db/migrations")]
async fn profile(pool: PgPool) {
    // create user, token, profile

    // test cases
    // 2. fetch personal profile -> Get info
    // 3. fetch others profile -> Get limited info
    // 4. update profile status -> success
    let db = Arc::new(pool);

    database_seeding(Arc::clone(&db))
        .await
        .unwrap();

    let url = format!("/api/v1/user/profile?username={}", USERS[0].0);
    let response = create_server()
        .await
        .get(&url)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

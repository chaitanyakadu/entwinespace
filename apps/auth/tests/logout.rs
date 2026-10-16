#[path = "./common/mod.rs"]
mod common;

use std::sync::Arc;

use common::axum::create_server;
use common::database::create_new_user;

use reqwest::StatusCode;
use auth::schema::app_state::Config;
use auth::utils::security::generate_sha2_hash;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../packages/db/migrations")]
async fn logout(pool: PgPool) {
    let config = Config::from_env();
    let server = create_server(config.clone(), pool.clone()).await;

    let db = Arc::new(pool);
    let new_user_entry = create_new_user(Arc::clone(&db), config).await;

    let token_hash = generate_sha2_hash(&new_user_entry.token);
    let cookie = format!("refresh_token={}", &new_user_entry.token);
    let response = server
        .post("/auth/logout")
        .add_header("Cookie", cookie)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let res_cookie = response.headers().get("Cookie");
    assert_eq!(res_cookie, None);

    let refresh_table = sqlx::query!(
        r#"
        SELECT revoked_at
        FROM refresh_token
        WHERE token_hash = $1
        "#,
        token_hash
    )
    .fetch_one(&*db)
    .await
    .unwrap();
    assert_ne!(refresh_table.revoked_at, None);
}

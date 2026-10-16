use std::sync::Arc;

use redis::{AsyncTypedCommands, aio::MultiplexedConnection};
use reqwest::StatusCode;
use auth::schema::{
    app_state::{AppState, Config},
    routes::{SignupCredentials, Userinfo},
};
use sqlx::PgPool;

use crate::common::{axum::create_server, database::create_new_user};

#[path = "./common/mod.rs"]
mod common;

#[sqlx::test(migrations = "../../packages/db/migrations")]
// // signup using already used credentials
// test 1 - used email
// test 2 - used username
// // signup using valid credentials
// test 3 - valid credentials
async fn signup_credentials(pool: PgPool) {
    let config = Config::from_env();
    let server = create_server(config.clone(), pool.clone()).await;

    let db = Arc::new(pool.clone());
    let new_user_entry = create_new_user(Arc::clone(&db), config.clone()).await;

    let redis_url = config.clone().metadata.redis_url;
    let redis_client = redis::Client::open(redis_url).unwrap();
    let redis_client = Arc::new(redis_client);

    let app_state = Arc::new(AppState {
        redis_client,
        pool,
        config,
    });
    let userinfo_1 = Userinfo {
        email: new_user_entry.credentials.email.clone(),
        picture: String::from(""),
        verified_email: true,
        id: String::from(""),
        family_name: Some(String::from("")),
        given_name: Some(String::from("")),
    };

    let mut redis_conn: MultiplexedConnection = app_state.get_redis_conn().await.unwrap();
    let userinfo_1_redis_key =
        format!("auth_signup_userinfo:{}", &new_user_entry.credentials.email);
    let userinfo_1_str = serde_json::to_string(&userinfo_1).unwrap();

    redis_conn
        .set_ex::<_, _>(userinfo_1_redis_key, userinfo_1_str, 60) // exp in 60 sec
        .await
        .unwrap();

    let response_1 = server
        .post("/auth/signup/credentials")
        .add_query_param("token", "2222")
        .json(&new_user_entry.credentials)
        .await;

    // test 1 - signup using the already used email
    assert_eq!(response_1.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    // todo - skipped the implementation of test 2

    let credentials_2 = SignupCredentials {
        id: String::from("ce64b7ca-18ea-4423-92cc-845fc71989c3"),
        email: String::from("test_2@user.com"),
        username: String::from("test_user_2"),
        contact: String::from("12345 54321"),
        password: String::from("test_pass_2"),
        name: String::from("Test User 2"),
    };

    let userinfo_2 = Userinfo {
        email: credentials_2.email.to_string(),
        picture: String::from(""),
        verified_email: true,
        id: credentials_2.id.to_string(),
        family_name: Some(String::from("")),
        given_name: Some(String::from("")),
    };

    let userinfo_2_redis_key = format!("auth_signup_userinfo:{}", &credentials_2.email);
    let userinfo_2_str = serde_json::to_string(&userinfo_2).unwrap();

    redis_conn
        .set_ex::<_, _>(userinfo_2_redis_key, userinfo_2_str, 60) // exp in 60 sec
        .await
        .unwrap();

    let response_2 = server
        .post("/auth/signup/credentials")
        .add_query_param("token", "2222")
        .json(&credentials_2)
        .await;

    // test 3 - signup using valid credentials
    assert_eq!(response_2.status_code(), StatusCode::OK);
}

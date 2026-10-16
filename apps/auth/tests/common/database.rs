use std::sync::Arc;

use auth::schema::{
    app_state::Config,
    routes::SignupCredentials,
    tests::{NewUserEntry, RefreshToken, Users},
};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use auth::utils::security::{generate_sha2_hash, sym_encryption};
use uuid::Uuid;

pub async fn create_new_user(db: Arc<PgPool>, config: Config) -> NewUserEntry {
    let mut tx = db.begin().await.unwrap();

    let payload = SignupCredentials {
        id: String::from(""),
        username: String::from("test_username"),
        password: String::from("test_password"),
        name: String::from("Test User"),
        email: String::from("test@user.com"),
        contact: String::from("12345 54321"),
    };
    let hashed_pass = generate_sha2_hash(&payload.password);
    let hashed_email = generate_sha2_hash(&payload.email);
    let hashed_contact = generate_sha2_hash(&payload.contact);

    let email_encrypted =
        sym_encryption(&payload.email, &config.security.symmetric_enc_secret).unwrap();
    let contact_encrypted =
        sym_encryption(&payload.contact, &config.security.symmetric_enc_secret).unwrap();

    let user = sqlx::query_as!(
        Users,
        r#"
    INSERT INTO users (
        username,
        password,
        name,
        email_hash,
        email_encrypted,
        contact_hash,
        contact_encrypted
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
    "#,
        payload.username,
        hashed_pass,
        payload.name,
        hashed_email,
        email_encrypted,
        hashed_contact,
        contact_encrypted
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    let user_id = user.id;
    let verified_email = true;
    let picture = String::from("img_url.com");

    sqlx::query!(
        r#"
    INSERT INTO oauth_identity (
        user_id,
        is_verified,
        image
    )
    VALUES ($1, $2, $3)
    "#,
        user_id,
        verified_email,
        picture
    )
    .execute(&mut *tx)
    .await
    .unwrap();

    let token_uuid = Uuid::new_v4().to_string();
    let token_hash = generate_sha2_hash(&token_uuid);
    let expires_at = OffsetDateTime::now_utc() + Duration::days(60);

    let user_agent = String::from("Mozilla/5.0 (X11; Linux x86_64)");
    let user_ip = String::from("127.0.0.1");

    let refresh_token = sqlx::query_as!(
        RefreshToken,
        r#"
    INSERT INTO refresh_token (
        user_id,
        token_hash,
        expires_at,
        user_agent,
        created_by_ip,
        last_used_ip
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6
    )
    RETURNING *
    "#,
        user_id,
        token_hash,
        expires_at,
        user_agent,
        user_ip,
        user_ip
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();

    tx.commit().await.unwrap();

    NewUserEntry {
        users: user,
        refresh_token,
        credentials: payload,
        token: token_uuid,
    }
}

#[path = "../setup/config.rs"]
pub mod config;

use std::sync::Arc;
use sqlx::PgPool;
use config::USERS;


pub async fn database_seeding(pool: Arc<PgPool>) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;

    for (
        username,
        password,
        name,
        email_hash,
        contact_hash,
        avatar,
        banner,
    ) in USERS
    {
        let user = sqlx::query!(
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
            RETURNING id
            "#,
            username,
            password,
            name,
            email_hash,
            format!("encrypted-email-{username}").into_bytes(),
            contact_hash,
            format!("encrypted-contact-{username}").into_bytes()
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO oauth_identity (
                user_id,
                is_verified,
                image
            )
            VALUES ($1, $2, $3)
            "#,
            user.id,
            true,
            "https://example.com/oauth.png"
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO profile (
                user_id,
                status,
                avatar,
                banner
            )
            VALUES ($1, $2, $3, $4)
            "#,
            user.id,
            "active",
            avatar,
            banner
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO settings (
                user_id,
                notifications,
                nearby_audio,
                keybindings
            )
            VALUES ($1, $2, $3, $4)
            "#,
            user.id,
            1,
            true,
            "1:a,2:d,3:s"
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(())
}


use crate::schema::routes::{OauthIdentity, RefreshToken, UserData};
use sqlx::{Error, PgPool, Postgres, Transaction};
use tracing::{debug, warn};
use uuid::Uuid;

/// Add a new user
/// returns the user id in case of success
/// returns the status code in case of failure
pub async fn add_new_user(
    userdata: &UserData,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Uuid, Error> {
    debug!(
        username = ?userdata.username,
        "add a new user entry"
    );
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
        userdata.username,
        userdata.password,
        userdata.name,
        userdata.email_hash,
        userdata.email_encrypted,
        userdata.contact_hash,
        userdata.contact_encrypted,
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| {
        warn!(error = ?e, "failed to insert new user");
        e
    })?;

    Ok(user.id)
}

/// Add a new oauth identity entry
pub async fn add_oauth_identity(
    oauth_identity: &OauthIdentity,
    user_id: &Uuid,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), Error> {
    debug!(
        user_id = ?user_id,
        "add a new oauth identity entry"
    );
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
        oauth_identity.is_verified,
        oauth_identity.image
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        warn!(error = ?e, "failed to insert new oauth identity");
        e
    })?;

    Ok(())
}

/// Add a new refresh token entry
pub async fn add_new_refresh_token(
    refresh_token: &RefreshToken,
    user_id: &Uuid,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), Error> {
    debug!("adding new refresh token entry");
    sqlx::query!(
        r#"
    INSERT INTO refresh_token (
        user_id,
        token_hash,
        expires_at,
        user_agent,
        created_by_ip,
        last_used_ip
    )
    VALUES ($1, $2, $3, $4, $5, $6)"#,
        user_id,
        refresh_token.token_hash,
        refresh_token.expires_at,
        refresh_token.user_agent,
        refresh_token.created_by_ip,
        refresh_token.last_used_ip
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        warn!(error = ?e, "failed to insert new refresh token");
        e
    })?;

    Ok(())
}

pub async fn get_userid_using_refresh_token(
    hashed_refresh_token: &str,
    db: &PgPool,
) -> Result<Uuid, Error> {
    debug!("get the user_id using the refresh token");
    let refresh_token = sqlx::query!(
        r#"SELECT user_id
    FROM refresh_token
    WHERE token_hash = $1"#,
        hashed_refresh_token
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to find the userid"
        );
        e
    })?;

    Ok(refresh_token.user_id)
}

pub async fn get_userid_using_username(username: &str, db: &PgPool) -> Result<Uuid, Error> {
    debug!(
        username = ?username,
        "get the user_id using the username"
    );
    let users = sqlx::query!(
        r#"SELECT id
    FROM users
    WHERE username = $1"#,
        username
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to find the userid"
        );
        e
    })?;

    Ok(users.id)
}

/// get the user_id using the email hash
pub async fn get_userid_using_email(email_hash: &str, db: &PgPool) -> Result<Uuid, Error> {
    debug!("get the user_id using the email hash");
    let users = sqlx::query!(
        r#"SELECT id
    FROM users
    WHERE email_hash = $1"#,
        email_hash
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to find the userid"
        );
        e
    })?;

    Ok(users.id)
}

/// Verify if the email already exists
/// returns Result<bool, StatusCode>
pub async fn email_exists(email_hash: &str, db: &PgPool) -> Result<bool, Error> {
    debug!("verify if the email already exists");

    let users = sqlx::query!(
        r#"SELECT id
    FROM users
    WHERE email_hash = $1"#,
        email_hash
    )
    .fetch_one(db)
    .await;

    match users {
        Err(e) => match e {
            Error::InvalidArgument(_) => {
                debug!(
                    error = ?e,
                    "invalid credentials"
                );
                Err(e)
            }
            Error::RowNotFound => {
                return Ok(false);
            }
            _ => {
                debug!(
                    error = ?e,
                    "failed to verify if the email already exists"
                );
                Err(e)
            }
        },
        Ok(_) => Ok(true),
    }
}

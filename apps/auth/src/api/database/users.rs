use reqwest::StatusCode;
use crate::schema::routes::UserData;
use sqlx::{Error, PgPool};
use tracing::{debug, warn};
use uuid::Uuid;

pub async fn update_email(
    username: &str,
    new_email_hash: &str,
    new_email_encrypted: &Vec<u8>,
    db: &PgPool,
) -> Result<Uuid, StatusCode> {
    debug!("updating the user email");
    let record = sqlx::query!(
        r#"
        UPDATE users
        SET email_hash = $1, email_encrypted = $2
        WHERE username = $3
        RETURNING id
        "#,
        new_email_hash,
        new_email_encrypted,
        username
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            username = ?username,
            "failed to update user email"
        );
        match e {
            Error::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            Error::RowNotFound => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    Ok(record.id)
}

pub async fn update_contact(
    username: &str,
    new_contact_hash: &str,
    new_contact_encrypted: &Vec<u8>,
    db: &PgPool,
) -> Result<Uuid, StatusCode> {
    debug!("updating the user contact");
    let record = sqlx::query!(
        r#"
        UPDATE users
        SET contact_hash = $1, contact_encrypted = $2
        WHERE username = $3
        RETURNING id
        "#,
        new_contact_hash,
        new_contact_encrypted,
        username
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            username = ?username,
            "failed to update user email"
        );
        match e {
            Error::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            Error::RowNotFound => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    Ok(record.id)
}

pub async fn update_userinfo(
    username: &str,
    new_credentials: UserData,
    db: &PgPool,
) -> Result<(), StatusCode> {
    debug!("updating the userinfo");
    sqlx::query!(
        r#"
        UPDATE users
        SET 
            contact_hash = $1, 
            contact_encrypted = $2, 
            email_hash = $3,
            email_encrypted = $4,
            username = $5,
            password = $6
        WHERE username = $7
        RETURNING id
        "#,
        new_credentials.contact_hash,
        new_credentials.contact_encrypted,
        new_credentials.email_hash,
        new_credentials.email_encrypted,
        new_credentials.username,
        new_credentials.password,
        username
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            username = ?username,
            "failed to update user email"
        );
        match e {
            Error::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            Error::RowNotFound => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    })?;

    Ok(())
}

/// Verify if the username is available
/// returns Result<bool, StatusCode>
///
/// in case of success if the bool is true it means the username is available
pub async fn verify_username_available(username: &str, db: &PgPool) -> Result<bool, StatusCode> {
    debug!("verify if the username is available");
    let record = sqlx::query!(
        r#"SELECT id 
        FROM users
        WHERE username = $1"#,
        username
    )
    .fetch_one(db)
    .await;

    match record {
        Err(e) => {
            warn!(
                error = ?e,
                username = ?username,
                "failed to verify if the username is available"
            );
            match e {
                Error::InvalidArgument(_) => Err(StatusCode::BAD_REQUEST),
                Error::RowNotFound => Ok(true),
                _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        Ok(_) => Ok(false),
    }
}

/// Get username and id using the email hash
/// in case of success it returns (username, user_id)
pub async fn get_username_and_id_using_email(
    email_hash: &str,
    db: &PgPool,
) -> Result<(String, Uuid), Error> {
    debug!("fetch the username and id using email hash");
    // todo - make sure to handle error if the account is revoked
    let record = sqlx::query!(
        r#"SELECT id, username
        FROM users
        WHERE email_hash = $1 AND revoked_at IS NULL"#,
        email_hash
    )
    .fetch_one(db)
    .await;

    match record {
        Err(e) => {
            warn!(
                error = ?e,
                "failed to fetch the username and id using email hash"
            );
            Err(e)
        }
        Ok(v) => Ok((v.username, v.id)),
    }
}

pub async fn delete_user(username: &str, password: &str, db: &PgPool) -> Result<Uuid, Error> {
    debug!("fetch the username and id using email hash");
    // todo - make sure to handle error if the account is already revoked
    let record = sqlx::query!(
        r#"UPDATE users
        SET revoked_at = NOW()
        WHERE username = $1 AND password = $2 AND revoked_at IS NULL
        RETURNING id"#,
        username,
        password
    )
    .fetch_one(db)
    .await;

    match record {
        Err(e) => {
            warn!(
                error = ?e,
                "failed to delete the user"
            );
            Err(e)
        }
        Ok(v) => Ok(v.id),
    }
}

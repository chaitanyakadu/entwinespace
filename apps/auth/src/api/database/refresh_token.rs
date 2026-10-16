use crate::schema::{
    routes::{RefreshTokenState, SessionsList},
    security::ValidateRefreshTokenMethod,
};
use sqlx::{Error, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{debug, warn};
use uuid::Uuid;

pub async fn revoke_refresh_token(refresh_token_hash: &str, db: &PgPool) -> Result<(), Error> {
    debug!("revoke the refresh token");
    let now = OffsetDateTime::now_utc();
    sqlx::query!(
        r#"
        UPDATE refresh_token
        SET revoked_at = $1
        WHERE token_hash = $2
        "#,
        now,
        refresh_token_hash
    )
    .execute(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to revoke the refresh token"
        );
        e
    })?;

    Ok(())
}

pub async fn revoke_refresh_token_using_id(id: &Uuid, db: &PgPool) -> Result<(), Error> {
    debug!("revoke the refresh token");
    let now = OffsetDateTime::now_utc();
    sqlx::query!(
        r#"
        UPDATE refresh_token
        SET revoked_at = $1
        WHERE id = $2
        "#,
        now,
        id
    )
    .execute(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to revoke the refresh token"
        );
        e
    })?;

    Ok(())
}

pub async fn revoke_all_refresh_tokens(user_id: &Uuid, db: &PgPool) -> Result<(), Error> {
    debug!("revoke all the refresh token");
    let now = OffsetDateTime::now_utc();
    sqlx::query!(
        r#"
        UPDATE refresh_token
        SET revoked_at = $1
        WHERE user_id = $2
        "#,
        now,
        user_id
    )
    .execute(db)
    .await
    .map_err(|e| {
        warn!(
            error = ?e,
            "failed to revoke the refresh token"
        );
        e
    })?;

    Ok(())
}

/// validate the refresh_token
/// returns RefreshTokenState enum
pub async fn validate_refresh_token(
    key: &str,
    method: ValidateRefreshTokenMethod,
    db: &PgPool,
) -> Result<RefreshTokenState, Error> {
    match method {
        ValidateRefreshTokenMethod::Username => {
            let record = sqlx::query!(
                r#"
            SELECT refresh_token.revoked_at, refresh_token.expires_at
            FROM refresh_token
            JOIN users on users.id = refresh_token.user_id
            WHERE username = $1
        "#,
                key
            )
            .fetch_one(db)
            .await;
            let record = match record {
                Err(e) => {
                    warn!(
                        error = ?e,
                        "failed to revoke the refresh token"
                    );

                    if let Error::RowNotFound = e {
                        return Ok(RefreshTokenState::Invalid);
                    }

                    return Err(e);
                }
                Ok(v) => v,
            };

            let now = OffsetDateTime::now_utc();
            if record.revoked_at.is_some() {
                return Ok(RefreshTokenState::Revoked);
            } else if record.expires_at <= now {
                return Ok(RefreshTokenState::Revoked);
            } else {
                return Ok(RefreshTokenState::Valid);
            }
        }
        ValidateRefreshTokenMethod::RefreshTokenHash => {
            let record = sqlx::query!(
                r#"
            SELECT revoked_at, expires_at
            FROM refresh_token
            WHERE token_hash = $1
        "#,
                key
            )
            .fetch_one(db)
            .await;

            match record {
                Err(e) => {
                    warn!(
                        error = ?e,
                        "failed to revoke the refresh token"
                    );

                    if let Error::RowNotFound = e {
                        return Ok(RefreshTokenState::Invalid);
                    }

                    Err(e)
                }
                Ok(v) => {
                    let now = OffsetDateTime::now_utc();
                    if v.revoked_at.is_some() {
                        return Ok(RefreshTokenState::Revoked);
                    } else if v.expires_at >= now {
                        return Ok(RefreshTokenState::Revoked);
                    } else {
                        return Ok(RefreshTokenState::Valid);
                    }
                }
            }
        }
    }
}

pub async fn get_all_sessions(
    user_id: &Uuid,
    limit: i64,
    db: &PgPool,
) -> Result<Vec<SessionsList>, Error> {
    let sessions_list = sqlx::query_as!(
        SessionsList,
        r#"
        SELECT id, expires_at, revoked_at, user_agent, created_by_ip, created_at
        FROM refresh_token
        WHERE user_id = $1
        LIMIT $2
        "#,
        user_id,
        limit
    )
    .fetch_all(&*db)
    .await
    .map_err(|e| {
        warn!(error = ?e, "failed to insert refresh token");
        e
    })?;

    Ok(sessions_list)
}

/// Get the total number of active sessions
pub async fn num_active_sessions(
    user_id: &Uuid,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<String>, Error> {
    debug!("adding new refresh token entry");
    let record: Vec<String> = sqlx::query_scalar!(
        r#"
    SELECT 
        token_hash
    FROM refresh_token
    WHERE 
        revoked_at IS NULL 
        AND expires_at > NOW() 
        AND user_id = $1"#,
        user_id,
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| {
        warn!(error = ?e, "failed to count the active sessions");
        e
    })?;

    Ok(record)
}

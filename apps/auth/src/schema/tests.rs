use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::schema::routes::SignupCredentials;

#[derive(Debug, Serialize, Deserialize)]
pub struct Users {
    pub id: Uuid,
    pub username: String,
    pub password: String,
    pub name: String,

    pub email_hash: String,
    pub email_encrypted: Vec<u8>,
    pub contact_hash: Option<String>,
    pub contact_encrypted: Option<Vec<u8>>,

    pub revoked_at: Option<OffsetDateTime>,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,

    pub token_hash: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub replaces_by_token_id: Option<String>,

    pub user_agent: Option<String>,
    pub created_by_ip: String,
    pub last_used_ip: String,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUserEntry {
    pub users: Users,
    pub refresh_token: RefreshToken,
    pub token: String,
    pub credentials: SignupCredentials,
}

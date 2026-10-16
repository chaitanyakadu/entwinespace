use std::{env::VarError, sync::Arc};

use axum::response::{IntoResponse, Response};
use redis::{Client, aio::MultiplexedConnection};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub hostname: String,
    pub port: u16,
    pub version: String, // api version

    // urls
    pub postgres_url: String,
    pub redis_url: String,

    pub frontend_url: String,
}

impl Metadata {
    pub fn from_env() -> Result<Self, VarError> {
        Ok(Self {
            hostname: std::env::var("AUTH_SERVER_HOSTNAME")?,
            port: std::env::var("AUTH_SERVER_PORT")?.parse().unwrap(),
            version: std::env::var("VERSION")?,

            postgres_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL")?,

            frontend_url: std::env::var("FRONTEND_SERVER")?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Security {
    pub argon_hash_secret: String,
    pub symmetric_enc_secret: String,
    pub jwt_secret: String,
}

impl Security {
    pub fn from_env() -> Result<Self, VarError> {
        Ok(Self {
            argon_hash_secret: std::env::var("ARGON_HASH_SECRET")?,
            symmetric_enc_secret: std::env::var("SYMMETRIC_ENC_SECRET")?,
            jwt_secret: std::env::var("JWT_SECRET")?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThirdPartyConfig {
    pub turnstile_key: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,
}

impl ThirdPartyConfig {
    pub fn from_env() -> Result<Self, VarError> {
        Ok(Self {
            turnstile_key: std::env::var("TURNSTILE_SECRET_KEY")?,
            google_client_id: std::env::var("GOOGLE_CLIENT_ID")?,
            google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET")?,
            google_redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum AppEnv {
    Development,
    Production,
}

impl AppEnv {
    pub fn from_env() -> Self {
        match std::env::var("APP_ENV")
            .unwrap_or_else(|_| "development".into())
            .as_str()
        {
            "production" => Self::Production,
            _ => Self::Development,
        }
    }

    pub fn is_dev(&self) -> bool {
        matches!(self, Self::Development)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub metadata: Metadata,
    pub security: Security,
    pub third_party: ThirdPartyConfig,
    pub app_env: AppEnv,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            metadata: Metadata::from_env().unwrap(),
            security: Security::from_env().unwrap(),
            third_party: ThirdPartyConfig::from_env().unwrap(),
            app_env: AppEnv::from_env(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub redis_client: Arc<Client>,
    pub pool: PgPool,
    pub config: Config,
}

impl AppState {
    pub async fn get_redis_conn(&self) -> Result<MultiplexedConnection, Response> {
        let redis_client = &self.redis_client;
        let redis_conn = redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                error!(error = ?e, "Redis client connection error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        Ok(redis_conn)
    }
}

use std::{env, num::ParseIntError};

use serde::{Deserialize, Serialize};

/// ================================
/// Configuration Error
/// ================================

#[derive(Debug)]
pub enum ConfigError {
    MissingEnvVar(env::VarError),
    InvalidNumber(ParseIntError),
}

impl From<env::VarError> for ConfigError {
    fn from(err: env::VarError) -> Self {
        Self::MissingEnvVar(err)
    }
}

impl From<ParseIntError> for ConfigError {
    fn from(err: ParseIntError) -> Self {
        Self::InvalidNumber(err)
    }
}

/// ================================
/// Application
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub app_env: String,
    pub rust_log: String,

    pub backend_service: BackendService,
    pub auth_service: AuthService,
    pub frontend_service: FrontendService,

    pub cloudflare: CloudflareConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub google_oauth: GoogleOAuthConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            app_env: env::var("APP_ENV")?,
            rust_log: env::var("RUST_LOG")?,

            backend_service: BackendService::from_env()?,
            auth_service: AuthService::from_env()?,
            frontend_service: FrontendService::from_env()?,

            cloudflare: CloudflareConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            redis: RedisConfig::from_env()?,
            google_oauth: GoogleOAuthConfig::from_env()?,
        })
    }
}

/// ================================
/// Backend Service
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendService {
    pub hostname: String,
    pub port: u16,
    pub version: String,
}

impl BackendService {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            hostname: env::var("BACKEND_SERVICE_HOSTNAME")?,
            port: env::var("BACKEND_SERVICE_PORT")?.parse()?,
            version: env::var("BACKEND_SERVICE_VERSION")?,
        })
    }
}

/// ================================
/// Authentication Service
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthService {
    pub hostname: String,
    pub port: u16,
    pub version: String,

    pub access_token_jwt_secret: String,
    pub enc_secret: String,
}

impl AuthService {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            hostname: env::var("AUTH_SERVICE_HOSTNAME")?,
            port: env::var("AUTH_SERVICE_PORT")?.parse()?,
            version: env::var("AUTH_SERVICE_VERSION")?,

            access_token_jwt_secret:
                env::var("AUTH_SERVICE_ACCESS_TOKEN_JWT_SECRET")?,

            enc_secret:
                env::var("AUTH_SERVICE_ENCRYPTION_SECRET")?,
        })
    }
}

/// ================================
/// Frontend Service
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrontendService {
    pub hostname: String,
    pub port: u16,
    pub version: String,
}

impl FrontendService {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            hostname: env::var("FRONTEND_SERVICE_HOSTNAME")?,
            port: env::var("FRONTEND_SERVICE_PORT")?.parse()?,
            version: env::var("FRONTEND_SERVICE_VERSION")?,
        })
    }
}

/// ================================
/// Cloudflare
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudflareConfig {
    pub turnstile_secret_key: String,
}

impl CloudflareConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            turnstile_secret_key: env::var("TURNSTILE_SECRET_KEY")?,
        })
    }
}

/// ================================
/// PostgreSQL Database
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub name: String,
    pub port: u16,
    pub host: String,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            url: env::var("DATABASE_URL")?,

            user: env::var("POSTGRES_USER")?,
            password: env::var("POSTGRES_PASSWORD")?,
            name: env::var("POSTGRES_DB")?,

            port: env::var("POSTGRES_PORT")?.parse()?,

            host: env::var("POSTGRES_HOST")?,
        })
    }
}

/// ================================
/// Redis
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
}

impl RedisConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            url: env::var("REDIS_URL")?,
        })
    }
}

/// ================================
/// Google OAuth
/// ================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl GoogleOAuthConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            client_id: env::var("GOOGLE_CLIENT_ID")?,
            client_secret: env::var("GOOGLE_CLIENT_SECRET")?,
            redirect_uri: env::var("GOOGLE_REDIRECT_URI")?,
        })
    }
}

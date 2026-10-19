use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use redis::{Client, aio::MultiplexedConnection};
use reqwest::StatusCode;
use sqlx::PgPool;
use tracing::error;
use app_schema::config::AppConfig;

#[derive(Debug, Clone)]
pub struct AppState {
    pub redis_client: Arc<Client>,
    pub pool: PgPool,
    pub config: AppConfig,
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


use axum::Json;
use chrono::Local;
use crate::schema::routes::{GetHealthResponse, ServerStatus};

pub async fn get_health() -> Json<GetHealthResponse> {
    Json(GetHealthResponse {
        timestamp: Local::now(),
        server: String::from("Health Server"),
        status: ServerStatus::Active,
        success: true,
    })
}

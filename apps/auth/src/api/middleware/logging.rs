use axum::{extract::Request, middleware::Next, response::Response};
use tokio::time::Instant;

use crate::prometheus::{
    ACTIVE_REQUEST, HTTP_REQUEST_DURATION_SECONDS, TOTAL_NUM_OF_ERR, TOTAL_NUM_OF_REQ,
};

pub async fn prometheus_logs(req: Request, next: Next) -> Response {
    println!("{:?}", req.headers());
    let endpoint = req.uri().path().to_string();
    let method = req.method().to_string();

    TOTAL_NUM_OF_REQ.inc();
    ACTIVE_REQUEST.inc();

    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();

    if response.status().is_client_error() || response.status().is_server_error() {
        TOTAL_NUM_OF_ERR.inc();
    }

    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[
            endpoint.as_str(),
            method.as_str(),
            response.status().as_str(),
        ])
        .observe(duration);

    ACTIVE_REQUEST.dec();

    response
}

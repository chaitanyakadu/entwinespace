use std::sync::LazyLock;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntGauge, Registry, TextEncoder,
    core::{AtomicI64, AtomicU64, GenericCounter, GenericGauge},
};
use tracing::error;

pub static REGISTER: LazyLock<Registry> = LazyLock::new(|| {
    let registry = Registry::new();
    registry
        .register(Box::new(TOTAL_NUM_OF_REQ.clone()))
        .unwrap();
    registry
        .register(Box::new(TOTAL_NUM_OF_ERR.clone()))
        .unwrap();
    registry.register(Box::new(UPTIME.clone())).unwrap();
    registry.register(Box::new(ACTIVE_REQUEST.clone())).unwrap();
    registry
        .register(Box::new(HTTP_REQUEST_DURATION_SECONDS.clone()))
        .unwrap();

    registry
});

pub fn metrics() -> String {
    let metric_families = REGISTER.gather();

    let mut buffer = vec![];
    TextEncoder::new()
        .encode(&metric_families, &mut buffer)
        .unwrap();

    String::from_utf8(buffer).unwrap()
}

pub async fn metrics_handler() -> String {
    metrics()
}

pub static TOTAL_NUM_OF_REQ: LazyLock<GenericCounter<AtomicU64>> = LazyLock::new(|| {
    IntCounter::new(
        "auth_total_num_of_req",
        "Authentication Server: Total number of requests served by the authentication service.",
    )
    .map_err(|e| {
        error!(
            error = ?e,
            "Failed to create prometheus counter for auth_total_num_of_req"
        );
        e
    })
    .unwrap()
});

pub static TOTAL_NUM_OF_ERR: LazyLock<GenericCounter<AtomicU64>> = LazyLock::new(|| {
    IntCounter::new(
        "auth_total_num_of_errors", 
        "Authentication Server: Total number of errors occurred. For example, missing configurations and database connectivity timeout."
    )
        .map_err(|e| {
            error!(
                error = ?e,
                "Failed to create prometheus counter for auth_total_num_of_errors"
            );
            e
        })
        .unwrap()
});

pub static UPTIME: LazyLock<GenericGauge<AtomicI64>> = LazyLock::new(|| {
    IntGauge::new("auth_uptime", "Authentication Server: Server Uptime.")
        .map_err(|e| {
            error!(
                error = ?e,
                "Failed to create prometheus gauge for auth_uptime"
            );
            e
        })
        .unwrap()
});

pub static ACTIVE_REQUEST: LazyLock<GenericGauge<AtomicI64>> = LazyLock::new(|| {
    IntGauge::new(
        "auth_active_requests",
        "Authentication Server: Total number of requests that has not been resolved yet.",
    )
    .map_err(|e| {
        error!(
            error = ?e,
            "Failed to create prometheus gauge for auth_active_requests"
        );
        e
    })
    .unwrap()
});

pub static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "auth_http_request_duration_seconds",
            "Authentication Server: HTTP request duration in seconds",
        ),
        &["endpoint", "method", "status_code"],
    )
    .map_err(|e| {
        error!(
            error = ?e,
            "Failed to create prometheus histogram for auth_http_request_duration_seconds"
        );
        e
    })
    .unwrap()
});

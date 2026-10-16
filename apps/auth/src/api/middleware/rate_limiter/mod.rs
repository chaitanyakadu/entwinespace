use std::{collections::HashMap, sync::{Arc, LazyLock, Mutex}};

use axum::{extract::Request, http::HeaderMap, middleware::Next, response::{IntoResponse, Response}};
use reqwest::{StatusCode, header::RETRY_AFTER};
use time::OffsetDateTime;

use crate::config::{AUTH_CAPACITY, AUTH_REFILL_RATE, OTHERS_CAPACITY, OTHERS_REFILL_RATE, SESSIONS_CAPACITY, SESSIONS_REFILL_RATE, TOKEN_CONSUMPTION};

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum BucketType {
    AUTHENTICATION,
    SESSIONS,
    OTHERS
}

#[derive(Debug)]
pub struct Bucket {
    pub capacity: u32,
    pub tokens: Arc<Mutex<u32>>,
    pub refill_rate: u32,
    pub last_updated: Arc<Mutex<OffsetDateTime>>
}

impl Bucket {
    pub fn refill(&self) {
        let now = OffsetDateTime::now_utc();
        let mut last_updated = self.last_updated.lock().unwrap();

        let period = (now - *last_updated).whole_milliseconds() as u32;
        let mut tokens = self.tokens.lock().unwrap();
        *tokens = self.capacity.min(period * self.refill_rate / 1000);
        *last_updated = now;
    }

    pub fn consume(&self, tokens_req: u32) -> bool {
        self.refill();

        println!("{:?}", BUCKET_HASH);
        let mut tokens = self.tokens.lock().unwrap();
        if *tokens >= tokens_req {
            *tokens = *tokens - tokens_req;
            return true;
        } else {
            return false;
        }
    }
}

pub static BUCKET_HASH: LazyLock<HashMap<BucketType, Bucket>> = LazyLock::new(|| {
    let mut hash: HashMap<BucketType, Bucket> = HashMap::new();
    hash.insert(BucketType::AUTHENTICATION, Bucket {
        capacity: AUTH_CAPACITY,
        refill_rate: AUTH_REFILL_RATE,
        tokens: Arc::new(Mutex::new(AUTH_CAPACITY)),
        last_updated: Arc::new(Mutex::new(OffsetDateTime::now_utc()))
    });
    hash.insert(BucketType::SESSIONS, Bucket {
        capacity: SESSIONS_CAPACITY,
        refill_rate: SESSIONS_REFILL_RATE,
        tokens: Arc::new(Mutex::new(SESSIONS_CAPACITY)),
        last_updated: Arc::new(Mutex::new(OffsetDateTime::now_utc()))
    });
    hash.insert(BucketType::OTHERS, Bucket {
        capacity: OTHERS_CAPACITY,
        refill_rate: OTHERS_REFILL_RATE,
        tokens: Arc::new(Mutex::new(OTHERS_CAPACITY)),
        last_updated: Arc::new(Mutex::new(OffsetDateTime::now_utc()))
    });

    hash
});

pub async fn rate_limit(
    req: Request,
    next: Next,
) -> Response {
    let bucket_type = match req.uri().path().split("/").collect::<Vec<&str>>()[1] {
        "signup" => BucketType::AUTHENTICATION,
        "login" => BucketType::AUTHENTICATION,
        "sessions" => BucketType::SESSIONS,
        _ => BucketType::OTHERS,
    };
    let bucket = BUCKET_HASH.get(&bucket_type).unwrap();
    let consume = TOKEN_CONSUMPTION.get(&bucket_type).unwrap();

    if bucket.consume(*consume) {
        next.run(req).await
    } else {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "10".parse().unwrap());
        (StatusCode::TOO_MANY_REQUESTS, headers).into_response()
    }
}

///////////////////////////////////////
// Rate Limit
// Token Bucket Algorithm
//////////////////////////////////////

use std::{collections::HashMap, sync::LazyLock};

use crate::api::middleware::rate_limiter::BucketType;

//
// Authentication
pub const AUTH_CAPACITY: u32 = 120;
pub const AUTH_REFILL_RATE: u32 = 10;

//
// Sessions
pub const SESSIONS_CAPACITY: u32 = 100;
pub const SESSIONS_REFILL_RATE: u32 = 10;

//
// Others
pub const OTHERS_CAPACITY: u32 = 100;
pub const OTHERS_REFILL_RATE: u32 = 10;

//
// Token Consumption
pub static TOKEN_CONSUMPTION: LazyLock<HashMap<BucketType, u32>> = LazyLock::new(|| {
    let mut token_consumption = HashMap::new();

    token_consumption.insert(BucketType::AUTHENTICATION, 1);
    token_consumption.insert(BucketType::SESSIONS, 1);
    token_consumption.insert(BucketType::OTHERS, 1);
    
    token_consumption
});

/////////////////////////////////////

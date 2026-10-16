// oauth_uri

use serde::Deserialize;

#[derive(Deserialize)]
pub struct TurnstilePayload {
    pub token: String,
}

#[derive(Deserialize, Debug)]
pub struct TurnstileVerify {
    pub success: bool,
}

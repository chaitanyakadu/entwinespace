use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use redis::{AsyncTypedCommands, aio::MultiplexedConnection};
use reqwest::StatusCode;
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCodeAuth, ApiResponseIssue, GetSignupCallbackParams,
        GoogleOauthToken, Userinfo,
    },
};
use sqlx::Error as SqlxError;
use tracing::{debug, info, warn};
use crate::utils::{
    oauth::{call_google_apis, exchange_auth_code},
    routes::{frontend_redirect, server_error_response_api},
    security::generate_sha2_hash,
};

use crate::api::database::auth::email_exists;

// in case of failure the user will be redirected to frontend/auth/signup?error={}
// in case of success the user will be redirected to frontend/auth/signup/credentials?email={}&id={}
// in both the cases the fronted is expected to handle the query params
pub async fn get_signup_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetSignupCallbackParams>,
) -> Result<Response, Response> {
    let config = &state.config;
    println!("{:?}", &params);
    // for more info - https://developers.google.com/identity/protocols/oauth2/web-server#handlingresponse
    debug!("parse code from params");
    let code: String = match params.code {
        None => {
            info!(
                data = ?params,
                "Received a error or missing code response from oauth2.google.com"
            );
            let response_code = ApiResponseCodeAuth::ServerError;
            let response_issue = ApiResponseIssue {
                msg: "Server error! Try again later.".to_string(),
            };
            let api_response: ApiResponse<ApiResponseCodeAuth, (), ApiResponseIssue> =
                ApiResponse {
                    code: response_code,
                    status: false,
                    payload: None,
                    issue: Some(response_issue),
                };
            return Ok((StatusCode::FORBIDDEN, Json(api_response)).into_response());
        }
        Some(v) => v,
    };

    let oauth_tokens: GoogleOauthToken = exchange_auth_code(
        &code,
        &config.google_oauth.redirect_uri,
        &config.google_oauth,
    )
    .await?;

    let userinfo: Userinfo = call_google_apis(&oauth_tokens).await?;

    let email_hash = generate_sha2_hash(&userinfo.email);

    debug!("verify if the user already exists");
    let db = &state.pool;
    let email_exists = email_exists(&email_hash, &db).await.map_err(|e| match e {
        SqlxError::InvalidArgument(_) => {
            let response_code = ApiResponseCodeAuth::InvalidCredentials;
            let response_issue = ApiResponseIssue {
                msg: "Invalid arguments! Verify the credentials.".to_string(),
            };
            let api_response: ApiResponse<ApiResponseCodeAuth, (), ApiResponseIssue> =
                ApiResponse {
                    code: response_code,
                    status: false,
                    payload: None,
                    issue: Some(response_issue),
                };
            (StatusCode::BAD_REQUEST, Json(api_response)).into_response()
        }
        _ => server_error_response_api(),
    })?;

    if email_exists == true {
        let response_code = ApiResponseCodeAuth::UserAlreadyExists;
        let response_issue = ApiResponseIssue {
            msg: "The email is already used!".to_string(),
        };
        let api_response: ApiResponse<ApiResponseCodeAuth, (), ApiResponseIssue> = ApiResponse {
            code: response_code,
            status: false,
            payload: None,
            issue: Some(response_issue),
        };
        return Ok((StatusCode::BAD_REQUEST, Json(api_response)).into_response());
    }

    // we cache the userinfo for 1hr
    // the user must provide credentials like username, password, contact,.. to complete the
    // signup process
    let mut redis_conn: MultiplexedConnection = state.get_redis_conn().await?;
    let userinfo_redis_key = format!("auth_signup_userinfo:{}", &userinfo.email);
    let userinfo_str = serde_json::to_string(&userinfo).map_err(|e| {
        warn!(error = ?e, "Failed to serialize userinfo");
        server_error_response_api()
    })?;
    redis_conn.set_ex::<_, _>(userinfo_redis_key, userinfo_str, 1 * 60 * 60) // exp in 1 hr
        .await
        .map_err(|e| {
            warn!(error = ?e, "Redis Error! Failed to set the userinfo value and expiration of a key.");
            server_error_response_api()
        })?;

    let query: Vec<(String, String)> = vec![
        ("email".to_string(), userinfo.email),
        ("picture".to_string(), userinfo.picture),
        ("id".to_string(), userinfo.id),
    ];
    Ok(frontend_redirect(
        "/auth/signup/credentials/",
        query,
        &config.frontend_service.url,
    )?)
}

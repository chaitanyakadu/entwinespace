use std::sync::Arc;

use app_schema::config::AppConfig;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::Header;
use redis::{AsyncTypedCommands, aio::MultiplexedConnection};
use reqwest::{StatusCode, Url, header};
use crate::schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCodeAuth, ApiResponseIssue, GetSignupCallbackParams,
        GoogleOauthToken, RefreshToken, Userinfo,
    },
    security::{AccessClaims, JWTClaims},
};
use sqlx::Error as SqlxError;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, warn};
use crate::utils::{
    oauth::{call_google_apis, exchange_auth_code},
    routes::server_error_response_api,
    security::{generate_jwt, generate_sha2_hash},
};
use uuid::Uuid;

use crate::api::database::{
    auth::add_new_refresh_token, refresh_token::num_active_sessions,
    users::get_username_and_id_using_email,
};

// in case of failure the user will be redirected to frontend/auth/login?error={}
// in case of success the user will be redirected to frontend/auth/login/credentials?email={}&id={}
// in both the cases the fronted is expected to handle the query params
pub async fn get_login_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<GetSignupCallbackParams>,
) -> Result<Response, Response> {
    let config = &state.config;

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

    let redirect_uri = config
        .google_oauth
        .redirect_uri
        .replace("signup", "login");
    let oauth_tokens: GoogleOauthToken =
        exchange_auth_code(&code, &redirect_uri, &config.google_oauth).await?;

    let userinfo: Userinfo = call_google_apis(&oauth_tokens).await?;

    let email_hash = generate_sha2_hash(&userinfo.email);

    debug!("push userinfo to database");
    let db = &state.pool;

    let (username, user_id) = get_username_and_id_using_email(&email_hash, &db)
        .await
        .map_err(|e| match e {
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
            SqlxError::RowNotFound => {
                let response_code = ApiResponseCodeAuth::NewUser;
                let response_issue = ApiResponseIssue {
                    msg: "Kindly signup! User does not exist.".to_string(),
                };
                let api_response: ApiResponse<ApiResponseCodeAuth, (), ApiResponseIssue> =
                    ApiResponse {
                        code: response_code,
                        status: false,
                        payload: None,
                        issue: Some(response_issue),
                    };
                (StatusCode::UNAUTHORIZED, Json(api_response)).into_response()
            }
            _ => server_error_response_api(),
        })?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_token_hash = generate_sha2_hash(&refresh_token);
    let expires_at = OffsetDateTime::now_utc() + Duration::days(60);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let user_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("unknown");

    let mut tx = db.begin().await.map_err(|e| {
        warn!(error = ?e, "failed to begin a new transaction");
        server_error_response_api()
    })?;

    let active_sessions: Vec<String> =
        num_active_sessions(&user_id, &mut tx).await.map_err(|_| {
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
            (StatusCode::INTERNAL_SERVER_ERROR, Json(api_response)).into_response()
        })?;

    if active_sessions.len() >= 3 {
        return handle_access_sessions(&config, active_sessions, &*state, user_id).await;
    }

    let refresh: RefreshToken = RefreshToken {
        user_id,
        token_hash: refresh_token_hash,
        expires_at,
        revoked_at: None,
        replaces_by_token_id: None,
        user_agent: Some(user_agent.to_string()),
        created_by_ip: user_ip.to_string(),
        last_used_ip: user_ip.to_string(),
    };

    add_new_refresh_token(&refresh, &user_id, &mut tx)
        .await
        .map_err(|e| match e {
            SqlxError::InvalidArgument(_) => {
                let response_code = ApiResponseCodeAuth::InvalidCredentials;
                let response_issue = ApiResponseIssue {
                    msg: "Invalid credentials!".to_string(),
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

    tx.commit().await.map_err(|e| {
        warn!(error = ?e, "failed to commit the transaction");
        server_error_response_api()
    })?;
    debug!("database transaction completed!");

    let mut response = StatusCode::OK.into_response();

    let header = Header::default();
    let jti = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let access_claims = AccessClaims {
        sub: "".to_string(),
        jti,
        iat: now.unix_timestamp(),
        exp: (now + Duration::minutes(60)).unix_timestamp(),
        username,
    };
    let jwt_claims = JWTClaims::AccessToken(access_claims);
    let access_token =
        generate_jwt(jwt_claims, &config.auth_service.access_token_jwt_secret, header).map_err(|e| {
            debug!(
                error = ?e,
                "failed to generate jsonwebtoken"
            );
            server_error_response_api()
        })?;

    let access = Cookie::build(("access_token", access_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build();

    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&access.to_string()).map_err(|e| {
            warn!(error = ?e, "Failed to create access token cookie");
            server_error_response_api()
        })?,
    );

    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&access.to_string()).map_err(|e| {
            warn!(error = ?e, "Failed to create access token cookie");
            server_error_response_api()
        })?,
    );

    let refresh = Cookie::build(("refresh_token", refresh_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build();

    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&refresh.to_string()).map_err(|e| {
            warn!(error = ?e, "Failed to create refresh token cookie");
            server_error_response_api()
        })?,
    );

    Ok(response)
}

async fn handle_access_sessions(
    config: &AppConfig,
    active_sessions: Vec<String>,
    state: &AppState,
    user_id: Uuid,
) -> Result<Response, Response> {
    debug!("there are {} active sessions", active_sessions.len());

    let session_token = Uuid::new_v4();

    let mut redis_conn: MultiplexedConnection = state.get_redis_conn().await?;
    let manage_session_redis_key = format!("auth_manage_session:{}", &session_token);
    redis_conn.set_ex::<_, _>(
        manage_session_redis_key,
        user_id.to_string(),
        15 * 60
    ) // exp in 15 mins
        .await
        .map_err(|e| {
            warn!(error = ?e, "Redis Error! Failed to set the userinfo value and expiration of a key.");
            server_error_response_api()
        })?;

    let endpoint = "/auth/manage-sessions".to_string();
    let query = vec![
        ("error", "too many active sessions".to_string()),
        ("token", session_token.to_string()),
    ];
    let mut url = Url::parse_with_params(&config.frontend_service.url, &query).map_err(|e| {
        debug!(
            endpoint = ?endpoint,
            query = ?query,
            error = ?e,
            "failed to parse absolute url and add query params"
        );
        server_error_response_api().into_response()
    })?;
    url.set_path(&endpoint);

    let redirect = Redirect::to(url.as_str());
    return Ok(redirect.into_response());
}

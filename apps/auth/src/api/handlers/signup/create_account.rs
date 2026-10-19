use std::sync::Arc;

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::Header;
use reqwest::{StatusCode, header};
use crate::{api::database::auth::add_profile_and_settings, schema::{
    app_state::AppState,
    routes::{
        ApiResponse, ApiResponseCodeAuth, ApiResponseIssue, AuthProvider, OauthIdentity,
        RefreshToken, SignupCredentials, UserData, Userinfo,
    },
    security::{AccessClaims, JWTClaims},
}};
use sqlx::Error as SqlxError;
use time::{Duration, OffsetDateTime};
use tracing::{debug, warn};
use crate::utils::{
    abstract_body,
    routes::{get_redis_value, server_error_response_api},
    security::{generate_jwt, generate_sha2_hash, sym_encryption},
};
use uuid::Uuid;

use crate::api::database::auth::{add_new_refresh_token, add_new_user, add_oauth_identity};

pub async fn post_signup_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut req: Request,
) -> Result<Response, Response> {
    let (payload, _) = abstract_body::<SignupCredentials>(&mut req).await?;
    let config = &state.config;

    // parse userinfo
    debug!("parse userinfo from redis");
    let redis_conn = state.get_redis_conn().await?;
    let redis_userinfo_key = format!("auth_signup_userinfo:{}", payload.email);
    let userinfo = get_redis_value::<Userinfo>(redis_conn, redis_userinfo_key).await?;

    // make sure that the oauth verified email and current email mathches
    if &userinfo.email != &payload.email && &userinfo.id == &payload.id {
        debug!("oauth verified email is not equal to current email");
        let response_code = ApiResponseCodeAuth::InvalidCredentials;
        let response_issue = ApiResponseIssue {
            msg: "Invalid credentials!".to_string(),
        };
        let api_response: ApiResponse<ApiResponseCodeAuth, (), ApiResponseIssue> = ApiResponse {
            code: response_code,
            status: false,
            payload: None,
            issue: Some(response_issue),
        };
        return Ok((StatusCode::BAD_REQUEST, Json(api_response)).into_response());
    }

    // hash specific credentials
    debug!("hash credentials");
    // todo - for passwords use argon2 instead
    let password_hash = generate_sha2_hash(&payload.password);
    let contact_hash = generate_sha2_hash(&payload.contact);
    let email_hash = generate_sha2_hash(&payload.email);

    // encrypt specific credentials
    debug!("encrypt credentials");
    let email_encrypted = sym_encryption(&payload.email, &config.auth_service.enc_secret)
        .map_err(|e| {
            warn!(
                error = ?e,
                "Error occured while encrypting email"
            );
            server_error_response_api()
        })?;
    let contact_encrypted = sym_encryption(&payload.contact, &config.auth_service.enc_secret)
        .map_err(|e| {
            warn!(
                error = ?e,
                "Error occured while encrypting contact"
            );
            server_error_response_api()
        })?;

    debug!("database transation begins");
    let db = &state.pool;
    let mut tx = db.begin().await.map_err(|e| {
        warn!(error = ?e, "failed to begin a new transaction");
        server_error_response_api()
    })?;

    let userdata = UserData {
        username: payload.username,
        password: password_hash,
        name: payload.name,
        email_hash,
        email_encrypted,
        contact_hash: Some(contact_hash),
        contact_encrypted: Some(contact_encrypted),
    };
    let user_id = add_new_user(&userdata, &mut tx)
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
            _ => server_error_response_api(),
        })?;

    let oauth_identity = OauthIdentity {
        image: userinfo.picture,
        is_verified: userinfo.verified_email,
        user_id,
        provider: AuthProvider::Gmail,
    };
    add_oauth_identity(&oauth_identity, &user_id, &mut tx)
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

    add_profile_and_settings(&user_id, &mut tx)
        .await
        .unwrap();

    tx.commit().await.map_err(|e| {
        warn!(error = ?e, "failed to commit the transaction");
        server_error_response_api()
    })?;
    debug!("database transaction completed!");

    let header = Header::default();
    let jti = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let access_claims = AccessClaims {
        sub: "EntwineSpace".to_string(),
        jti,
        iat: now.unix_timestamp(),
        exp: (now + Duration::minutes(60)).unix_timestamp(),
        username: userdata.username,
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

    let mut response = StatusCode::OK.into_response();

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

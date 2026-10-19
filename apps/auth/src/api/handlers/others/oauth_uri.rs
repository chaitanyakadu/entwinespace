use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use crate::schema::{app_state::AppState, routes::GetOauthRedirectUri};
use crate::utils::oauth::oauth_redirect_uri;

// refer - https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens
pub async fn get_oauth_redirect_uri(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetOauthRedirectUri>,
) -> Result<Response, Response> {
    let config = &state.config;

    let redirect_uri = oauth_redirect_uri(&config.google_oauth, &params.redirect_url)
        .map_err(|e| e.into_response())?;

    let response = Redirect::to(redirect_uri.as_str()).into_response();
    Ok(response)
}

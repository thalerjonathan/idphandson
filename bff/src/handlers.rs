use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{Extension, Json, extract::State, http::HeaderMap};
use log::{info, warn};
use reqwest::Url;
use shared::{
    app_error::AppError,
    bff_rest_dtos::LoginDTO,
    token::{TokenManager, Tokens},
};

use crate::app_state::AppState;

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(login_info): Json<LoginDTO>,
) -> Result<String, AppError> {
    info!("handle_login: {:?}", login_info);

    let idp_token = state
        .token_manager
        .request_idp_tokens(&login_info.username, &login_info.password)
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("idp_token: {:?}", idp_token);

    let tokens: Tokens = idp_token
        .try_into()
        .map_err(|e: String| AppError::from_error(e.as_str()))?;

    info!("tokens: {:?}", &tokens);

    let user_id = tokens.identity.sub.clone();

    let mut lock = state.token_cache.lock().unwrap();
    let token_cache = &mut *lock;
    token_cache.insert(user_id.clone(), tokens);

    Ok(user_id)
}

pub async fn handle_admin_only(
    State(state): State<Arc<AppState>>,
    Extension(backend_host): Extension<String>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only");

    let roles: Vec<&str> = vec!["admin"];
    let tokens = check_loggedin(&headers, &state.token_manager, &state.token_cache, &roles).await?;

    let url = Url::parse(&format!(
        "http://{}/idphandson/backend/adminonly",
        backend_host
    ));

    let authorization_header = format!("Bearer {}", tokens.idp.access_token);

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header("Authorization", authorization_header)
        .send()
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    let reply_text = response
        .text()
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("reply_text: {}", reply_text);

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(
    State(state): State<Arc<AppState>>,
    Extension(backend_host): Extension<String>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_all_roles");

    let roles_allowed: Vec<&str> = vec!["admin", "sachbearbeiter"];
    let tokens = check_loggedin(
        &headers,
        &state.token_manager,
        &state.token_cache,
        &roles_allowed,
    )
    .await?;

    let url = Url::parse(&format!(
        "http://{}/idphandson/backend/allroles",
        backend_host
    ));

    let authorization_header = format!("Bearer {}", tokens.idp.access_token);

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header("Authorization", authorization_header)
        .send()
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    let reply_text = response
        .text()
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("reply_text: {}", reply_text);

    Ok("handle_all_roles success".to_string())
}

async fn check_loggedin(
    headers: &HeaderMap,
    token_manager: &TokenManager,
    token_cache: &Mutex<HashMap<String, Tokens>>,
    roles_allowed: &Vec<&str>,
) -> Result<Tokens, AppError> {
    let user_id_header = headers
        .get("user_id")
        .ok_or(AppError::from_error_unauthorized("Missing user_id header"))?;
    let user_id = user_id_header
        .to_str()
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    // restrict holding lock, because check_roles below might refresh roles, which can have some delay
    let tokens = {
        let mut lock = token_cache.lock().unwrap();
        let token_cache = &mut *lock;

        token_cache
            .get(user_id)
            .ok_or(AppError::from_error_unauthorized("User not logged in!"))?
            .clone()
    };

    let refreshed_tokens = check_roles(token_manager, &tokens, roles_allowed).await?;

    {
        let mut lock = token_cache.lock().unwrap();
        let token_cache = &mut *lock;

        // checking roles also checks for expiration of access token, and does a refresh of the tokens,
        // therefore returning a potentially new token - if it hasn't change it returns the initial token
        // and this insert simply overrides it in the cache
        token_cache.insert(user_id.to_string(), refreshed_tokens.clone());
    }

    Ok(refreshed_tokens)
}

async fn check_roles(
    token_manager: &TokenManager,
    init_tokens: &Tokens,
    roles_allowed: &Vec<&str>,
) -> Result<Tokens, AppError> {
    let access_token_sec_left = init_tokens.access.seconds_until_expiration();

    info!(
        "Checking Roles for Access Token which expires in {} secs",
        access_token_sec_left
    );

    let tokens = if init_tokens.access.is_expired() {
        let refresh_token_sec_left: i128 = init_tokens.refresh.seconds_until_expiration();

        info!(
            "Access Token expired - requesting new token using refresh token which expires in {} secs",
            refresh_token_sec_left
        );

        if init_tokens.refresh.is_expired() {
            warn!("Refresh Token expired - User needs to re-login");

            return Err(AppError::from_error_unauthorized(
                "Refresh Token expired - User needs to re-login",
            ));
        }

        let new_idp_token = token_manager
            .refresh_tokens(&init_tokens.idp.refresh_token)
            .await
            .map_err(|e| {
                AppError::from_error(&format!("Failed to refresh token: {}", e.to_string()))
            })?;

        let new_token: Tokens = new_idp_token
            .try_into()
            .map_err(|e: String| AppError::from_error(e.as_str()))?;

        let new_access_token_sec_left = new_token.access.seconds_until_expiration();

        info!(
            "Successfully requested new Tokens using Refresh Token. New Access Token expires in {} secs",
            new_access_token_sec_left
        );

        // NOTE: it would be nice to simply do a recursive call, but Rust async/await complicates recursive calls...
        // check_roles(idp_disc_doc, &new_token, roles_allowed).await?;
        new_token
    } else {
        init_tokens.clone()
    };

    if false == tokens.access.satisfies_any_role(roles_allowed) {
        warn!(
            "user {:?} access to resource refused because user roles {:?} did not satisfy allowed roles {:?}",
            tokens.identity.sub, tokens.access.resource_access.idphandson.roles, roles_allowed
        );

        return Err(AppError::from_error_unauthorized("Missing role"));
    }

    Ok(tokens)
}

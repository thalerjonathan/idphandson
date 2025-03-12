use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State, http::HeaderMap};
use log::{debug, info, warn};
use reqwest::StatusCode;
use shared::bff_rest_dtos::LoginDTO;

use crate::{
    app_error::AppError,
    app_state::AppState,
    token::{IdpDiscoveryDocument, Tokens, refresh_tokens, request_idp_tokens},
};

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(login_info): Json<LoginDTO>,
) -> Result<String, AppError> {
    debug!("handle_login: {:?}", login_info);

    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    let idp_token = request_idp_tokens(
        &state.idp_disc_doc,
        client_id,
        client_secret,
        &login_info.username,
        &login_info.password,
    )
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
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only");

    let roles: Vec<&str> = vec!["admin"];
    check_loggedin(&headers, &state.idp_disc_doc, &state.token_cache, &roles).await?;

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    debug!("handle_all_roles");

    let roles_allowed: Vec<&str> = vec!["admin", "sachbearbeiter"];
    check_loggedin(
        &headers,
        &state.idp_disc_doc,
        &state.token_cache,
        &roles_allowed,
    )
    .await?;

    Ok("handle_all_roles success".to_string())
}

async fn check_loggedin(
    headers: &HeaderMap,
    idp_disc_doc: &IdpDiscoveryDocument,
    token_cache: &Mutex<HashMap<String, Tokens>>,
    roles_allowed: &Vec<&str>,
) -> Result<(), AppError> {
    let user_id_header = headers
        .get("user_id")
        .ok_or(AppError::from_error("Missing user_id header"))?;
    let user_id = user_id_header
        .to_str()
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    // restrict holding lock, because check_roles below might refresh roles, which can have some delay
    let tokens = {
        let mut lock = token_cache.lock().unwrap();
        let token_cache = &mut *lock;

        token_cache
            .get(user_id)
            .ok_or(AppError::from_error("User not logged in!"))?
            .clone()
    };

    let refreshed_tokens = check_roles(idp_disc_doc, &tokens, roles_allowed).await?;

    {
        let mut lock = token_cache.lock().unwrap();
        let token_cache = &mut *lock;

        // checking roles also checks for expiration of access token, and does a refresh of the tokens,
        // therefore returning a potentially new token - if it hasn't change it returns the initial token
        // and this insert simply overrides it in the cache
        token_cache.insert(user_id.to_string(), refreshed_tokens);
    }

    Ok(())
}

async fn check_roles(
    idp_disc_doc: &IdpDiscoveryDocument,
    init_tokens: &Tokens,
    roles_allowed: &Vec<&str>,
) -> Result<Tokens, AppError> {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let now_secs = since_the_epoch.as_secs();

    let access_token_sec_left: i128 = init_tokens.access.exp as i128 - now_secs as i128;

    info!(
        "Checking Roles for Access Token which expires in {} secs",
        access_token_sec_left
    );

    let tokens = if access_token_sec_left < 0 {
        let refresh_token_sec_left: i128 = init_tokens.refresh.exp as i128 - now_secs as i128;

        info!(
            "Access Token expired - requesting new token using refresh token which expires in {} secs",
            refresh_token_sec_left
        );

        if refresh_token_sec_left < 0 {
            warn!("Refresh Token expired - User needs to re-login");

            return Err(AppError::from_error_with_status(
                "Refresh Token expired - User needs to re-login",
                StatusCode::UNAUTHORIZED,
            ));
        }

        // TODO: build a "Token handler" object that encapsulates things like client id, client secret
        let client_id = "idphandson";
        let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

        let new_idp_token = refresh_tokens(
            idp_disc_doc,
            client_id,
            client_secret,
            &init_tokens.idp.refresh_token,
        )
        .await
        .map_err(|e| {
            AppError::from_error(&format!("Failed to refresh token: {}", e.to_string()))
        })?;

        let new_token: Tokens = new_idp_token
            .try_into()
            .map_err(|e: String| AppError::from_error(e.as_str()))?;

        let new_access_token_sec_left: i128 = new_token.access.exp as i128 - now_secs as i128;

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

    let mut role_found = false;

    for role_allowed in roles_allowed {
        if tokens
            .access
            .resource_access
            .idphandson
            .roles
            .iter()
            .find(|actual_role| actual_role.to_lowercase() == role_allowed.to_lowercase())
            .is_some()
        {
            role_found = true;
            break;
        }
    }

    if false == role_found {
        warn!(
            "user {:?} access to resource refused because user roles {:?} did not satisfy allowed roles {:?}",
            tokens.identity.sub, tokens.access.resource_access.idphandson.roles, roles_allowed
        );

        return Err(AppError::from_error_with_status(
            "Access not allowed",
            StatusCode::UNAUTHORIZED,
        ));
    }

    Ok(tokens)
}

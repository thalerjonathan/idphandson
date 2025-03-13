use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use log::{info, warn};
use reqwest::Url;
use serde::Deserialize;
use shared::{
    app_error::AppError,
    bff_rest_dtos::LoginDTO,
    token::{TokenManager, Tokens},
};

use crate::app_state::AppState;

static USER_ID_HEADER: &str = "Idphandson-User-Id";

/*
http://localhost:1234/idphandson/bff/authfromidp?state=af0ifjsldkj&session_state=457c4f86-7efa-457a-8f7b-5f780a4e07ce&iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fidphandson&code=6eaafee7-83b0-4a07-a522-0eee04094779.457c4f86-7efa-457a-8f7b-5f780a4e07ce.0c25b80b-66b4-439d-8681-8766e4b0fafb
*/
#[allow(dead_code)]
#[derive(Deserialize)]
pub struct AuthFromIdpQueryParams {
    session_state: String,
    iss: String,
    code: String,
}

#[derive(Deserialize)]
pub struct UserIdParam {
    user_id: String,
}

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(login_info): Json<LoginDTO>,
) -> Result<String, AppError> {
    info!("handle_login: {:?}", login_info);

    let idp_token = state
        .token_manager
        .request_idp_tokens_via_credentials(&login_info.username, &login_info.password)
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

pub async fn handle_authfromidp(
    State(state): State<Arc<AppState>>,
    auth_from_idp_params: Query<AuthFromIdpQueryParams>,
) -> Result<Redirect, AppError> {
    info!(
        "handle_authfromidp with code '{}'",
        auth_from_idp_params.code
    );

    let idp_tokens = state
        .token_manager
        .request_idp_tokens_via_code(&auth_from_idp_params.code)
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("token request result: {:?}", idp_tokens);

    let tokens: Tokens = idp_tokens.try_into().unwrap();

    let mut lock = state.token_cache.lock().unwrap();
    let token_cache = &mut *lock;

    let user_id = tokens.identity.sub.clone();

    token_cache.insert(user_id.clone(), tokens);

    Ok(Redirect::to(&format!("testpage?user_id={}", user_id)))
}

pub async fn handle_testpage(
    State(state): State<Arc<AppState>>,
    user_id: Query<UserIdParam>,
) -> impl IntoResponse {
    info!("handle_testpage");

    let auth_redirect_url = format!(
        "{}?response_type=code&scope=openid&client_id={}&redirect_uri=http://localhost:1234/idphandson/bff/authfromidp",
        state
            .token_manager
            .idp_discovery_document()
            .authorization_endpoint
            .clone(),
        state.token_manager.client_id()
    );

    let lock = state.token_cache.lock().unwrap();
    let token_cache = lock;

    match token_cache.get(&user_id.user_id).clone() {
        None => {
            info!("No token found for user id - redirecting to Idp login...");
            // no token found for user assume user not logged in - redirect to login via Idp
            Redirect::to(&auth_redirect_url).into_response()
        }
        Some(tokens) => {
            // NOTE: we are not checking the actual roles here, just displaying some HTML with all the roles the logged in user has
            let testpage_html = format!("<html> \
                        <body> \
                            <header> \
                                <h1>Welcome to Idp Hands-On</h1> \
                                <p>User: {}</p> \
                                <p>Roles: {:?}</p> \
                                 <p>If user was not logged in, it would have gotten redirected to Idp</p> \
                            </header> \
                        </body>
                    </html>", 
                    tokens.identity.name,
                    tokens.access.resource_access.idphandson.roles);

            Html(testpage_html).into_response()
        }
    }
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
        .get(USER_ID_HEADER)
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

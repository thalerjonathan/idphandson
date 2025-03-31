use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use log::{info, warn};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shared::{
    app_error::AppError,
    bff_rest_dtos::LoginDTO,
    token::{AccessToken, TokenManager, Tokens},
};
use uuid::Uuid;

use crate::app_state::AppState;

static REST_USER_ID_HEADER: &str = "idphandson-user-id";

static ACCESS_TOKEN_COOKIE_ID: &str = "idphandson-access";
static IDENTITY_TOKEN_COOKIE_ID: &str = "idphandson-identity";
static REFRESH_TOKEN_COOKIE_ID: &str = "idphandson-refresh";
/*
http://localhost:1234/idphandson/bff/authfromidp?state=af0ifjsldkj&session_state=457c4f86-7efa-457a-8f7b-5f780a4e07ce&iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fidphandson&code=6eaafee7-83b0-4a07-a522-0eee04094779.457c4f86-7efa-457a-8f7b-5f780a4e07ce.0c25b80b-66b4-439d-8681-8766e4b0fafb
*/
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthFromIdpQueryParams {
    // session_state: String,
    iss: String,
    code: String,
    state: String,
}

fn auth_redirect_url(tm: &TokenManager, state: &str, code_challenge: &str) -> String {
    format!(
        "{}?response_type=code&scope=openid&client_id={}&state={}&code_challenge={}&code_challenge_method=S256&redirect_uri=http://localhost:1234/idphandson/bff/authfromidp",
        tm.idp_discovery_document().authorization_endpoint.clone(),
        tm.client_id(),
        state,
        code_challenge,
    )
}

fn generate_and_store_code_verifier(
    code_challenge_cache: &mut HashMap<String, String>,
) -> (String, String) {
    // NOTE:
    //  code_verifier is a random string, in our case we use 2x a uuid v4 because the code_verifier has to be at least 43 characters
    //  code_challenge = {BASE64(SHA256(code_verifier))}
    let code_verifier = format!(
        "{}{}",
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string()
    );

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hashed = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(hashed);

    // let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
    //     .encode(sha256::digest(code_verifier.clone()));
    // NOTE: we need the state to be able to connect the incoming redirect from idp to the stored code_verifier
    let state = Uuid::new_v4().to_string();
    code_challenge_cache.insert(state.clone(), code_verifier.clone());

    info!("state: {:?}", state);
    info!("code_verifier: {:?}", code_verifier);

    (state, code_challenge)
}

pub async fn handle_page_landing(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    info!("handle_page_landing");

    match extract_cookie(&headers, ACCESS_TOKEN_COOKIE_ID) {
        None => {
            info!("No access token cookie found - redirecting to Idp login...");

            let mut lock = state.code_challenge_cache.lock().unwrap();
            let code_challenge_cache = &mut *lock;
            let (state_str, code_challenge) =
                generate_and_store_code_verifier(code_challenge_cache);

            let auth_redirect_url =
                auth_redirect_url(&state.token_manager, &state_str, &code_challenge);

            info!("Redirect to {}", auth_redirect_url);

            // no token found for user assume user not logged in - redirect to login via Idp
            Ok(Redirect::to(&auth_redirect_url).into_response())
        }
        Some(access_token_encoded) => {
            info!("Access token cookie found");

            info!("Fetching certs...");
            let idp_certs = state
                .token_manager
                .get_certs()
                .await
                .map_err(|e| AppError::from_error(&e.to_string()))?;
            info!("Successfully fetched certs");

            info!("Decoding and validating Access token...");
            let access_token_decoding_result =
                AccessToken::from_encoded_with_idp_certs(&access_token_encoded, &idp_certs);

            match access_token_decoding_result {
                Err(err) => {
                    let error_kind = err.into_kind();
                    match error_kind {
                        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                            info!("Access token ExpiredSignature - redirecting to Idp login...");

                            let mut lock = state.code_challenge_cache.lock().unwrap();
                            let code_challenge_cache = &mut *lock;
                            let (state_str, code_challenge) =
                                generate_and_store_code_verifier(code_challenge_cache);

                            let auth_redirect_url = auth_redirect_url(
                                &state.token_manager,
                                &state_str,
                                &code_challenge,
                            );

                            info!("Redirect to {}", auth_redirect_url);

                            Ok(Redirect::to(&auth_redirect_url).into_response())
                        }
                        _ => {
                            info!("Failed to decode/validate Access token: {:?}", error_kind);

                            let error_page_html = format!(
                                "<html> \
                                    <body> \
                                        <header> \
                                            <h1>Invalid Access</h1> \
                                            <p>Error: {:?}</p> \
                                        </header> \
                                    </body>
                                </html>",
                                error_kind
                            );

                            Ok(Html(error_page_html).into_response())
                        }
                    }
                }
                Ok(access_token) => {
                    info!("Successfully decoded (and validated) Access token");

                    // NOTE: we are not checking the actual roles here, just displaying some HTML with all the roles the logged in user has
                    let landing_page_html = format!(
                        "<html> \
                            <body> \
                                <header> \
                                    <h1>Welcome to Idp Hands-On</h1> \
                                    <p>User: {}</p> \
                                    <p>Roles: {:?}</p> \
                                    <p>If user was not logged in, it would have gotten redirected to Idp</p> \
                                </header> \
                            </body>
                        </html>", 
                    access_token.name,
                    access_token.resource_access.idphandson.roles);

                    Ok(Html(landing_page_html).into_response())
                }
            }
        }
    }
}

pub async fn handle_redirect_authfromidp(
    State(state): State<Arc<AppState>>,
    auth_from_idp_params: Query<AuthFromIdpQueryParams>,
) -> Result<impl IntoResponse, AppError> {
    info!("handle_redirect_authfromidp {:?}", auth_from_idp_params);

    let original_code_verifier = {
        let mut lock = state.code_challenge_cache.lock().unwrap();
        let code_challenge_cache = &mut *lock;
        let original_code_verifier = code_challenge_cache
            .get(&auth_from_idp_params.state)
            .ok_or("State not found!")
            .map_err(|e| AppError::from_error_unauthorized(&e.to_string()))?
            .clone();
        code_challenge_cache.remove(&auth_from_idp_params.state);
        original_code_verifier
    };

    info!("original_code_verifier {:?}", original_code_verifier);

    let idp_tokens = state
        .token_manager
        .request_idp_tokens_via_code(&auth_from_idp_params.code, &original_code_verifier)
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    // info!("token request result: {:?}", idp_tokens);

    // NOTE: we construct `Set-Cookie` header manually because unable to get tower-cookies to work
    let access_token_cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax",
        ACCESS_TOKEN_COOKIE_ID, idp_tokens.access_token
    );
    let refresh_token_cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax",
        REFRESH_TOKEN_COOKIE_ID, idp_tokens.refresh_token
    );
    let identity_token_cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax",
        IDENTITY_TOKEN_COOKIE_ID, idp_tokens.id_token
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::LOCATION,
        HeaderValue::from_str("landing").unwrap(),
    );
    headers.insert(
        reqwest::header::SET_COOKIE,
        HeaderValue::from_str(&access_token_cookie).unwrap(),
    );
    headers.append(
        reqwest::header::SET_COOKIE,
        HeaderValue::from_str(&refresh_token_cookie).unwrap(),
    );
    headers.append(
        reqwest::header::SET_COOKIE,
        HeaderValue::from_str(&identity_token_cookie).unwrap(),
    );

    Ok((StatusCode::SEE_OTHER, headers).into_response())
}

pub async fn handle_rest_login(
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

    let mut lock = state.rest_token_cache.lock().unwrap();
    let rest_token_cache = &mut *lock;
    rest_token_cache.insert(user_id.clone(), tokens);

    Ok(user_id)
}

pub async fn handle_rest_admin_only(
    State(state): State<Arc<AppState>>,
    Extension(backend_host): Extension<String>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only");

    let roles: Vec<&str> = vec!["admin"];
    let tokens = check_rest_loggedin(
        &headers,
        &state.token_manager,
        &state.rest_token_cache,
        &roles,
    )
    .await?;

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

pub async fn handle_rest_all_roles(
    State(state): State<Arc<AppState>>,
    Extension(backend_host): Extension<String>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_all_roles");

    let roles_allowed: Vec<&str> = vec!["admin", "sachbearbeiter"];
    let tokens = check_rest_loggedin(
        &headers,
        &state.token_manager,
        &state.rest_token_cache,
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

async fn check_rest_loggedin(
    headers: &HeaderMap,
    token_manager: &TokenManager,
    token_cache: &Mutex<HashMap<String, Tokens>>,
    roles_allowed: &Vec<&str>,
) -> Result<Tokens, AppError> {
    let user_id_header = headers
        .get(REST_USER_ID_HEADER)
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

// NOTE: we extract `Set-Cookie` header manually because unable to get tower-cookies to work with axum (using State)
fn extract_cookie(headers: &HeaderMap, cookie_id: &str) -> Option<String> {
    let cookie_header = headers.get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?.to_string();
    let cookies: Vec<&str> = cookie_str.split("; ").collect();

    for cookie in cookies.iter() {
        let cookie_split: Vec<&str> = cookie.split("=").collect();
        if cookie_split.len() == 2 {
            if cookie_split[0] == cookie_id {
                return Some(cookie_split[1].to_string());
            }
        }
    }

    None
}

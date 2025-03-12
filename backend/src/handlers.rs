use std::sync::Arc;

use axum::{extract::State, http::HeaderMap};
use log::{info, warn};
use reqwest::StatusCode;
use shared::{
    app_error::AppError,
    token::{AccessToken, TokenManager},
};

use crate::app_state::AppState;

pub async fn handle_admin_only(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only");

    let roles: Vec<&str> = vec!["admin"];
    check_roles(&headers, &state.token_manager, &roles).await?;

    info!("handle_admin_only success");

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_all_roles");

    let roles_allowed: Vec<&str> = vec!["admin", "sachbearbeiter"];
    check_roles(&headers, &state.token_manager, &roles_allowed).await?;

    info!("handle_all_roles success");

    Ok("handle_all_roles success".to_string())
}

async fn check_roles(
    headers: &HeaderMap,
    token_manager: &TokenManager,
    roles_allowed: &Vec<&str>,
) -> Result<(), AppError> {
    let authorization_header = headers
        .get("Authorization")
        .ok_or(AppError::from_error_unauthorized("Missing bearer token"))?
        .to_str()
        .unwrap();

    let authorization_header_tokens: Vec<String> = authorization_header
        .to_string()
        .split(" ")
        .map(|s| s.to_string())
        .collect();

    if authorization_header_tokens.len() != 2 {
        return Err(AppError::from_error_unauthorized(
            "Malformed Authorization token, expected 'Bearer ACCESS_TOKEN'",
        ));
    }

    if authorization_header_tokens[0] != "Bearer" {
        return Err(AppError::from_error_unauthorized(
            "Invalid Authorization token, expected 'Bearer ACCESS_TOKEN'",
        ));
    }

    let access_token_encoded = authorization_header_tokens[1].clone();

    // NOTE: we introspect received token to check if it has been tampered with (zero-trust)
    let access_token: AccessToken = token_manager
        .introspect_access_token(&access_token_encoded)
        .await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    let access_token_sec_left = access_token.seconds_until_expiration();

    info!(
        "Checking Roles for Access Token which expires in {} secs",
        access_token_sec_left
    );

    if access_token.is_expired() {
        warn!("Access Token expired - refusing access");

        return Err(AppError::from_error_with_status(
            "Access Token expired - refusing access",
            StatusCode::UNAUTHORIZED,
        ));
    }

    if false == access_token.satisfies_any_role(roles_allowed) {
        warn!(
            "user {:?} access to resource refused because user roles {:?} did not satisfy allowed roles {:?}",
            access_token.sub, access_token.resource_access.idphandson.roles, roles_allowed
        );

        return Err(AppError::from_error_with_status(
            "Access not allowed",
            StatusCode::UNAUTHORIZED,
        ));
    }

    Ok(())
}

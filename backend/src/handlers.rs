use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{extract::State, http::HeaderMap};
use log::{info, warn};
use reqwest::StatusCode;
use shared::{
    app_error::AppError,
    token::{AccessToken, IdpDiscoveryDocument, introspect_access_token},
};

use crate::app_state::AppState;

pub async fn handle_admin_only(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only");

    let roles: Vec<&str> = vec!["admin"];
    check_roles(&headers, &state.idp_disc_doc, &roles).await?;

    info!("handle_admin_only success");

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_all_roles");

    let roles_allowed: Vec<&str> = vec!["admin", "sachbearbeiter"];
    check_roles(&headers, &state.idp_disc_doc, &roles_allowed).await?;

    info!("handle_all_roles success");

    Ok("handle_all_roles success".to_string())
}

async fn check_roles(
    headers: &HeaderMap,
    idp_disc_doc: &IdpDiscoveryDocument,
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

    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    // NOTE: we introspect received token to check if it has been tampered with (zero-trust)
    let access_token: AccessToken = introspect_access_token(
        idp_disc_doc,
        client_id,
        client_secret,
        &access_token_encoded,
    )
    .await
    .map_err(|e| AppError::from_error(&e.to_string()))?;

    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let now_secs = since_the_epoch.as_secs();

    let access_token_sec_left: i128 = access_token.exp as i128 - now_secs as i128;

    info!(
        "Checking Roles for Access Token which expires in {} secs",
        access_token_sec_left
    );

    if access_token_sec_left < 0 {
        warn!("Access Token expired - refusing access");

        return Err(AppError::from_error_with_status(
            "Access Token expired - refusing access",
            StatusCode::UNAUTHORIZED,
        ));
    }

    let mut role_found = false;

    for role_allowed in roles_allowed {
        if access_token
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
            access_token.sub, access_token.resource_access.idphandson.roles, roles_allowed
        );

        return Err(AppError::from_error_with_status(
            "Access not allowed",
            StatusCode::UNAUTHORIZED,
        ));
    }

    Ok(())
}

use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
use log::{debug, info};
use shared::bff_rest_dtos::LoginDTO;

use crate::{
    app_error::AppError,
    app_state::AppState,
    token::{Token, post_idp_token},
};

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(login_info): Json<LoginDTO>,
) -> Result<String, AppError> {
    debug!("handle_login: {:?}", login_info);

    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    let idp_token = post_idp_token(
        &state.idp_disc_doc,
        client_id,
        client_secret,
        &login_info.username,
        &login_info.password,
    )
    .await
    .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("idp_token: {:?}", idp_token);

    let token: Token = idp_token
        .try_into()
        .map_err(|e: String| AppError::from_error(e.as_str()))?;

    info!("token: {:?}", &token);

    let user_id = token.identity.sub.clone();

    let mut lock = state.token_cache.lock().await;
    let token_cache = &mut *lock;
    token_cache.insert(user_id.clone(), token);

    Ok(user_id)
}

pub async fn handle_admin_only(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    info!("handle_admin_only: {:?}", state.idp_disc_doc);

    let user_id_header = headers
        .get("user_id")
        .ok_or(AppError::from_error("Missing user_id header"))?;
    let user_id = user_id_header
        .to_str()
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    let mut lock = state.token_cache.lock().await;
    let token_cache = &mut *lock;

    let token = token_cache
        .get(user_id)
        .ok_or(AppError::from_error("User not logged in!"));

    info!("token: {:?}", token);

    Err(AppError::from_error(
        "handle_admin_only not implemented yet",
    ))?;

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(State(state): State<Arc<AppState>>) -> Result<String, AppError> {
    debug!("handle_all_roles: {:?}", state.idp_disc_doc);

    // TODO: implement

    Err(AppError::from_error("handle_all_roles not implemented yet"))?;

    Ok("handle_all_roles success".to_string())
}

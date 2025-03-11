use std::sync::Arc;

use axum::{extract::State, Json};
use log::{debug, info};
use shared::bff_rest_dtos::LoginDTO;

use crate::{app_error::AppError, app_state::AppState, token::get_token};

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(login_info): Json<LoginDTO>,
) -> Result<String, AppError> {
    debug!("handle_login: {:?}", login_info);

    // TODO: check if not already logged in
    
    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    let token = get_token(&state.idp_disc_doc, client_id, client_secret, &login_info.username, &login_info.password).await
        .map_err(|e| AppError::from_error(&e.to_string()))?;

    info!("token: {:?}", token);

    Err(AppError::from_error("handle_login not implemented yet"))?;

    Ok("handle_login success".to_string())
}

pub async fn handle_admin_only(
    State(state): State<Arc<AppState>>,
) -> Result<String, AppError> {
    debug!("handle_admin_only: {:?}", state.idp_disc_doc);

    // TODO: implement

    Err(AppError::from_error("handle_admin_only not implemented yet"))?;

    Ok("handle_admin_only success".to_string())
}

pub async fn handle_all_roles(
    State(state): State<Arc<AppState>>,
) -> Result<String, AppError> {
    debug!("handle_all_roles: {:?}", state.idp_disc_doc);

    // TODO: implement

    Err(AppError::from_error("handle_all_roles not implemented yet"))?;

    Ok("handle_all_roles success".to_string())
}
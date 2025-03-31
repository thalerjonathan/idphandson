use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};

use log::info;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared::app_error::AppError;
use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SCIMUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "externalId")]
    pub external_id: Option<String>,
    #[serde(alias = "userName")]
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<SCIMUserName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "displayName")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "nickName")]
    pub nick_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "profileUrl")]
    pub profile_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<String>>, // SCIMEmail seems not to work with WSO2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<SCIMAddress>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "phoneNumbers")]
    pub phone_numbers: Option<Vec<SCIMPhoneNumber>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ims: Option<Vec<SCIMIM>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photos: Option<Vec<SCIMPhoto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "userType")]
    pub user_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "preferredLanguage")]
    pub preferred_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<SCIMGroupMembership>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<SCIMMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Value>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMUserName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "familyName")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "givenName")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "middleName")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "honorificPrefix")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "honorificSuffix")]
    pub honorific_suffix: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMEmail {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "streetAddress")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "postalCode")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMPhoneNumber {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMIM {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMPhoto {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMGroupMembership {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Clone)]
pub struct SCIMMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "resourceType")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

pub async fn handle_scim_list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SCIMUser>>, AppError> {
    info!("handle_scim_list_users");

    let mut lock = state.scim_users.lock().unwrap();
    let scim_users = &mut *lock;
    let scim_users_result: Vec<SCIMUser> = scim_users.values().cloned().collect();

    Ok(Json(scim_users_result))
}

pub async fn handle_scim_create_user(
    State(state): State<Arc<AppState>>,
    Json(user): Json<SCIMUser>,
) -> Result<Json<SCIMUser>, AppError> {
    info!("handle_scim_create_user: {:?}", user);

    let mut lock = state.scim_users.lock().unwrap();
    let scim_users = &mut *lock;

    let user_id = Uuid::new_v4().to_string();

    scim_users.insert(user_id.clone(), user.clone());

    let new_user_with_id = SCIMUser {
        id: Some(user_id),
        ..user
    };

    // TODO: do i really need to return 201?

    Ok(Json(new_user_with_id))
}

pub async fn handle_scim_get_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> Result<Json<SCIMUser>, AppError> {
    info!("handle_scim_get_user: {:?}", user_id);

    let mut lock = state.scim_users.lock().unwrap();
    let scim_users = &mut *lock;

    match scim_users.get(&user_id) {
        None => Err(AppError::from_error_with_status(
            &format!("User {:?} not found", user_id),
            StatusCode::NOT_FOUND,
        )),
        Some(user) => Ok(Json(user.clone())),
    }
}

pub async fn handle_scim_update_full_user(
    State(state): State<Arc<AppState>>,
    Json(user): Json<SCIMUser>,
) -> Result<Json<SCIMUser>, AppError> {
    info!("handle_scim_update_full_user: {:?}", user);

    let mut lock = state.scim_users.lock().unwrap();
    let scim_users = &mut *lock;

    let user_id = user
        .id
        .clone()
        .ok_or("User missing id, cannot update")
        .map_err(|e| AppError::from_error_with_status(e, StatusCode::BAD_REQUEST))?;

    match scim_users.get(&user_id) {
        None => Err(AppError::from_error_with_status(
            &format!("User {:?} not found", user_id),
            StatusCode::NOT_FOUND,
        )),
        Some(_user) => {
            scim_users.insert(user_id, user.clone());
            Ok(Json(user))
        }
    }
}

pub async fn handle_scim_delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> Result<Json<()>, AppError> {
    info!("handle_scim_delete_user: {:?}", user_id);

    let mut lock = state.scim_users.lock().unwrap();
    let scim_users = &mut *lock;

    match scim_users.get(&user_id) {
        None => Err(AppError::from_error_with_status(
            &format!("User {:?} not found", user_id),
            StatusCode::NOT_FOUND,
        )),
        Some(_user) => {
            scim_users.remove(&user_id);
            Ok(Json(()))
        }
    }
}

use std::{collections::HashMap, sync::Mutex};

use shared::token::{TokenManager, Tokens};

use crate::handlers_scim::SCIMUser;

pub struct AppState {
    pub token_manager: TokenManager,
    pub rest_token_cache: Mutex<HashMap<String, Tokens>>,
    pub scim_users: Mutex<HashMap<String, SCIMUser>>,
}

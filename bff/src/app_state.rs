use std::{collections::HashMap, sync::Mutex};

use shared::token::{TokenManager, Tokens};

use crate::handlers_scim::SCIMUser;

pub struct AppState {
    pub token_manager: TokenManager,
    pub rest_token_cache: Mutex<HashMap<String, Tokens>>,
    pub code_challenge_cache: Mutex<HashMap<String, String>>, // NOTE: in production we prob would use REDIS which automatically evicts
    pub scim_users: Mutex<HashMap<String, SCIMUser>>,
}

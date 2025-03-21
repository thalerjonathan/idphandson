use std::{collections::HashMap, sync::Mutex};

use shared::token::{TokenManager, Tokens};

pub struct AppState {
    pub token_manager: TokenManager,
    pub rest_token_cache: Mutex<HashMap<String, Tokens>>,
}

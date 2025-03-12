use std::{collections::HashMap, sync::Mutex};

use shared::token::{IdpDiscoveryDocument, Tokens};

pub struct AppState {
    pub idp_disc_doc: IdpDiscoveryDocument,
    pub token_cache: Mutex<HashMap<String, Tokens>>,
}

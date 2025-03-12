use std::{collections::HashMap, sync::Mutex};

use crate::token::{IdpDiscoveryDocument, Tokens};

pub struct AppState {
    pub idp_disc_doc: IdpDiscoveryDocument,
    pub token_cache: Mutex<HashMap<String, Tokens>>,
}

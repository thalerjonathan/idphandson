use std::collections::HashMap;

use crate::token::{IdpDiscoveryDocument, Token};

pub struct AppState {
    pub idp_disc_doc: IdpDiscoveryDocument,
    pub token_cache: tokio::sync::Mutex<HashMap<String, Token>>,
}

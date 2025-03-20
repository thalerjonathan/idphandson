use app_state::AppState;
use axum::Extension;
use axum::http::Method;
use axum::routing::post;
use axum::{Router, routing::get};

use handlers::{
    handle_page_landing, handle_redirect_authfromidp, handle_rest_admin_only,
    handle_rest_all_roles, handle_rest_login,
};
use shared::get_from_env_or_panic;
use shared::token::TokenManager;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod app_state;
mod handlers;

#[tokio::main]
async fn main() {
    env_logger::init();

    let bff_host = get_from_env_or_panic("BFF_HOST");

    let idp_host = get_from_env_or_panic("IDP_HOST");
    let idp_realm = get_from_env_or_panic("IDP_REALM");

    let client_id = get_from_env_or_panic("CLIENT_ID");
    let client_secret = get_from_env_or_panic("CLIENT_SECRET");

    let backend_host: String = get_from_env_or_panic("BACKEND_HOST");

    let token_manager = TokenManager::new(&idp_host, &idp_realm, &client_id, &client_secret)
        .await
        .unwrap();

    let rest_token_cache = Mutex::new(HashMap::new());
    let app_state: AppState = AppState {
        token_manager,
        rest_token_cache,
    };
    let state_arc = Arc::new(app_state);

    let cors = tower_http::cors::CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
        .allow_origin(tower_http::cors::Any);

    let app = Router::new()
        .route(
            "/idphandson/bff/rest/adminonly",
            get(handle_rest_admin_only),
        )
        .route("/idphandson/bff/rest/allroles", get(handle_rest_all_roles))
        .route("/idphandson/bff/rest/login", post(handle_rest_login))
        .route("/idphandson/bff/landing", get(handle_page_landing))
        .route(
            "/idphandson/bff/authfromidp",
            get(handle_redirect_authfromidp),
        )
        .layer(cors)
        .layer(Extension(backend_host))
        .with_state(state_arc);

    let listener = tokio::net::TcpListener::bind(bff_host).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

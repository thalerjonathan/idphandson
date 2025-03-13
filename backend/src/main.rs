use app_state::AppState;
use axum::http::Method;
use axum::{Router, routing::get};

use handlers::{handle_admin_only, handle_all_roles};
use shared::get_from_env_or_panic;
use shared::token::TokenManager;

use std::sync::Arc;

mod app_state;
mod handlers;

#[tokio::main]
async fn main() {
    env_logger::init();

    let idp_host = get_from_env_or_panic("IDP_HOST");
    let idp_realm = get_from_env_or_panic("IDP_REALM");

    let client_id = get_from_env_or_panic("CLIENT_ID");
    let client_secret = get_from_env_or_panic("CLIENT_SECRET");

    let backend_host: String = get_from_env_or_panic("BACKEND_HOST");

    let token_manager = TokenManager::new(&idp_host, &idp_realm, &client_id, &client_secret)
        .await
        .unwrap();

    let app_state: AppState = AppState { token_manager };
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
        .route("/idphandson/backend/adminonly", get(handle_admin_only))
        .route("/idphandson/backend/allroles", get(handle_all_roles))
        .layer(cors)
        .with_state(state_arc);

    let listener = tokio::net::TcpListener::bind(backend_host).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

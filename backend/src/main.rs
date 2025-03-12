use app_state::AppState;
use axum::http::Method;
use axum::{Router, routing::get};

use handlers::{handle_admin_only, handle_all_roles};
use shared::token::TokenManager;

use std::sync::Arc;

mod app_state;
mod handlers;

#[tokio::main]
async fn main() {
    env_logger::init();

    // TODO: load from env
    let backend_host = "localhost:2345";

    let idp_host = "localhost:8080";
    let idp_realm = "idphandson";

    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    let token_manager = TokenManager::new(idp_host, idp_realm, client_id, client_secret)
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

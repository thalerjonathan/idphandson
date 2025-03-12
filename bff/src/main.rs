use app_state::AppState;
use axum::Extension;
use axum::http::Method;
use axum::routing::post;
use axum::{Router, routing::get};

use handlers::{handle_admin_only, handle_all_roles, handle_login};
use shared::token::TokenManager;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod app_state;
mod handlers;

#[tokio::main]
async fn main() {
    env_logger::init();

    // TODO: load from env
    let bff_host = "localhost:1234";

    let idp_host = "localhost:8080";
    let idp_realm = "idphandson";

    let client_id = "idphandson";
    let client_secret = "YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK";

    let backend_host: String = "localhost:2345".to_string();

    let token_manager = TokenManager::new(idp_host, idp_realm, client_id, client_secret)
        .await
        .unwrap();

    let token_cache = Mutex::new(HashMap::new());
    let app_state: AppState = AppState {
        token_manager,
        token_cache,
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
        .route("/idphandson/bff/adminonly", get(handle_admin_only))
        .route("/idphandson/bff/allroles", get(handle_all_roles))
        .route("/idphandson/bff/login", post(handle_login))
        .layer(cors)
        .layer(Extension(backend_host))
        .with_state(state_arc);

    let listener = tokio::net::TcpListener::bind(bff_host).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

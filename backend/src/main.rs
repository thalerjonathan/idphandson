use app_state::AppState;
use axum::http::Method;
use axum::{Router, routing::get};

use handlers::{handle_admin_only, handle_all_roles};
use log::info;
use shared::token::get_discovery_document;

use std::sync::Arc;

mod app_state;
mod handlers;

#[tokio::main]
async fn main() {
    env_logger::init();

    let backend_host = "localhost:2345";

    let idp_host = "localhost:8080";
    let idp_realm = "idphandson";

    let idp_disc_doc = get_discovery_document(idp_host, idp_realm).await.unwrap();

    info!(
        "Successfully queried discovery document from Idp: {:?}",
        idp_disc_doc
    );

    let app_state: AppState = AppState { idp_disc_doc };
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

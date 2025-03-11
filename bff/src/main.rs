use app_state::AppState;
use axum::http::Method;
use axum::routing::post;
use axum::{Router, routing::get};

use handlers::{handle_admin_only, handle_all_roles, handle_login};
use log::info;
use token::get_discovery_document;
use tokio::sync::Mutex;

use std::collections::HashMap;
use std::sync::Arc;

mod app_error;
mod app_state;
mod handlers;
mod token;

#[tokio::main]
async fn main() {
    env_logger::init();

    let bff_host = "localhost:1234";

    let idp_host = "localhost:8080";
    let idp_realm = "idphandson";

    let idp_disc_doc = get_discovery_document(idp_host, idp_realm).await.unwrap();

    info!(
        "Successfully queried discovery document from Idp: {:?}",
        idp_disc_doc
    );

    let token_cache = Mutex::new(HashMap::new());
    let app_state: AppState = AppState {
        idp_disc_doc,
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
        .with_state(state_arc);

    let listener = tokio::net::TcpListener::bind(bff_host).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

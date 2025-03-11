use std::collections::HashMap;

use log::info;
use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct IdpDiscoveryDocument {
    // A OAuth2-compliant Token Endpoint that supports the urn:ietf:params:oauth:grant-type:uma-ticket grant type. Through this endpoint, clients can send authorization requests and obtain an RPT with all permissions granted by Keycloak.
    token_endpoint: String,
    // A OAuth2-compliant Token Introspection Endpoint which clients can use to query the server to determine the active state of an RPT and to determine any other information associated with the token, such as the permissions granted by Keycloak.
    introspection_endpoint: String,
    // A UMA-compliant Resource Registration Endpoint which resource servers can use to manage their protected resources and scopes. This endpoint provides operations create, read, update and delete resources and scopes in Keycloak.
    resource_registration_endpoint: String,
    // A UMA-compliant Permission Endpoint which resource servers can use to manage permission tickets. This endpoint provides operations create, read, update, and delete permission tickets in Keycloak.
    permission_endpoint: String,

    authorization_endpoint: String,
    policy_endpoint: String,
    end_session_endpoint: String,
    jwks_uri: String,
    registration_endpoint: String,
}

#[derive(Debug, Deserialize)]
// Returned from IdpDiscoveryDocument.token_endpoint
pub struct Token {
    access_token: String,
    expires_in: u64,
    refresh_expires_in: u64,
    refresh_token: String,
    token_type: String,
    id_token: String,
    session_state: String,
    scope: String
}

pub async fn get_discovery_document(idp_host: &str, realm: &str,
) -> Result<IdpDiscoveryDocument, reqwest::Error> {
    let url = Url::parse(&format!(
        "http://{}/realms/{}/.well-known/uma2-configuration",
        idp_host,
        realm
    ));

    let response = reqwest::Client::new().get(url.unwrap()).send().await?;
    response.json().await
}

pub async fn get_token(idp_doc: &IdpDiscoveryDocument, client_id: &str, client_secret: &str, username: &str, password: &str) 
    -> Result<Token, reqwest::Error> {
    /*
    curl -X POST "http://localhost:8080/realms/idphandson/protocol/openid-connect/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=idphandson" \
     -d "client_secret=YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK" \
     -d "grant_type=password" \
     -d "username=alice" \
     -d "password=alice" \
     -d "scope=openid"
     */
    let url = Url::parse(&idp_doc.token_endpoint);

    info!("url: {:?}", url);

    // Prepare the form data
    let mut params = HashMap::new();
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    params.insert("grant_type", "password");
    params.insert("username", username);
    params.insert("password", password);
    params.insert("scope", "openid");

    let response = reqwest::Client::new()
        .post(url.unwrap())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params) 
        .send()
        .await?;
    
    info!("response: {:?}", response);

    response.json().await
}
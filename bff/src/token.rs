use std::collections::{HashMap, HashSet};

use jsonwebtoken::DecodingKey;
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

/*
Example returned from Keycloak

{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0MkdBM1NVa3RUUTVibll4SnNITzBYUGdLS09RX2MtTWl3YUc4U25Wb3VvIn0.eyJleHAiOjE3NDE2OTI3NzAsImlhdCI6MTc0MTY5MjQ3MCwianRpIjoiOWM4MmE5M2ItOWJlMC00ZmU0LTljYzAtYzBkMGY2NGVjNmRkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjlmYWEzYmQ1LTA2YjUtNDE0Ny1iYzBmLTQ0NWQzNmRjNTQ0NiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImlkcGhhbmRzb24iLCJzaWQiOiJlMGQzODU3Ni04M2I3LTQ2ZmItYjZmNC0xZTFhNmU0ODM4OWUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6MTIzNCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1pZHBoYW5kc29uIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFRlc3QiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiVGVzdCIsImVtYWlsIjoiYWxpY2VAdGVzdC5jb20ifQ.SyMZ0pP6gUrEI49a99S8P2Q2AiUEtcLfwN2cbWmjd411Fe25qlSOJ8mzSnI9CPe6cFev1yGxgKtCXQpqI4g5G2iL_laD1LAtWClhZU-rj_X-49YDZL_g1T0JPfGQKw2ENmHSiEipDhQ84SQ_zsaDCEdbnTxxCb5bGWaL0DAzLWw5ZDSiR-kPPaZ_dYAtbHnT6xdlVuNgkOMT_Ac6uEnuYSnXvST-PhGBLRd8iJ_vGw2LPQL9g9bfhAp1IRW09g6_JqNIuZH9gKTnWR7n6wGC8wn7P2YJ6ZQ9NBaoo677H2M-VqA4Pu-PFV7rF9N_ij3mrsfhFt47ro2nTCuJZEMG0g",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1NjE0ZTQ4Zi1hNzc3LTQyNzktYWFkOS03NWYxNDExNWU0MWMifQ.eyJleHAiOjE3NDE2OTQyNzAsImlhdCI6MTc0MTY5MjQ3MCwianRpIjoiMWNmOWQ4NTUtNGNjNy00ZDJkLTk3ZWQtOTkxOThhYjc5Zjg2IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwic3ViIjoiOWZhYTNiZDUtMDZiNS00MTQ3LWJjMGYtNDQ1ZDM2ZGM1NDQ2IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImlkcGhhbmRzb24iLCJzaWQiOiJlMGQzODU3Ni04M2I3LTQ2ZmItYjZmNC0xZTFhNmU0ODM4OWUiLCJzY29wZSI6Im9wZW5pZCBhY3IgcHJvZmlsZSBlbWFpbCB3ZWItb3JpZ2lucyBzZXJ2aWNlX2FjY291bnQgYmFzaWMgcm9sZXMifQ.XZ498MIWdD2wLL5Ssjcd8ctI_Tm39edylvTS_ZSosYpVEpoPkPqrmtVvJZu7LkzxO_eVWmEB4ztp011_XCQwNg",
    "token_type": "Bearer",
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0MkdBM1NVa3RUUTVibll4SnNITzBYUGdLS09RX2MtTWl3YUc4U25Wb3VvIn0.eyJleHAiOjE3NDE2OTI3NzAsImlhdCI6MTc0MTY5MjQ3MCwianRpIjoiZWNiZTVjMmMtNmMzOS00NjUwLThhZTMtMzM4N2QyMDVkMDZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwiYXVkIjoiaWRwaGFuZHNvbiIsInN1YiI6IjlmYWEzYmQ1LTA2YjUtNDE0Ny1iYzBmLTQ0NWQzNmRjNTQ0NiIsInR5cCI6IklEIiwiYXpwIjoiaWRwaGFuZHNvbiIsInNpZCI6ImUwZDM4NTc2LTgzYjctNDZmYi1iNmY0LTFlMWE2ZTQ4Mzg5ZSIsImF0X2hhc2giOiJBZDZ4blVDM0IwZ2VpamdLdmYxc3pRIiwiYWNyIjoiMSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiQWxpY2UgVGVzdCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJUZXN0IiwiZW1haWwiOiJhbGljZUB0ZXN0LmNvbSJ9.YKP4zx7OCofavE6YJnAO-AShZaOYCaENlqCojN3wCMYFUFqBMknGBGhGzo0iDmUtqVxqU6lRPc63riXnid9EXoOZf62I2B6w2_l8KUpC102eZKEC-qnixJa4srsDcT8WQrBi2kPH_hmIIKMHkRXnE9U6O9z7XkgxkxPqj-YNnj9n-j2fTOLgfGFw54FjWE2HC5l9Ba6asEpPX3ujtXUOsph6F2UKeE0yYbiuxQFfjV7rxpTaabBBmS-pf6OD20RbCdmb-8hfrLt2JySIfWXsQNTQ5-yaQ_o1DwN2ihc32AWlDEoe9BfH6vq-G55BtqgYgLBJDmKVavOovTr7p4TR1Q",
    "not-before-policy": 0,
    "session_state": "e0d38576-83b7-46fb-b6f4-1e1a6e48389e",
    "scope": "openid profile email"
}
*/
#[derive(Debug, Clone, Deserialize)]
// Returned from IdpDiscoveryDocument.token_endpoint
pub struct IdpTokens {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub refresh_token: String,
    pub token_type: String,
    pub id_token: String,
    pub session_state: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub idp: IdpTokens,
    pub identity: IdentityToken,
    pub refresh: RefreshToken,
    pub access: AccessToken,
}

/*
Example Identity Token Payload from Keycloak

{
  "exp": 1741692770,
  "iat": 1741692470,
  "jti": "ecbe5c2c-6c39-4650-8ae3-3387d205d06a",
  "iss": "http://localhost:8080/realms/idphandson",
  "aud": "idphandson",
  "sub": "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
  "typ": "ID",
  "azp": "idphandson",
  "sid": "e0d38576-83b7-46fb-b6f4-1e1a6e48389e",
  "at_hash": "Ad6xnUC3B0geijgKvf1szQ",
  "acr": "1",
  "email_verified": true,
  "name": "Alice Test",
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "Test",
  "email": "alice@test.com"
}
*/

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityToken {
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub typ: String,
    pub azp: String,
    pub sid: String,
    pub at_hash: String,
    pub acr: String,
    pub email_verified: bool,
    pub name: String,
    pub preferred_username: String,
    pub given_name: String,
    pub family_name: String,
    pub email: String,
}

/*
Example Refresh Token Payload from Keycloak

{
  "exp": 1741694270,
  "iat": 1741692470,
  "jti": "1cf9d855-4cc7-4d2d-97ed-99198ab79f86",
  "iss": "http://localhost:8080/realms/idphandson",
  "aud": "http://localhost:8080/realms/idphandson",
  "sub": "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
  "typ": "Refresh",
  "azp": "idphandson",
  "sid": "e0d38576-83b7-46fb-b6f4-1e1a6e48389e",
  "scope": "openid acr profile email web-origins service_account basic roles"
}
*/
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshToken {
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub typ: String,
    pub azp: String,
    pub sid: String,
    pub scope: String,
}

/*
Example Access Token Payload from Keycloak

{
  "exp": 1741766129,
  "iat": 1741766124,
  "jti": "b31cda76-530b-4bd6-8ed2-4966654d3104",
  "iss": "http://localhost:8080/realms/idphandson",
  "sub": "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
  "typ": "Bearer",
  "azp": "idphandson",
  "sid": "9164ece8-d57d-4d61-b2a5-f4f9c957d555",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:1234"
  ],
  "resource_access": {
    "idphandson": {
      "roles": [
        "sachbearbeiter",
        "admin"
      ]
    }
  },
  "scope": "openid profile email",
  "email_verified": true,
  "name": "Alice Test",
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "Test",
  "email": "alice@test.com"
}
*/
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceAccess {
    pub idphandson: ResourceAccessAccount,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceAccessAccount {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessToken {
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub iss: String,
    pub sub: String,
    pub typ: String,
    pub azp: String,
    pub sid: String,
    pub acr: String,
    #[serde(alias = "allowed-origins")]
    pub allowed_origins: Vec<String>,
    pub resource_access: ResourceAccess,
    pub scope: String,
    pub email_verified: bool,
    pub name: String,
    pub preferred_username: String,
    pub given_name: String,
    pub family_name: String,
    pub email: String,
}

impl TryFrom<IdpTokens> for Tokens {
    type Error = String;

    fn try_from(value: IdpTokens) -> Result<Self, Self::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.required_spec_claims = HashSet::new();
        validation.validate_aud = false;
        validation.insecure_disable_signature_validation();
        let key = DecodingKey::from_secret(&[]);

        /* Example decoded Identity Token from Keycloak
        TokenData {
            header: Header {
                typ: Some("JWT"),
                alg: RS256,
                cty: None,
                jku: None,
                jwk: None,
                kid: Some("42GA3SUktTQ5bnYxJsHO0XPgKKOQ_c-MiwaG8SnVouo"),
                x5u: None,
                x5c: None,
                x5t: None,
                x5t_s256: None
            },
            claims: IdentityToken {
                exp: 1741702618,
                iat: 1741702318,
                jti: "5978496d-3289-437a-bf3f-b9000df92e63",
                iss: "http://localhost:8080/realms/idphandson",
                aud: "idphandson",
                sub: "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
                typ: "ID",
                azp: "idphandson",
                sid: "603e0cbd-9035-46fd-a754-f43cae72becb",
                at_hash: "tuLIRu7EYwKYkDXBv02WTQ",
                acr: "1",
                email_verified: true,
                name: "Alice Test",
                preferred_username: "alice",
                given_name: "Alice",
                family_name: "Test",
                email: "alice@test.com"
            }
        }
         */
        let identity_token_result =
            jsonwebtoken::decode::<IdentityToken>(&value.id_token, &key, &validation).map_err(
                |e| {
                    format!(
                        "failed to decode identity token with error {}",
                        e.to_string()
                    )
                },
            )?;
        info!("identity_token_result: {:?}", identity_token_result);

        /* Example decoded Refresh Token from Keycloak
        TokenData {
            header: Header {
                typ: Some("JWT"),
                alg: HS512,
                cty: None,
                jku: None,
                jwk: None,
                kid: Some("5614e48f-a777-4279-aad9-75f14115e41c"),
                x5u: None,
                x5c: None,
                x5t: None,
                x5t_s256: None
            },
            claims: RefreshToken {
                exp: 1741704689,
                iat: 1741702889,
                jti: "efea4aa8-ffd1-49b6-a792-252a68f04802",
                iss: "http://localhost:8080/realms/idphandson",
                aud: "http://localhost:8080/realms/idphandson",
                sub: "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
                typ: "Refresh",
                azp: "idphandson",
                sid: "2d2737a9-9cb7-487e-ab06-07400a1a8485",
                scope: "openid acr profile email web-origins service_account basic roles"
            }
        }
         */
        let refresh_token_result =
            jsonwebtoken::decode::<RefreshToken>(&value.refresh_token, &key, &validation).map_err(
                |e| {
                    format!(
                        "failed to decode refresh token with error {}",
                        e.to_string()
                    )
                },
            )?;
        info!("refresh_token_result: {:?}", refresh_token_result);

        /* Example decoded Access Token from Keycloak
        TokenData {
            header: Header {
                typ: Some("JWT"),
                alg: RS256,
                cty: None,
                jku: None,
                jwk: None,
                kid: Some("42GA3SUktTQ5bnYxJsHO0XPgKKOQ_c-MiwaG8SnVouo"),
                x5u: None,
                x5c: None,
                x5t: None,
                x5t_s256: None
            },
            claims: AccessToken {
                exp: 1741766337,
                iat: 1741766332,
                jti: "3ba87a53-0329-4444-8272-4ac792e9c084",
                iss: "http://localhost:8080/realms/idphandson",
                sub: "9faa3bd5-06b5-4147-bc0f-445d36dc5446",
                typ: "Bearer",
                azp: "idphandson",
                sid: "7d47c1ed-02f8-416f-94a5-fc496f053d0e",
                acr: "1",
                allowed_origins: ["http://localhost:1234"],
                resource_access: ResourceAccess {
                    idphandson: ResourceAccessAccount {
                        roles: ["sachbearbeiter", "admin"]
                    }
                },
                scope: "openid profile email",
                email_verified: true,
                name: "Alice Test",
                preferred_username: "alice",
                given_name: "Alice",
                family_name: "Test",
                email: "alice@test.com"
            }
        }
         */
        let access_token_result =
            jsonwebtoken::decode::<AccessToken>(&value.access_token, &key, &validation).map_err(
                |e| format!("failed to decode access token with error {}", e.to_string()),
            )?;
        info!("access_token_result: {:?}", access_token_result);

        Ok(Tokens {
            idp: value,
            identity: identity_token_result.claims,
            refresh: refresh_token_result.claims,
            access: access_token_result.claims,
        })
    }
}

pub async fn get_discovery_document(
    idp_host: &str,
    realm: &str,
) -> Result<IdpDiscoveryDocument, reqwest::Error> {
    let url = Url::parse(&format!(
        "http://{}/realms/{}/.well-known/uma2-configuration",
        idp_host, realm
    ));

    let response = reqwest::Client::new().get(url.unwrap()).send().await?;
    response.json().await
}

pub async fn request_idp_tokens(
    idp_doc: &IdpDiscoveryDocument,
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
) -> Result<IdpTokens, reqwest::Error> {
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

    info!("request_idp_token url: {:?}", url);

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

    info!("request_idp_token response: {:?}", response);

    response.json().await
}

pub async fn refresh_tokens(
    idp_doc: &IdpDiscoveryDocument,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<IdpTokens, reqwest::Error> {
    /*
    curl -X POST "http://localhost:8080/realms/idphandson/protocol/openid-connect/token" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "client_id=idphandson" \
         -d "client_secret=YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK" \
         -d "grant_type=refresh_token" \
         -d "refresh_token=REFRESH_TOKEN"
    */
    let url = Url::parse(&idp_doc.token_endpoint);

    info!("refresh_token url: {:?}", url);

    // Prepare the form data
    let mut params = HashMap::new();
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    params.insert("grant_type", "refresh_token");
    params.insert("refresh_token", refresh_token);
    params.insert("scope", "openid");

    let response = reqwest::Client::new()
        .post(url.unwrap())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;

    info!("refresh_token response: {:?}", response);

    response.json().await
}

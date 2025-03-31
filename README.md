# Idp Hands-On

This repo contains stuff collected while traying to get hands-on experience with topics related to IAM/Idp: OAuth2, SAML, SSO, JWT, OIDC, SCIM.

## Components

### Idp

We have set up Keycloack as a dockerised Identity Provider (Idp): https://www.keycloak.org/getting-started/getting-started-docker
To configure it for the application:
1. Naviagte to http://localhost:8080/admin/ and log in by admin/admin
2. Create a new Realm "idphandson" and switch to it
3. Create a new Client "idphandson" in the new Realm. This Client represents the BFF and Backend REST Services. Set client secret to "Awn3a59BOFLTpZ9PK7HuRWarMW04mKeW"
4. Create 2 new Client Roles "admin", "sachbearbeiter" in the Client
5. Create a new User "alice" with password "alice", put some values into email, first and last name otherwise Keycloak reports the user not to be ready to use. Remove default roles and assign Role "admin" and "sachbearbeiter" to alice
6. Create a new Users "bob" with password "bob" (dont forget email, first last name). Remove default roles and assign Role "sachbearbeiter" to bob
7. To enable PKCE: select the Client and under settings:
    - Ensure Access Type is public (PKCE is mainly for public clients), that is Client Authentication should be OFF
    - Ensure Standard Flow Enabled is ON (PKCE works with Authorization Code Flow)
    - Under Advanced Settings → Proof Key for Code Exchange Required → Set to "Code Challenge Required"

### BFF
A small BFF REST service in Rust with 2 REST endpoints. This service acts as BFF for the Frontend. The BFF holds the tokens and forwards them to the Backend REST service for authorization. Also, the BFF does not expose the tokens to the Frontend, and only returns a simple user-id for identification.

## Backend
A small Backend REST service in Rust with 2 REST endpoints that receives the Access token from the BFF and introspects it at the Idp to check if it is valid.

### Frontend
A very simple Rust application that plays through a simple scenario with login and calling the 2 REST endpoints, mimicking a Frontend via HTTP REST calls.

## Browser Based "Authorization Code Flow" 

see https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc-auth-flows-authorization

1. In Browser navigate to http://localhost:1234/idphandson/bff/landing
2. BFF checks if tokens are present in Http-only cookies
    - If yes, decode and validate token using JWK, that is, the certificates of the Idp. If valid, then simply show HTML page, rendering username and roles. If invalid/expired, proceed with point 3 (redirect, see below).
3. If tokens are not found in cookies, issue a redirect to Idp login page with a callback uri in case login is successful.
4. Idp processes login and redirects back to BFF 'idphandson/bff/authfromidp' URL.
5. BFF extracts code query param and requests tokens from Idpl
6. BFF redirects back to the original url (see 1.) but now with tokens in Http-only cookies and performs the same as in 2. but finds now a token.

NOTE: PKCE (Proof Key for Code Exchange) is implemented, by sending 2 concatenated uuid v4 strings SHA256 Hashed as code_verifier, using a uuid v4 as state to connect the incoming redirect.

## Service-Based Flow

1. Frontend (FE) requests login at BFF via login REST endpoint, using user credentials (username, password). Note that all traffic in this example is NOT using HTTPS but unencrypted HTTP, so in a production environment this needs to be changed to HTTPS to make the transmission of user credentials secure.
2. BFF contacts Identity Provider (Idp) to fetch a token for the given user credentials.
3. Idp returns Identity, Refresh and Access token to BFF.
4. BFF decodes and stores the tokens in its token cache and returns a unique user_id that identifies the user. For now this user_id is the "sub" part of the Identity token, therefore it is provided by the Idp. If necessary, this can be changed to a UUID4 generated in the BFF and used instead, because BFF/Backend are not using the "sub" in any way when interacting with the Idp. The only thing that is required from the user_id is that it is unique across all users, as it is used to store and look up the tokens in the token cache.
5. BFF returns the user_id to the FE.
6. FE makes a call to any of the secured (non login) REST endpoints. It adds the user_id in a separate "user_id" header.
7. BFF extracts the user_id from the "user_id" header and looks up the tokens in the token cache. If there are none found, this means that the user is not logged in and BFF returns 401.
8. BFF checks if the Authorization token is expired. If the Authorization token is expired, it checks if the Refresh Token is expired. If the Refresh Token is expired it returns 401 indicating that the User needs to re-login. If the Refresh Token is not expired, it refreshes the tokens from the Idp by sending the Refresh Token. Note that we do not use an introspection point at the Idp but simply trust that the token we received from the Idp is correct.
9. BFF checks if the (potentially refreshed) Access token contains the necessary role. If not then it returns 401. If yes, then it does a HTTP call to the Backend, passing the Access token in an "Authorization Bearer ACCESS_TOKEN" header.
10. Backend extracts the Access token from the "Authorization" header, and uses the introspection point of the Idp to validate it. It then checks for the necessary role and if not satisfied returns 401, or 200 otherwise. Note that we do not handle the case where the Access token is expired. Although it is a very rare edge case because the BFF just checked the expiration and its very low probability that in the few milliseconds between the checking in the BFF and the call of the Backend to the introspection point, that the Access token expires - still it is possible. In this case we can deal with it basically only in 1 way: communicate a suitable error code back to the BFF which then goes on to refresh the tokens and re-try the call to the Backend. Note that in this flow implementation, the Backend cannot request a new Token because it simply doesn't hold the Refresh token. Therefore the BFF is in full control and charge of all the tokens, which is much more secure. In this case where we have synchronous calls from the FE through to the BFF down to the Backend, an expiring Access Token either in the BFF or Backend is not really too much trouble, and just needs to be dealt with robustly by refreshing the tokens. However, if we had long-running async operations in the Backend, then we have to deal with them in an entirely different way, bypassing the user access token, and resorting to some kind of either offline tokens or a new service account that gets a separate token just for long running operations.
11. BFF awaits the response of the Backend and simply returns 200 after success.
12. Frontend has been waiting synchronously for the response of the BFF and continues the processing once the HTTP REST request returned.

## SCIM 

The BFF implements a REST interface that follows the SCIM specification, for provisioning and managing Users. Note that the users are only kept in an in-memory HashMap and not persistet. Also, the users are NOT used for authentication in the BFF, which uses the actual Access Token from the headers - see above. So this part exists purely to develop an understanding of what the SCIM interface looks like and also how to integrate it with an identity provider.

Keycloak serves as the front-facing Idp to the BFF therefore it can be seen as Identity Broker. It forwards authentication to WSO2, which servces as the back-facing Idp to Kecloak. 

WSO2 should be already running from the docker-compose.yml file. Make really sure it runs in "network_mode: host" so that it can connect to the BFF to provision users.

1. Log in to WSO2 via https://localhost:9443/console admin/admin
2. follow https://is.docs.wso2.com/en/latest/guides/users/outbound-provisioning/provisioning-levels/org-level/#enable-organization-level-outbound-provisioning
3. Make sure that the SCIM URL to the BFF is correct: make sure the URL is correct http://localhost:1234/idphandson/scim/v2/Users

NOTE: for some reason WSO2 isn't happy with the returned JSON from the POST /Users endpoint and I couldn't really find out what was the problem, also because WSO2 has terrible error messages. For the SCIM hands-on experiment however this suffices.

NOTE: we override have `provisioning.outbound.scim` config in deployment.toml to disable HTTPS for provisioning, otherwise would run into x509 error.

Conclusion: it was substantially harder to config WSO2 (and its infra) and figure out the JSON format on the receiving end, than the rest.

## TODOs

- export/import realm config
- set up identity provider (some that does not require some cloud application: LinkedIn or FB)
- set up a dockerised LDAP with some test users with test roles/OUs: https://github.com/osixia/docker-openldap 
    - Navigate to http://localhost:8081 and log in by Login DN: 'cn=admin,dc=example,dc=com' and Password: 'admin'
- set up an IAM tool that connects to LDAP and the Idp: wso2
    - https://localhost:9443/console and log in by admin/admin
    - https://htamahc.medium.com/configuring-keycloak-as-an-identity-provider-in-wso2-identity-server-c5cc124b6d6c
    - https://chakray.com/how-use-keycloak-as-wso2-api-manager-identity-provider/

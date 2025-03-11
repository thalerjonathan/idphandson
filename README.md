# Idp Hands-On

This repo contains stuff collected while traying to get hands-on experience with topics related to IAM/Idp: Active Directory, OAuth2, SAML, SSO, JWT, OIDC.

1. set up a dockerised Identity Provider (Idp) that is able to connect to the dockerised LDAP: https://www.keycloak.org/getting-started/getting-started-docker
    - Naviagte to http://localhost:8080/admin/ and log in by admin/admin
    - Create a new Realm R and switch to it
    - Create 2 new Realm Roles RO1, RO2 in the Realm
    - Create a new Client C in the new Realm. This Client represents the REST Service.
    - Create 2 new Users U1 and U2 in the new Realm.
        - Assign RO1 and RO2 to U1
        - Assign R02 to U2
    - export/import realm config
2. set up a small BFF REST service in Rust with 2 REST endpoints. This service acts as BFF for a potential UI. The BFF holds the tokens and forwards them to the Backend REST service for authorization. We are not sending the identity token back to the Backendservice. Also: the BFF does not expose the tokens to the UI, but need to find out how we implement the flow then.
    - Implement a "Login" to fetch the bearer token that is gonna be stored in the BFF
3. set up a small Backend REST service in Rust with 2 REST endpoints that receives the token from the BFF and unpacks it and uses an inspection endpoint with the Idp to check if the token is valid.
4. implement a 3rd Rust application that mimicks the Frontend via HTTP REST calls. Also implement refresh tokens
3. Implement "Authorization Code Flow" https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc-auth-flows-authorization
    - Server Side Client using Rust
    - https://www.oauth.com/oauth2-servers/token-introspection-endpoint/
4. explore SSO

## TODO Identity Provider / IAM / LDAP / AD integration: after Idp <-> REST Server interaction and SSO works 
- set up identity provider (some that does not require some cloud application: LinkedIn or FB)
- set up a dockerised LDAP with some test users with test roles/OUs: https://github.com/osixia/docker-openldap 
    - Navigate to http://localhost:8081 and log in by Login DN: 'cn=admin,dc=example,dc=com' and Password: 'admin'
- set up an IAM tool that connects to LDAP and the Idp: wso2
    - https://localhost:9443/console and log in by admin/admin
    - https://htamahc.medium.com/configuring-keycloak-as-an-identity-provider-in-wso2-identity-server-c5cc124b6d6c
    - https://chakray.com/how-use-keycloak-as-wso2-api-manager-identity-provider/



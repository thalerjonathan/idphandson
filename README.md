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
2. create script for automatically configuring Idp via REST (is this actually possible?)
    - new realm
    - new testuser 
    - new testuser roles
3. set up a small REST service in Rust with 2-3 REST endpoints.
4. Implement "Authorization Code Flow" https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc-auth-flows-authorization
    - Server Side Client using Rust
    - https://www.oauth.com/oauth2-servers/token-introspection-endpoint/
5. explore SSO

## TODO Identity Provider / IAM / LDAP / AD integration: after Idp <-> REST Server interaction and SSO works 
- set up identity provider (some that does not require some cloud application: LinkedIn or FB)
- set up a dockerised LDAP with some test users with test roles/OUs: https://github.com/osixia/docker-openldap 
    - Navigate to http://localhost:8081 and log in by Login DN: 'cn=admin,dc=example,dc=com' and Password: 'admin'
- set up an IAM tool that connects to LDAP and the Idp: wso2
    - https://localhost:9443/console and log in by admin/admin
    - https://htamahc.medium.com/configuring-keycloak-as-an-identity-provider-in-wso2-identity-server-c5cc124b6d6c
    - https://chakray.com/how-use-keycloak-as-wso2-api-manager-identity-provider/



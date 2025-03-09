# Idp Hands-On

This repo contains stuff collected while traying to get hands-on experience with topics related to IAM/Idp: Active Directory, OAuth2, SAML, SSO, JWT, OIDC.

1. set up a dockerised LDAP with some test users with test roles/OUs: https://github.com/osixia/docker-openldap 
2. set up a dockerised Identity Provider (Idp) that is able to connect to the dockerised LDAP: https://www.keycloak.org/getting-started/getting-started-docker
3. set up an IAM tool that connects to LDAP and the Idp: wso2
3. set up a small REST service in Rust with 2-3 REST endpoints.
4. Implement identity flow using OAuth2 from Rust service to Idp for login to receive   
    - identity token from idp
    - authorization token with roles from idp
    - refresh token from idp
5. In each REST endpoint check the token and roles required
    - explore signed token
    - explore encrypted token
6. explore SSO
7. explore SAML

## LDAP: OpenLDAP
Navigate to http://localhost:8081 and log in by Login DN: 'cn=admin,dc=example,dc=com' and Password: 'admin'

## Idp: Keycloak
Naviagte to http://localhost:8080/admin/ and log in by admin/admin

## IAM Identity Server: WSO2
https://localhost:9443/console and log in by admin/admin

## TODO

https://htamahc.medium.com/configuring-keycloak-as-an-identity-provider-in-wso2-identity-server-c5cc124b6d6c

https://chakray.com/how-use-keycloak-as-wso2-api-manager-identity-provider/

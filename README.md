# Idp Hands-On

This repo contains stuff collected while traying to get hands-on experience with topics related to IAM/Idp: Active Directory, OAuth2, SAML, SSO, JWT, OIDC.

1. set up a dockerised LDAP or AD with some test users with test roles/OUs.
2. set up a dockerised test/mock Idp/OAuth2 server that connects to the dockerised LDAP/AD.
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

## Dockerised LDAP/AD and Mock Idp/OAuth2 server

### LDAP / AD
https://github.com/osixia/docker-openldap

Navigate to http://localhost:8081 and log in by Login DN: 'cn=admin,dc=example,dc=com' and Password: 'admin'

### IDP
https://www.keycloak.org/getting-started/getting-started-docker

Naviagte to http://localhost:8080/admin/ and log in by admin/admin.

### Misc
https://gitlab.com/yaal/canaille
https://github.com/authelia/authelia
https://github.com/freeipa/freeipa-container
https://github.com/rroemhild/docker-test-openldap
https://hub.docker.com/r/bitnami/openldap
https://github.com/kenchan0130/docker-simplesamlphp
https://github.com/kristophjunge/docker-test-saml-idp
https://github.com/navikt/mock-oauth2-server
https://hub.docker.com/r/richardknop/go-oauth2-server

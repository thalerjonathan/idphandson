curl -X POST "http://localhost:8080/realms/lambdabytes/protocol/openid-connect/token/introspect" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=lambdabytes" \
     -d "client_secret=YOUR_CLIENT_SECRET" \
     -d "token=YOUR_ACCESS_TOKEN"

curl -X POST "http://localhost:8080/realms/lambdabytes/protocol/openid-connect/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=lambdabytes" \
     -d "grant_type=password" \
     -d "username=testuser" \
     -d "password=test" \
     -d "scope=openid"
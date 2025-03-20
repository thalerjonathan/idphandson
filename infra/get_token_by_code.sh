
curl -X POST "http://localhost:8080/realms/idphandson/protocol/openid-connect/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=idphandson" \
     -d "client_secret=Awn3a59BOFLTpZ9PK7HuRWarMW04mKeW" \
     -d "grant_type=authorization_code" \
     -d "code=15f45e7d-70cd-4586-afa1-f6e8f3966601.457c4f86-7efa-457a-8f7b-5f780a4e07ce.0c25b80b-66b4-439d-8681-8766e4b0fafb" \
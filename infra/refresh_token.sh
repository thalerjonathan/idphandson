curl -X POST "http://localhost:8080/realms/idphandson/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=idphandson" \
        -d "client_secret=YfJSiTcLafsjrEiDFMIz8EZDwxVJiToK" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1NjE0ZTQ4Zi1hNzc3LTQyNzktYWFkOS03NWYxNDExNWU0MWMifQ.eyJleHAiOjE3NDE3NzI0MjEsImlhdCI6MTc0MTc3MDYyMSwianRpIjoiNTIyNDMxZTctOGY3Ny00M2RkLWFhODYtMDBiZGQ0YjQxYmMyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9pZHBoYW5kc29uIiwic3ViIjoiOWZhYTNiZDUtMDZiNS00MTQ3LWJjMGYtNDQ1ZDM2ZGM1NDQ2IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6ImlkcGhhbmRzb24iLCJzaWQiOiIzNTdiOTczZS1hZTY2LTQyOGItOGNjZS0wNjk5MzJhZTg2MTgiLCJzY29wZSI6Im9wZW5pZCBhY3IgcHJvZmlsZSBlbWFpbCB3ZWItb3JpZ2lucyBzZXJ2aWNlX2FjY291bnQgYmFzaWMgcm9sZXMifQ.St-lZxaM2aNP6tLSr8ENlAqHK-BPVW9Km0MlfQAI40UMc7thdYhNthFoeOSLjK1KN_V3hytJRVvAoYooTk__tg"
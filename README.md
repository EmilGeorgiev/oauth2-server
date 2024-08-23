# oauth2-server


## Generate private and public key
```azure
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

extract public key:
```azure
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

## Start the server
```azure
go run cmd/oauth2-server/main.go
```

Register an user and receive apikey and secret
```azure
curl -X POST http://localhost:8282/register -H "Content-Type: application/x-www-form-urlencoded" -d "username=EmilGeorgiev"
```

Get the token:
```azure
curl -X POST http://localhost:8282/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" -d "client_id=<client-id>" -d "client_secret=<secret>"
```


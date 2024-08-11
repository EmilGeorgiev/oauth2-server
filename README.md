# oauth2-server


## Generate private and public key
```azure
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

extract public key:
```azure
openssl rsa -pubout -in private_key.pem -out public_key.pem
```



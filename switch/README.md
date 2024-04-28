# Generate a certificate
```
openssl req -new -sha256 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes -days 365 -out cert.pem -keyout cert.pem -subj "/CN=WebRTC"
```

# Get the fingerprint of a certificate
```
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

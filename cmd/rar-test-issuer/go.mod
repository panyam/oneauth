module github.com/panyam/oneauth/cmd/rar-test-issuer

go 1.26.2

require github.com/panyam/oneauth v0.0.70

require (
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
)

replace github.com/panyam/oneauth => ../..

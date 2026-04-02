module github.com/panyam/oneauth/cmd/demo-hostapp

go 1.24.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/panyam/oneauth v0.0.39
	golang.org/x/oauth2 v0.34.0
)

require (
	github.com/alexedwards/scs/v2 v2.8.0 // indirect
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace github.com/panyam/oneauth => ../..

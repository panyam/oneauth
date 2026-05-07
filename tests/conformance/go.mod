module github.com/panyam/oneauth/tests/conformance

go 1.26.3

replace github.com/panyam/oneauth => ../..

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/panyam/oneauth v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/alexedwards/scs/v2 v2.8.0 // indirect
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611 // indirect
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
)

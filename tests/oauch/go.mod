module github.com/panyam/oneauth/tests/oauch

go 1.26.9

toolchain go1.27.4

replace github.com/panyam/oneauth => ../..

require (
	github.com/mxschmitt/playwright-go v0.6201.1
	github.com/panyam/oneauth v0.3.23
	github.com/stretchr/testify v1.12.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/alexedwards/scs/v2 v2.8.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/deckarep/golang-set/v2 v2.8.0 // indirect
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
)

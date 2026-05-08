package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level server configuration.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	KeyStore   KeyStoreConfig   `yaml:"keystore"`
	AppStore   AppStoreConfig   `yaml:"app_store"`
	UserStores UserStoresConfig `yaml:"user_stores"`
	JWT        JWTConfig        `yaml:"jwt"`
	AdminAuth  AdminAuthConfig  `yaml:"admin_auth"`
	TLS        TLSConfig        `yaml:"tls"`
}

// AppStoreConfig configures the AppRegistrationStore backing AppRegistrar
// (issue 167 — closes parent 20). Mirrors KeyStoreConfig so deployments
// see consistent shape.
type AppStoreConfig struct {
	Type string     `yaml:"type"` // memory, fs, gorm (defaults to memory)
	FS   FSConfig   `yaml:"fs"`
	GORM GORMConfig `yaml:"gorm"`
}

// UserStoresConfig configures persistent stores for users, identities, channels, tokens.
type UserStoresConfig struct {
	Type string   `yaml:"type"` // fs, gorm (defaults to fs)
	FS   FSConfig `yaml:"fs"`
	// When type=gorm, reuses keystore.gorm config
}

// JWTConfig configures JWT signing for browser sessions and API tokens.
type JWTConfig struct {
	SecretKey                 string   `yaml:"secret_key"`                  // Secret key for signing JWTs (HS256 mode only)
	Issuer                    string   `yaml:"issuer"`                      // JWT issuer claim
	AuthorizationDetailsTypes []string `yaml:"authorization_details_types"` // RFC 9396 supported types (advertised in AS metadata)

	// SigningAlg controls how access tokens are signed. Defaults to HS256
	// (uses SecretKey). Set to "RS256" / "ES256" for asymmetric signing —
	// the public half is exposed via JWKS so remote resource servers can
	// validate without a shared secret. See issue 184.
	SigningAlg string `yaml:"signing_alg"`

	// PrivateKeyPath is the path to a PEM-encoded private key (RSA / EC)
	// used for asymmetric signing. Required for RS256/ES256 in production.
	PrivateKeyPath string `yaml:"private_key_path"`

	// EphemeralSigningKey, when true with SigningAlg=RS256/ES256, generates
	// a fresh keypair on each startup. Tokens issued under one instance are
	// invalid after a restart (kid changes, JWKS rotates). This is a
	// **test / dev only** convenience — production deployments must set
	// PrivateKeyPath. The flag is explicit (rather than implicit fallback)
	// so misconfiguration fails loudly: "set private_key_path or
	// ephemeral_signing_key".
	EphemeralSigningKey bool `yaml:"ephemeral_signing_key"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
	// PublicURL is the externally-visible base URL clients use to reach
	// this server (e.g., "http://localhost:8181" or "https://auth.example").
	// Used for the OIDC `iss` claim and the RFC 8414 metadata document.
	// When empty, falls back to scheme://host:port — fine for dev where
	// host is loopback, but unreliable when host is 0.0.0.0 (bind-all),
	// behind a reverse proxy, or otherwise differs from the public URL.
	// See issue 184.
	PublicURL string `yaml:"public_url"`
}

type KeyStoreConfig struct {
	Type      string     `yaml:"type"` // memory, gorm, fs, gae
	GORM      GORMConfig `yaml:"gorm"`
	FS        FSConfig   `yaml:"fs"`
	GAE       GAEConfig  `yaml:"gae"`
	MasterKey string     `yaml:"master_key"` // 64-char hex key for AES-256-GCM encryption of HS256 secrets at rest
}

type GORMConfig struct {
	Driver string `yaml:"driver"` // postgres, sqlite, mysql
	DSN    string `yaml:"dsn"`
}

type FSConfig struct {
	Path string `yaml:"path"`
}

type GAEConfig struct {
	Project   string `yaml:"project"`
	Namespace string `yaml:"namespace"`
}

type AdminAuthConfig struct {
	Type   string        `yaml:"type"` // none, api-key, oidc
	APIKey APIKeyConfig  `yaml:"api_key"`
}

type APIKeyConfig struct {
	Key string `yaml:"key"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// envVarPattern matches ${VAR_NAME} for environment variable substitution.
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandEnvVars replaces ${VAR_NAME} patterns with environment variable values.
func expandEnvVars(data []byte) []byte {
	return envVarPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		varName := string(match[2 : len(match)-1]) // strip ${ and }

		// Support ${VAR:-default} syntax
		parts := strings.SplitN(varName, ":-", 2)
		val := os.Getenv(parts[0])
		if val == "" && len(parts) == 2 {
			val = parts[1]
		}
		return []byte(val)
	})
}

// LoadConfig reads and parses a YAML config file with env var substitution.
// If the config file doesn't exist, falls back to pure environment variable configuration.
func LoadConfig(path string) (*Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — build config entirely from env vars
			cfg = configFromEnv()
		} else {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}
	} else {
		data = expandEnvVars(data)
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
	}

	// Defaults
	if cfg.Server.Port == "" {
		cfg.Server.Port = "8080"
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.KeyStore.Type == "" {
		cfg.KeyStore.Type = "memory"
	}
	if cfg.AppStore.Type == "" {
		cfg.AppStore.Type = "memory"
	}
	if cfg.AdminAuth.Type == "" {
		cfg.AdminAuth.Type = "none"
	}
	if cfg.UserStores.Type == "" {
		cfg.UserStores.Type = "fs"
	}
	if cfg.UserStores.FS.Path == "" {
		cfg.UserStores.FS.Path = "./data/server"
	}
	if cfg.JWT.Issuer == "" {
		cfg.JWT.Issuer = "oneauth"
	}

	return &cfg, nil
}

// configFromEnv builds a Config purely from environment variables.
// Used when no config file is present (e.g., GAE deployments).
func configFromEnv() Config {
	return Config{
		Server: ServerConfig{
			Port: os.Getenv("PORT"),
			Host: os.Getenv("HOST"),
		},
		KeyStore: KeyStoreConfig{
			Type:      os.Getenv("KEYSTORE_TYPE"),
			MasterKey: os.Getenv("ONEAUTH_MASTER_KEY"),
			GORM: GORMConfig{
				Driver: os.Getenv("GORM_DRIVER"),
				DSN:    os.Getenv("DATABASE_URL"),
			},
			FS: FSConfig{
				Path: os.Getenv("KEYSTORE_PATH"),
			},
			GAE: GAEConfig{
				Project:   os.Getenv("GCP_PROJECT"),
				Namespace: os.Getenv("GAE_NAMESPACE"),
			},
		},
		AppStore: AppStoreConfig{
			Type: os.Getenv("APP_STORE_TYPE"),
			FS: FSConfig{
				Path: os.Getenv("APP_STORE_PATH"),
			},
			GORM: GORMConfig{
				Driver: os.Getenv("APP_STORE_GORM_DRIVER"),
				DSN:    os.Getenv("APP_STORE_DATABASE_URL"),
			},
		},
		AdminAuth: AdminAuthConfig{
			Type: os.Getenv("ADMIN_AUTH_TYPE"),
			APIKey: APIKeyConfig{
				Key: os.Getenv("ADMIN_API_KEY"),
			},
		},
		UserStores: UserStoresConfig{
			Type: os.Getenv("USER_STORES_TYPE"),
			FS: FSConfig{
				Path: os.Getenv("USER_STORES_PATH"),
			},
		},
		JWT: JWTConfig{
			SecretKey: os.Getenv("JWT_SECRET_KEY"),
			Issuer:    os.Getenv("JWT_ISSUER"),
		},
	}
}


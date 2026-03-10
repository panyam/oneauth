package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/datastore"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	oa "github.com/panyam/oneauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
	gaestore "github.com/panyam/oneauth/stores/gae"
	gormstore "github.com/panyam/oneauth/stores/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	configPath := flag.String("config", "oneauth-server.yaml", "Path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Build KeyStore
	keyStore, err := buildKeyStore(cfg)
	if err != nil {
		log.Fatalf("Failed to create KeyStore: %v", err)
	}

	// Build AdminAuth
	adminAuth, err := buildAdminAuth(cfg)
	if err != nil {
		log.Fatalf("Failed to create AdminAuth: %v", err)
	}

	// Build HostRegistrar
	registrar := &oa.HostRegistrar{
		KeyStore: keyStore,
		Auth:     adminAuth,
	}

	// Wire up HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.Handle("/", registrar.Handler())

	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("oneauth-server listening on %s (keystore=%s, auth=%s)", addr, cfg.KeyStore.Type, cfg.AdminAuth.Type)

	if cfg.TLS.Enabled {
		log.Fatal(http.ListenAndServeTLS(addr, cfg.TLS.Cert, cfg.TLS.Key, mux))
	} else {
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}

func buildKeyStore(cfg *Config) (oa.WritableKeyStore, error) {
	switch cfg.KeyStore.Type {
	case "memory":
		log.Println("Using in-memory KeyStore (not persistent)")
		return oa.NewInMemoryKeyStore(), nil

	case "fs":
		log.Printf("Using filesystem KeyStore at %s", cfg.KeyStore.FS.Path)
		return fsstore.NewFSKeyStore(cfg.KeyStore.FS.Path), nil

	case "gorm":
		db, err := openGORM(cfg.KeyStore.GORM)
		if err != nil {
			return nil, err
		}
		if err := gormstore.AutoMigrate(db); err != nil {
			return nil, err
		}
		log.Printf("Using GORM KeyStore (driver=%s)", cfg.KeyStore.GORM.Driver)
		return gormstore.NewKeyStore(db), nil

	case "gae":
		ctx := context.Background()
		client, err := datastore.NewClient(ctx, cfg.KeyStore.GAE.Project)
		if err != nil {
			return nil, err
		}
		log.Printf("Using GAE Datastore KeyStore (project=%s, namespace=%s)", cfg.KeyStore.GAE.Project, cfg.KeyStore.GAE.Namespace)
		return gaestore.NewKeyStore(client, cfg.KeyStore.GAE.Namespace), nil

	default:
		log.Fatalf("Unknown keystore type: %s", cfg.KeyStore.Type)
		return nil, nil
	}
}

func openGORM(cfg GORMConfig) (*gorm.DB, error) {
	switch cfg.Driver {
	case "postgres":
		return gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	default:
		log.Fatalf("Unsupported GORM driver: %s (only postgres is supported in the reference server)", cfg.Driver)
		return nil, nil
	}
}

func buildAdminAuth(cfg *Config) (oa.AdminAuth, error) {
	switch cfg.AdminAuth.Type {
	case "none":
		log.Println("WARNING: Admin auth disabled (type=none). Do not use in production!")
		return oa.NewNoAuth(), nil

	case "api-key":
		key := cfg.AdminAuth.APIKey.Key
		if key == "" {
			// Try fetching from Secret Manager
			var err error
			key, err = fetchSecretManagerKey(cfg)
			if err != nil {
				log.Fatalf("admin_auth.api_key.key is required. Set ADMIN_API_KEY env var, create a Secret Manager secret, or generate one:\n  export ADMIN_API_KEY=\"$(openssl rand -hex 32)\"\nSecret Manager error: %v", err)
			}
			log.Println("Admin API key loaded from Secret Manager")
		}
		return oa.NewAPIKeyAuth(key), nil

	default:
		log.Fatalf("Unknown admin_auth type: %s", cfg.AdminAuth.Type)
		return nil, nil
	}
}

// fetchSecretManagerKey attempts to load the admin API key from Google Secret Manager.
// It uses ADMIN_API_KEY_SECRET env var as the full resource name, or defaults to
// projects/<GCP_PROJECT>/secrets/oneauth-admin-key/versions/latest.
func fetchSecretManagerKey(cfg *Config) (string, error) {
	secretName := os.Getenv("ADMIN_API_KEY_SECRET")
	if secretName == "" {
		project := cfg.KeyStore.GAE.Project
		if project == "" {
			return "", fmt.Errorf("no GCP_PROJECT configured for Secret Manager lookup")
		}
		secretName = fmt.Sprintf("projects/%s/secrets/oneauth-admin-key/versions/latest", project)
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	result, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", secretName, err)
	}
	return string(result.Payload.Data), nil
}

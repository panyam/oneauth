package main

import (
	"flag"
	"log"
	"net/http"

	oa "github.com/panyam/oneauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
	gormstore "github.com/panyam/oneauth/stores/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
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
	mux.Handle("/", registrar.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

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

	default:
		log.Fatalf("Unknown keystore type: %s", cfg.KeyStore.Type)
		return nil, nil
	}
}

func openGORM(cfg GORMConfig) (*gorm.DB, error) {
	switch cfg.Driver {
	case "postgres":
		return gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	case "sqlite":
		return gorm.Open(sqlite.Open(cfg.DSN), &gorm.Config{})
	default:
		log.Fatalf("Unsupported GORM driver: %s", cfg.Driver)
		return nil, nil
	}
}

func buildAdminAuth(cfg *Config) (oa.AdminAuth, error) {
	switch cfg.AdminAuth.Type {
	case "none":
		log.Println("WARNING: Admin auth disabled (type=none). Do not use in production!")
		return oa.NewNoAuth(), nil

	case "api-key":
		if cfg.AdminAuth.APIKey.Key == "" {
			log.Fatal("admin_auth.api_key.key is required. Set ADMIN_API_KEY env var or generate one:\n  export ADMIN_API_KEY=\"$(openssl rand -hex 32)\"")
		}
		return oa.NewAPIKeyAuth(cfg.AdminAuth.APIKey.Key), nil

	default:
		log.Fatalf("Unknown admin_auth type: %s", cfg.AdminAuth.Type)
		return nil, nil
	}
}

package gae

import (
	"context"

	"cloud.google.com/go/datastore"
	"github.com/panyam/goapplib/dsmigrate"
)

// StoreOption configures a UserStore, IdentityStore or ChannelStore.
type StoreOption func(*storeConfig)

type storeConfig struct {
	reg             *dsmigrate.Registry
	numericUserKeys bool
}

func applyOptions(opts []StoreOption) storeConfig {
	var cfg storeConfig
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// WithNumericUserKeys lets a UserStore find users that live at Datastore's numeric keys
// (datastore.IDKey), as an app that created users with incomplete keys left them. A user whose
// ID is all digits is looked up at its name key first, then at the numeric key with that value,
// and SaveUser updates whichever one it found. New users still get name keys. It applies to
// NewUserStore only.
func WithNumericUserKeys() StoreOption {
	return func(cfg *storeConfig) { cfg.numericUserKeys = true }
}

// WithSchemaRegistry makes the store upgrade old entities as it reads them and stamp the current
// schema version on what it writes, using reg's Schema for each kind (KindUser, KindIdentity,
// KindChannel). An app registers upgraders for entities an older build or another system wrote,
// and runs dsmigrate.Backfill for the ones nobody reads, so queries find them too. See
// https://panyam.github.io/goapplib/reference/dsmigrate/ for the design.
//
// Without it, a store reads and writes exactly as before, through the client.
func WithSchemaRegistry(reg *dsmigrate.Registry) StoreOption {
	return func(cfg *storeConfig) { cfg.reg = reg }
}

// schemaIO routes a store's reads and writes through dsmigrate when a registry is set, and
// straight to the client otherwise.
type schemaIO struct {
	client *datastore.Client
	reg    *dsmigrate.Registry
}

func newSchemaIO(client *datastore.Client, cfg storeConfig) schemaIO {
	return schemaIO{client: client, reg: cfg.reg}
}

func (io schemaIO) get(ctx context.Context, key *datastore.Key, dst any) error {
	if io.reg == nil {
		return io.client.Get(ctx, key, dst)
	}
	return dsmigrate.Get(ctx, io.client, key, dst, io.reg)
}

func (io schemaIO) put(ctx context.Context, key *datastore.Key, src any) (*datastore.Key, error) {
	if io.reg == nil {
		return io.client.Put(ctx, key, src)
	}
	return dsmigrate.Put(ctx, io.client, key, src, io.reg)
}

// next reads the iterator's next entity into dst, upgrading it and writing the upgrade back as
// dsmigrate.Get does.
func (io schemaIO) next(ctx context.Context, it *datastore.Iterator, dst any) (*datastore.Key, error) {
	if io.reg == nil {
		return it.Next(dst)
	}
	var props datastore.PropertyList
	key, err := it.Next(&props)
	if err != nil {
		return key, err
	}
	upgraded, changed, err := io.reg.Load(key.Kind, props, dst)
	if err != nil {
		return key, err
	}
	if changed {
		if _, err := dsmigrate.WriteBack(ctx, io.client, key, props, upgraded); err != nil && io.reg.OnWriteBackError != nil {
			io.reg.OnWriteBackError(key, err)
		}
	}
	return key, nil
}

// txGet reads inside a transaction, upgrading without writing: the transaction's own Put stamps
// the current version, and a transaction that only reads leaves the entity for the next read.
func (io schemaIO) txGet(tx *datastore.Transaction, key *datastore.Key, dst any) error {
	if io.reg == nil {
		return tx.Get(key, dst)
	}
	var props datastore.PropertyList
	if err := tx.Get(key, &props); err != nil {
		return err
	}
	_, _, err := io.reg.Load(key.Kind, props, dst)
	return err
}

func (io schemaIO) txPut(tx *datastore.Transaction, key *datastore.Key, src any) (*datastore.PendingKey, error) {
	if io.reg == nil {
		return tx.Put(key, src)
	}
	props, err := io.reg.Save(key.Kind, src)
	if err != nil {
		return nil, err
	}
	return tx.Put(key, &props)
}

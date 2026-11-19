package outbound

import (
	"context"
	"errors"
	"sync"
	"time"
)

// UserTokenRecord is one person's token for one provider, as a store keeps
// it. Sealed is opaque ciphertext from UserTokens; a store never sees the
// token itself.
type UserTokenRecord struct {
	// Provider names the service, such as "github". Together with Subject
	// it is the record's key.
	Provider string

	// Subject names the person in the app, normally the app's user ID.
	Subject string

	// Sealed is the token, sealed by UserTokens under AAD naming Provider
	// and Subject.
	Sealed []byte

	// Version starts at 1 and goes up by one on every write. Stores set
	// it; callers pass the version they read as ExpectedVersion.
	Version int64

	// UpdatedAt is when the store last wrote the record.
	UpdatedAt time.Time
}

// ErrUserTokenNotFound is returned by GetUserToken when there is no record
// for the key. To a caller it means the person hasn't connected.
var ErrUserTokenNotFound = errors.New("outbound: user token not found")

// ErrVersionConflict is returned by PutUserToken when the stored version
// isn't ExpectedVersion: another writer got there first. The caller
// re-reads rather than retrying the write blind.
var ErrVersionConflict = errors.New("outbound: user token version conflict")

// GetUserTokenRequest is the input to UserTokenStore.GetUserToken.
type GetUserTokenRequest struct {
	Provider string
	Subject  string
}

// GetUserTokenResponse carries the stored record.
type GetUserTokenResponse struct {
	Record *UserTokenRecord
}

// PutUserTokenRequest is the input to UserTokenStore.PutUserToken.
type PutUserTokenRequest struct {
	Provider string
	Subject  string
	Sealed   []byte

	// ExpectedVersion is the version the caller read. Zero means "create":
	// the write fails with ErrVersionConflict if a record exists.
	ExpectedVersion int64
}

// PutUserTokenResponse carries the version the store wrote.
type PutUserTokenResponse struct {
	Version int64
}

// DeleteUserTokenRequest is the input to UserTokenStore.DeleteUserToken.
type DeleteUserTokenRequest struct {
	Provider string
	Subject  string
}

// DeleteUserTokenResponse is the output of UserTokenStore.DeleteUserToken.
type DeleteUserTokenResponse struct{}

// UserTokenStore keeps sealed user tokens with compare-and-swap writes.
//
// The compare-and-swap is what keeps refresh safe across replicas. GitHub
// and most providers rotate the refresh token on every use, and the old
// one stops working. If two replicas refresh the same token and both
// write, the store can end up with the loser's refresh token, which the
// provider has already refused. With CAS the loser's write fails and it
// reads the winner's token instead.
//
// usertokentest.RunAll checks an implementation against this contract.
type UserTokenStore interface {
	// GetUserToken returns the record, or ErrUserTokenNotFound.
	GetUserToken(ctx context.Context, req *GetUserTokenRequest) (*GetUserTokenResponse, error)

	// PutUserToken writes the record if the stored version equals
	// ExpectedVersion (zero meaning no record exists), and answers
	// ErrVersionConflict otherwise. The check and the write are atomic
	// per record.
	PutUserToken(ctx context.Context, req *PutUserTokenRequest) (*PutUserTokenResponse, error)

	// DeleteUserToken removes the record. Deleting a missing record is
	// not an error, so disconnecting twice is safe.
	DeleteUserToken(ctx context.Context, req *DeleteUserTokenRequest) (*DeleteUserTokenResponse, error)
}

// MemoryUserTokenStore is an in-process UserTokenStore for tests and
// single-process tools. It loses everything on restart.
type MemoryUserTokenStore struct {
	mu      sync.Mutex
	records map[[2]string]UserTokenRecord
}

// NewMemoryUserTokenStore returns an empty store.
func NewMemoryUserTokenStore() *MemoryUserTokenStore {
	return &MemoryUserTokenStore{records: map[[2]string]UserTokenRecord{}}
}

// GetUserToken returns a copy of the record, or ErrUserTokenNotFound.
func (m *MemoryUserTokenStore) GetUserToken(_ context.Context, req *GetUserTokenRequest) (*GetUserTokenResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[[2]string{req.Provider, req.Subject}]
	if !ok {
		return nil, ErrUserTokenNotFound
	}
	rec.Sealed = append([]byte(nil), rec.Sealed...)
	return &GetUserTokenResponse{Record: &rec}, nil
}

// PutUserToken writes under the store's lock, so the version check and
// the write are atomic.
func (m *MemoryUserTokenStore) PutUserToken(_ context.Context, req *PutUserTokenRequest) (*PutUserTokenResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{req.Provider, req.Subject}
	cur, ok := m.records[key]
	if (!ok && req.ExpectedVersion != 0) || (ok && cur.Version != req.ExpectedVersion) {
		return nil, ErrVersionConflict
	}
	next := UserTokenRecord{
		Provider:  req.Provider,
		Subject:   req.Subject,
		Sealed:    append([]byte(nil), req.Sealed...),
		Version:   req.ExpectedVersion + 1,
		UpdatedAt: time.Now(),
	}
	m.records[key] = next
	return &PutUserTokenResponse{Version: next.Version}, nil
}

// DeleteUserToken removes the record if present.
func (m *MemoryUserTokenStore) DeleteUserToken(_ context.Context, req *DeleteUserTokenRequest) (*DeleteUserTokenResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, [2]string{req.Provider, req.Subject})
	return &DeleteUserTokenResponse{}, nil
}

var _ UserTokenStore = (*MemoryUserTokenStore)(nil)

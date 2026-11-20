package apiauth

import (
	"context"
	"errors"
	"testing"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
)

type failingAppStore struct{ core.AppRegistrationStore }

func (failingAppStore) GetApp(context.Context, *core.GetAppRequest) (*core.GetAppResponse, error) {
	return nil, errors.New("datastore down")
}

// An unregistered client sees the user's ID, as before pairwise existed.
// A store that can't answer is an error, not a guess at "public", which
// would hand a pairwise client the real ID.
func TestClientSubjects_UnregisteredAndStoreErrors(t *testing.T) {
	salt := []byte("pairwise-salt-for-tests-32-bytes!")
	got, err := clientSubjects(core.NewInMemoryAppStore(), salt)(context.Background(), "nobody", "alice")
	assert.NoError(t, err)
	assert.Equal(t, "alice", got)

	_, err = clientSubjects(failingAppStore{}, salt)(context.Background(), "client", "alice")
	assert.ErrorContains(t, err, "datastore down")
}

package core

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrConsentNotFound is returned by ConsentStore.GetConsent when the user
// has no recorded consent for the client.
var ErrConsentNotFound = errors.New("consent not found")

// ConsentGrant records that a user approved a client for a set of scopes.
// The authorization endpoint reads it to skip the consent screen when an
// earlier approval already covers a request, which is what lets it answer
// an OIDC `prompt=none` request without showing any page (OIDC Core
// §3.1.2.1).
//
// One grant exists per (Subject, ClientID). A new approval replaces it,
// and the caller passes the union of the old and new scopes, so approving
// a narrower request doesn't take back what the user approved before.
//
// ExpiresAt bounds how long an approval counts. A zero ExpiresAt never
// expires.
type ConsentGrant struct {
	Subject   string    `json:"subject"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// IsExpired reports whether the approval is past its lifetime.
func (g *ConsentGrant) IsExpired(now time.Time) bool {
	return !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt)
}

// Covers reports whether the grant is unexpired and includes every scope
// in scopes. A nil grant covers nothing.
func (g *ConsentGrant) Covers(scopes []string, now time.Time) bool {
	if g == nil || g.IsExpired(now) {
		return false
	}
	for _, s := range scopes {
		if !slices.Contains(g.Scopes, s) {
			return false
		}
	}
	return true
}

// SaveConsentRequest carries the grant to store. It replaces any grant
// already stored for the same Subject and ClientID.
type SaveConsentRequest struct {
	Grant *ConsentGrant
}

// SaveConsentResponse echoes the stored grant.
type SaveConsentResponse struct {
	Grant *ConsentGrant
}

// GetConsentRequest looks up the grant a user gave a client.
type GetConsentRequest struct {
	Subject  string
	ClientID string
}

// GetConsentResponse wraps the stored grant. An expired grant is still
// returned; the caller checks it with Covers.
type GetConsentResponse struct {
	Grant *ConsentGrant
}

// RevokeConsentRequest removes the grant a user gave a client.
type RevokeConsentRequest struct {
	Subject  string
	ClientID string
}

// RevokeConsentResponse is empty.
type RevokeConsentResponse struct{}

// ConsentStore keeps the consent users have given clients, so the
// authorization endpoint can skip the consent screen for a request an
// earlier approval covers.
//
// Implementations must:
//   - key grants by (Subject, ClientID), with SaveConsent replacing a
//     stored grant rather than adding a second one, and refusing a nil
//     grant or one with an empty Subject or ClientID;
//   - return ErrConsentNotFound from GetConsent when nothing is stored,
//     and return an expired grant rather than hiding it;
//   - make RevokeConsent idempotent, returning nil when nothing is stored;
//   - store copies, so a caller changing a grant's Scopes after
//     SaveConsent or GetConsent doesn't change the stored grant.
//
// A grant names a user and a client, and holds no secret, so it is stored
// as is. The shared contract suite is consenttest.RunAll.
type ConsentStore interface {
	SaveConsent(ctx context.Context, req *SaveConsentRequest) (*SaveConsentResponse, error)
	GetConsent(ctx context.Context, req *GetConsentRequest) (*GetConsentResponse, error)
	RevokeConsent(ctx context.Context, req *RevokeConsentRequest) (*RevokeConsentResponse, error)
}

// ListConsentsRequest names the user whose grants to list.
type ListConsentsRequest struct {
	Subject string
}

// ListConsentsResponse holds the user's unexpired grants, sorted by
// ClientID so a page listing them doesn't reorder between loads. An
// empty list is not an error.
type ListConsentsResponse struct {
	Grants []*ConsentGrant
}

// ConsentLister is an optional ConsentStore capability. A store that
// implements it lets a user see every client they approved and withdraw
// one, as the reference server's connected-apps page does. It is a
// separate interface so a custom ConsentStore written before it existed
// still compiles; callers check for it with a type assertion.
//
// Implementations must:
//   - return only grants whose Subject is req.Subject, so one user never
//     sees another's approvals;
//   - leave out expired grants, since they no longer let a client skip
//     the consent screen and revoking them changes nothing;
//   - return an empty list for an empty Subject rather than every grant;
//   - return copies, as GetConsent does.
//
// The shared contract suite is consenttest.RunLister.
type ConsentLister interface {
	ListConsents(ctx context.Context, req *ListConsentsRequest) (*ListConsentsResponse, error)
}

// SortConsentGrants orders grants by ClientID, the order ListConsents
// promises. Backends call it on what they collected.
func SortConsentGrants(grants []*ConsentGrant) {
	slices.SortFunc(grants, func(a, b *ConsentGrant) int { return strings.Compare(a.ClientID, b.ClientID) })
}

// InMemoryConsentStore is a ConsentStore for tests and single-process
// deployments. Grants are lost on restart, so users see the consent screen
// again.
type InMemoryConsentStore struct {
	mu     sync.Mutex
	grants map[[2]string]ConsentGrant
}

// NewInMemoryConsentStore returns an empty store.
func NewInMemoryConsentStore() *InMemoryConsentStore {
	return &InMemoryConsentStore{grants: map[[2]string]ConsentGrant{}}
}

// SaveConsent stores a copy of req.Grant, replacing any grant for the same
// user and client.
func (s *InMemoryConsentStore) SaveConsent(ctx context.Context, req *SaveConsentRequest) (*SaveConsentResponse, error) {
	if req == nil || req.Grant == nil || req.Grant.Subject == "" || req.Grant.ClientID == "" {
		return nil, errors.New("consent: a grant needs a subject and a client_id")
	}
	g := copyConsentGrant(req.Grant)
	s.mu.Lock()
	s.grants[[2]string{g.Subject, g.ClientID}] = *g
	s.mu.Unlock()
	return &SaveConsentResponse{Grant: copyConsentGrant(g)}, nil
}

// GetConsent returns a copy of the stored grant, or ErrConsentNotFound.
func (s *InMemoryConsentStore) GetConsent(ctx context.Context, req *GetConsentRequest) (*GetConsentResponse, error) {
	s.mu.Lock()
	g, ok := s.grants[[2]string{req.Subject, req.ClientID}]
	s.mu.Unlock()
	if !ok {
		return nil, ErrConsentNotFound
	}
	return &GetConsentResponse{Grant: copyConsentGrant(&g)}, nil
}

// RevokeConsent removes the grant, if any.
func (s *InMemoryConsentStore) RevokeConsent(ctx context.Context, req *RevokeConsentRequest) (*RevokeConsentResponse, error) {
	s.mu.Lock()
	delete(s.grants, [2]string{req.Subject, req.ClientID})
	s.mu.Unlock()
	return &RevokeConsentResponse{}, nil
}

// ListConsents returns copies of the subject's unexpired grants, sorted
// by ClientID.
func (s *InMemoryConsentStore) ListConsents(ctx context.Context, req *ListConsentsRequest) (*ListConsentsResponse, error) {
	out := []*ConsentGrant{}
	if req == nil || req.Subject == "" {
		return &ListConsentsResponse{Grants: out}, nil
	}
	now := time.Now()
	s.mu.Lock()
	for k, g := range s.grants {
		if k[0] == req.Subject && !g.IsExpired(now) {
			out = append(out, copyConsentGrant(&g))
		}
	}
	s.mu.Unlock()
	SortConsentGrants(out)
	return &ListConsentsResponse{Grants: out}, nil
}

var (
	_ ConsentStore  = (*InMemoryConsentStore)(nil)
	_ ConsentLister = (*InMemoryConsentStore)(nil)
)

func copyConsentGrant(g *ConsentGrant) *ConsentGrant {
	c := *g
	c.Scopes = slices.Clone(g.Scopes)
	return &c
}

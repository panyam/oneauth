package apiauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/panyam/oneauth/core"
)

// SubjectTypePairwise is the OIDC Core §8 subject_type that gives a client
// a sub derived from its sector rather than the user's own ID.
const SubjectTypePairwise = "pairwise"

// MinPairwiseSaltLen is the shortest OIDCConfig.PairwiseSalt accepted. The
// salt is what stops anyone who knows a user's ID from computing their
// pairwise subs, so it gets the length of an HMAC key.
const MinPairwiseSaltLen = 32

// ErrPairwiseNotConfigured is a pairwise client on a server with no
// pairwise salt, or with no sector recorded for the client. The ID token
// and userinfo fail rather than hand out the user's own ID.
var ErrPairwiseNotConfigured = errors.New("apiauth: pairwise client, but no pairwise salt or sector")

// PairwiseSubject derives a pairwise sub (OIDC Core §8.1): HMAC-SHA256
// keyed with salt over the sector, a zero byte, and the user's subject,
// base64url without padding. It is stable for one user and sector, differs
// across sectors, and can't be reversed or computed without salt. The zero
// byte keeps ("ab", "c") and ("a", "bc") apart.
func PairwiseSubject(salt []byte, sector, subject string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(sector))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ClientSubjectFunc maps a user's subject to the sub a client sees.
type ClientSubjectFunc func(ctx context.Context, clientID, subject string) (string, error)

// clientSubjects returns the ClientSubjectFunc for apps and salt. A client
// that isn't registered, or isn't pairwise, sees subject unchanged. A
// pairwise client sees PairwiseSubject of its SectorIdentifier, or gets
// ErrPairwiseNotConfigured. A store error other than not-found is
// returned, since guessing "public" would leak the user's ID.
func clientSubjects(apps core.AppRegistrationStore, salt []byte) ClientSubjectFunc {
	return func(ctx context.Context, clientID, subject string) (string, error) {
		if apps == nil || clientID == "" {
			return subject, nil
		}
		resp, err := apps.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
		if errors.Is(err, core.ErrAppNotFound) {
			return subject, nil
		}
		if err != nil {
			return "", fmt.Errorf("look up client %q: %w", clientID, err)
		}
		if resp == nil || resp.App == nil || resp.App.SubjectType != SubjectTypePairwise {
			return subject, nil
		}
		if len(salt) == 0 || resp.App.SectorIdentifier == "" {
			return "", ErrPairwiseNotConfigured
		}
		return PairwiseSubject(salt, resp.App.SectorIdentifier, subject), nil
	}
}

// SubjectForClient returns the sub clientID sees for the user subject:
// their own ID, or a pairwise value when the client registered
// subject_type pairwise (issue 507). ID tokens, userinfo and logout tokens
// use it. Access tokens and introspection keep the user's own ID, which
// resource servers key on.
func (oa *OneAuth) SubjectForClient(ctx context.Context, clientID, subject string) (string, error) {
	var salt []byte
	if oa.OIDC != nil {
		salt = oa.OIDC.PairwiseSalt
	}
	return clientSubjects(oa.AppStore, salt)(ctx, clientID, subject)
}

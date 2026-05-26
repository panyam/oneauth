package core

import "context"

type subjectParamNameKey string

// DefaultSubjectParamName is the default context / session key for the
// authenticated principal — RFC 7519 `sub`. Holds a user ID for
// human-driven flows and a client_id for client_credentials.
const DefaultSubjectParamName = "loggedInSubject"

// GetSubjectFromContext retrieves the authenticated subject from the
// request context. Uses the default key DefaultSubjectParamName.
func GetSubjectFromContext(ctx context.Context) string {
	if v := ctx.Value(subjectParamNameKey(DefaultSubjectParamName)); v != nil {
		if subject, ok := v.(string); ok {
			return subject
		}
	}
	return ""
}

// SetSubjectInContext sets the authenticated subject in the request
// context.
func SetSubjectInContext(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectParamNameKey(DefaultSubjectParamName), subject)
}

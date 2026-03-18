package core

import "context"

type userParamNameKey string

// DefaultUserParamName is the default context key for user ID
const DefaultUserParamName = "loggedInUserId"

// GetUserIDFromContext retrieves the user ID from the request context
// Uses the default key "loggedInUserId"
func GetUserIDFromContext(ctx context.Context) string {
	if v := ctx.Value(userParamNameKey(DefaultUserParamName)); v != nil {
		if userID, ok := v.(string); ok {
			return userID
		}
	}
	return ""
}

// SetUserIDInContext sets the user ID in the request context
func SetUserIDInContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userParamNameKey(DefaultUserParamName), userID)
}

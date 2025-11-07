// Package oneauth provides a unified authentication framework for Go applications.
//
// OneAuth separates authentication concerns into three layers: users, identities,
// and channels. This design enables multiple authentication methods per user while
// maintaining a single account.
//
// # Architecture
//
// User: A unique account in your system. Users are identified by a user ID and
// contain profile information.
//
// Identity: A contact method (email address or phone number) that belongs to a
// user. Identities have verification status and can be shared across multiple
// authentication channels.
//
// Channel: An authentication mechanism (local password, Google OAuth, GitHub OAuth)
// connected to an identity. Channels store provider-specific credentials and profile data.
//
// # Basic Usage
//
// Set up stores for users, identities, channels, and tokens:
//
//	import (
//	    "github.com/panyam/oneauth"
//	    "github.com/panyam/oneauth/stores"
//	)
//
//	storagePath := "/path/to/storage"
//	userStore := stores.NewFSUserStore(storagePath)
//	identityStore := stores.NewFSIdentityStore(storagePath)
//	channelStore := stores.NewFSChannelStore(storagePath)
//	tokenStore := stores.NewFSTokenStore(storagePath)
//
// Create authentication callbacks:
//
//	createUser := oneauth.NewCreateUserFunc(userStore, identityStore, channelStore)
//	validateCreds := oneauth.NewCredentialsValidator(identityStore, channelStore, userStore)
//	verifyEmail := oneauth.NewVerifyEmailFunc(identityStore, tokenStore)
//	updatePassword := oneauth.NewUpdatePasswordFunc(identityStore, channelStore)
//
// Configure local authentication:
//
//	localAuth := &oneauth.LocalAuth{
//	    CreateUser:          createUser,
//	    ValidateCredentials: validateCreds,
//	    EmailSender:         &oneauth.ConsoleEmailSender{},
//	    TokenStore:          tokenStore,
//	    BaseURL:             "https://yourapp.com",
//	    VerifyEmail:         verifyEmail,
//	    UpdatePassword:      updatePassword,
//	    HandleUser: func(authtype, provider string, token *oauth2.Token,
//	                    userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
//	        // Create session and respond
//	    },
//	}
//
// Set up HTTP handlers:
//
//	mux := http.NewServeMux()
//	mux.Handle("/auth/login", localAuth)
//	mux.Handle("/auth/signup", http.HandlerFunc(localAuth.HandleSignup))
//	mux.Handle("/auth/verify-email", http.HandlerFunc(localAuth.HandleVerifyEmail))
//	mux.Handle("/auth/forgot-password", http.HandlerFunc(localAuth.HandleForgotPassword))
//	mux.Handle("/auth/reset-password", http.HandlerFunc(localAuth.HandleResetPassword))
//
// # Store Implementations
//
// OneAuth provides file-based store implementations in the stores package,
// suitable for development and small applications. For production use with
// larger user bases, implement the store interfaces backed by your database.
//
// # Security
//
// Passwords are hashed using bcrypt with default cost. Verification and password
// reset tokens are cryptographically secure 32-byte values, hex-encoded to 64
// characters. Tokens expire automatically (24 hours for verification, 1 hour
// for password reset) and are deleted after single use.
//
// # Testing
//
// Authentication handlers can be tested without a running HTTP server using
// httptest.NewRequest and httptest.ResponseRecorder. Tests use temporary storage
// directories for complete isolation.
package oneauth

# OneAuth User Guide

## Introduction

This guide explains how to use applications that implement OneAuth for authentication. OneAuth provides a secure way to create accounts and sign in using passwords or social login providers.

## Creating an Account

### With Email and Password

1. Navigate to the signup page
2. Enter your desired username (3-20 characters, letters, numbers, underscores, and hyphens)
3. Enter your email address
4. Create a password (minimum 8 characters)
5. Click "Sign Up"

Some applications may send a verification email. Check your inbox and click the verification link to activate your account.

### With Social Login

If enabled by the application:

1. Navigate to the login page
2. Click "Continue with Google" or "Continue with GitHub"
3. Authorize the application in the provider's window
4. You'll be redirected back and logged in automatically

Your email from the social provider becomes your identity in the application.

## Signing In

### With Password

1. Navigate to the login page
2. Enter your email address or username
3. Enter your password
4. Click "Sign In"

### With Social Login

1. Navigate to the login page
2. Click your preferred social login button
3. Authorize if prompted
4. You'll be signed in automatically

## Multiple Authentication Methods

OneAuth allows you to use multiple ways to sign into the same account:

- Sign up with email and password
- Later, sign in with Google using the same email
- Both methods access the same account and data

This provides flexibility while keeping your account unified.

### Linking Additional Login Methods

If you signed up with one method, you can add others:

#### Adding Password to Social Login Account

If you signed up with Google or GitHub and want to add password login:

1. Log in with your social account
2. Navigate to account settings or profile
3. Look for "Add Password" or "Link Password"
4. Enter your desired password (optionally a username)
5. Click "Save" or "Link"

Now you can log in with either Google or email/password.

#### Adding Social Login to Password Account

If you signed up with email/password and want to add Google login:

1. Log in with your password
2. Navigate to account settings
3. Look for "Link Google Account" or similar
4. Click the link button
5. Authorize the application in Google's window
6. You'll be redirected back and the accounts are linked

Now you can log in with either method.

### Viewing Linked Accounts

In account settings, you can typically see which login methods are linked:

- **Email/Password**: Shows if you have a password set
- **Google**: Shows if Google is linked
- **GitHub**: Shows if GitHub is linked

### Unlinking Accounts

Some applications allow you to unlink login methods:

1. Navigate to account settings
2. Find the linked account section
3. Click "Unlink" next to the method you want to remove

**Note**: You cannot unlink your last login method. At least one must remain.

## Email Verification

Some applications require email verification for security:

1. After signing up, check your email inbox
2. Open the verification email
3. Click the verification link
4. Your email is now verified

Verification links typically expire after 24 hours. If your link expires, request a new one from the application.

## Password Requirements

Passwords must meet these minimum requirements:

- At least 8 characters long
- No maximum length limit

Some applications may enforce stronger requirements such as:

- Uppercase and lowercase letters
- Numbers
- Special characters

The signup form will indicate specific requirements if they apply.

## Forgot Password

If you forget your password:

1. Click "Forgot password?" on the login page
2. Enter your email address
3. Click "Send Reset Link"
4. Check your email for the password reset link
5. Click the link (valid for 1 hour)
6. Enter your new password
7. Click "Reset Password"

For security, you'll always see a success message even if the email address isn't registered in the system.

## Changing Your Password

If you're logged in and want to change your password:

1. Navigate to account settings
2. Look for "Change Password" or similar option
3. Enter your current password
4. Enter your new password
5. Confirm your new password
6. Click "Update Password"

Note: The exact steps depend on how the application implements its settings interface.

## Account Security

### Best Practices

1. **Use a strong, unique password**: Don't reuse passwords across sites
2. **Enable email verification**: If offered, verify your email for account recovery
3. **Remember where you signed up**: Note whether you used password or social login
4. **Review account activity**: Check for suspicious login attempts if the application provides this feature
5. **Sign out on shared devices**: Always sign out when using public computers

### Password Managers

Password managers are recommended for creating and storing strong passwords. They integrate seamlessly with OneAuth-enabled applications.

### Social Login Security

When using social login:

- You're trusting the social provider (Google, GitHub, etc.) for authentication
- Revoke application access in your social provider's settings if you no longer use an application
- Your email address from the social provider is used as your identity

## Privacy

### Information Collected

Applications using OneAuth typically store:

- Your email address or phone number
- Your username
- Hashed password (if using password authentication) - bcrypt one-way hash that cannot be reversed
- Profile information from social providers (if using social login)

### Information Not Collected

OneAuth does not:

- Store passwords in plain text
- Share your credentials between applications
- Track your activity across different applications

Each application using OneAuth maintains its own user database.

## Common Issues

### "Invalid credentials" error

- Verify you're entering the correct email and password
- Check if caps lock is on
- Ensure you're using the correct authentication method (password vs. social login)
- Try resetting your password if needed

### Email verification link not working

- Check if the link has expired (usually 24 hours)
- Ensure you clicked the complete link (some email clients break long URLs)
- Request a new verification link from the application

### Not receiving emails

- Check your spam/junk folder
- Verify you entered the correct email address
- Wait a few minutes, as email delivery can be delayed
- Contact the application's support if emails continue not to arrive

### Can't remember which sign-in method was used

- Try password login first
- If that fails, try social login options
- Use the "Forgot password" feature to confirm if a password account exists

### Account lockout

If an application locks accounts after failed login attempts:

- Wait for the lockout period to expire (varies by application)
- Use the "Forgot password" feature to reset and regain access
- Contact application support if you believe your account was compromised

## Multiple Accounts

OneAuth links authentication methods by email address:

- **Same email, different methods = Same account**: Signing up with password and later using Google with the same email accesses one account
- **Different emails = Different accounts**: Using different email addresses creates separate accounts, even with the same provider

## Session Management

### Session Duration

Applications control how long you stay signed in. Common approaches:

- Active sessions expire after inactivity (15-30 minutes typical)
- Sessions persist until you sign out
- "Remember me" option for extended sessions

### Signing Out

Always sign out when finished, especially on shared devices:

1. Look for "Sign Out" or "Log Out" button
2. Click it to end your session
3. You'll be redirected to the login page

### Multiple Devices

You can be signed in on multiple devices simultaneously. Signing out on one device doesn't affect other sessions unless the application implements global logout.

## Developer Support

If you experience issues with OneAuth in an application:

1. Check the application's support documentation
2. Contact the application's support team
3. Report bugs to the application developers

OneAuth is a library integrated by application developers. For issues with specific applications, contact those applications directly.

## Technical Users

### API Access

Applications using OneAuth may provide API access for programmatic use. This includes:

**API Login**
```bash
curl -X POST https://app.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"your@email.com","password":"yourpassword"}'
```

This returns an access token and refresh token for subsequent API calls.

**Using Access Tokens**
```bash
curl https://app.example.com/api/resource \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Access tokens expire quickly (typically 15 minutes). Use the refresh token to get a new access token.

**Refreshing Tokens**
```bash
curl -X POST https://app.example.com/api/login \
  -d '{"grant_type":"refresh_token","refresh_token":"YOUR_REFRESH_TOKEN"}'
```

**API Keys**

For long-lived access (CI/CD, scripts, automation), create an API key:

1. Log in to the application
2. Navigate to API settings or developer settings
3. Create a new API key with appropriate scopes
4. Store the key securely - it's only shown once

Use API keys like access tokens:
```bash
curl https://app.example.com/api/resource \
  -H "Authorization: Bearer oa_YOUR_API_KEY"
```

**Scopes**

API tokens have scopes that limit what they can access:
- `read` - Read data
- `write` - Modify data
- `profile` - Access profile information

When creating API keys, request only the scopes you need.

### Browser Requirements

OneAuth works with modern browsers that support:

- JavaScript enabled
- Cookies enabled
- HTTPS connections
- Form submissions

For optimal security, keep your browser updated to the latest version.

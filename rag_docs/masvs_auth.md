# MASVS-AUTH: Authentication and Authorization

## Core Concepts
Authentication and session management are critical for mobile apps. Weaknesses in this area allow attackers to impersonate users, hijack sessions, or bypass access controls.

## Common Weaknesses
- **Weak Login Flows**: Lack of rate limiting or account lockout mechanisms.
- **Missing MFA**: Absence of Multi-Factor Authentication for sensitive operations.
- **Insecure Session Handling**: Tokens stored in plain SharedPreferences instead of Keystore.
- **Infinite Token Lifetime**: JWTs or session tokens that do not expire or lack refresh mechanisms.
- **Improper Logout**: Failing to invalidate tokens on the server-side upon user logout.

## Suggested Verification Tests
1. Verify that all API endpoints require valid, unexpired authentication tokens.
2. Test login endpoints for brute-force protections (e.g., rate limiting, CAPTCHA).
3. Ensure tokens are securely stored (e.g., EncryptedSharedPreferences or Android Keystore).
4. Verify that session tokens expire after a reasonable period of inactivity.
5. Perform a logout and attempt to reuse the old session token.

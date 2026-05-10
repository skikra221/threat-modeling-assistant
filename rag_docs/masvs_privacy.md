# MASVS-PRIVACY: Privacy and Personal Data

## Core Concepts
Privacy focuses on protecting the user's personal information and ensuring compliance with regulations like GDPR or CCPA. Applications must only collect what is necessary and be transparent about data usage.

## Common Weaknesses
- **Excessive Permissions**: Requesting location, camera, or contacts access when the core features do not require them.
- **Hidden Tracking**: Integrating third-party SDKs that collect device identifiers or location data without explicit consent.
- **Data Retention**: Keeping user data indefinitely without a clear deletion policy.
- **Lack of Consent**: Failing to provide a clear privacy policy or opt-in mechanism before collecting data.

## Suggested Verification Tests
1. Review the application's Privacy Policy and map it to actual data collection behavior.
2. Intercept network traffic to identify third-party trackers or analytics SDKs.
3. Check `AndroidManifest.xml` for excessive or dangerous permissions.
4. Verify that users can easily delete their account and associated data.

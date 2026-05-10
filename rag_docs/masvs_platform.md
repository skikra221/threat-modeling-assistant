# MASVS-PLATFORM: Platform Interaction

## Core Concepts
Android applications interact with the OS and other apps through IPC (Inter-Process Communication) mechanisms like Intents, Activities, Services, and Content Providers. Improper configuration can expose internal functionality to malicious apps.

## Common Weaknesses
- **Exported Components**: Activities, Services, or Receivers marked as `exported="true"` without permission checks.
- **Insecure Deep Links**: Custom URL schemes that can be hijacked or used to trigger unintended actions.
- **Intent Spoofing**: Accepting implicit intents without validating the sender.
- **Tapjacking**: Allowing the app to be overlaid by other malicious applications.

## Suggested Verification Tests
1. Analyze `AndroidManifest.xml` for exported components and verify if they are protected by custom signature permissions.
2. Use tools like `drozer` or `adb shell am` to interact with exported components and trigger unexpected behaviors.
3. Verify that deep links and App Links correctly validate input parameters.
4. Ensure `filterTouchesWhenObscured` is used for sensitive UI elements to prevent tapjacking.

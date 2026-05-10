# MASVS-STORAGE: Data Storage and Privacy

## Core Concepts
Mobile apps often handle sensitive data such as PII, credentials, and financial information. Storing this data insecurely on the device can lead to severe data breaches if the device is lost, stolen, or compromised by malware.

## Common Weaknesses
- **Plaintext Storage**: Storing sensitive data in SQLite databases, XML files, or SharedPreferences without encryption.
- **Insecure Key Storage**: Hardcoding encryption keys in the application binary instead of using the Android Keystore.
- **Log Leakage**: Printing sensitive API responses or credentials to Logcat.
- **Insecure Backups**: Allowing application data to be included in ADB backups (`android:allowBackup="true"`).

## Suggested Verification Tests
1. Inspect the `/data/data/<package_name>` directory on a rooted device to verify no plaintext sensitive data exists.
2. Verify that `EncryptedSharedPreferences` or SQLCipher is used for sensitive storage.
3. Check AndroidManifest.xml to ensure `android:allowBackup="false"` is set.
4. Monitor `adb logcat` during application usage to ensure no secrets are leaked.

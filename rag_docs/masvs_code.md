# MASVS-CODE: Code Quality and Build Setting

## Core Concepts
Secure coding practices and proper build configurations are fundamental to application security. Attackers can exploit debuggable builds, reverse-engineer obfuscated code, or extract hardcoded secrets from the binary.

## Common Weaknesses
- **Hardcoded Secrets**: Embedding API keys, passwords, or cryptographic keys directly in the source code.
- **Debuggable Builds**: Releasing an APK with `android:debuggable="true"`, allowing attackers to attach debuggers.
- **Lack of Obfuscation**: Failing to use ProGuard or R8 to obfuscate the codebase, making reverse engineering trivial.
- **Insecure Third-Party Libraries**: Using libraries with known CVEs or relying on unmaintained dependencies.

## Suggested Verification Tests
1. Decompile the APK and run tools like `trufflehog` or `gitleaks` to find hardcoded secrets.
2. Verify that the production APK is signed with a release key and `android:debuggable="false"`.
3. Check the application for obfuscation using tools like `jadx` to ensure class and method names are minified.
4. Scan dependencies with tools like OWASP Dependency-Check.

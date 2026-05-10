# MASVS-NETWORK: Network Communication

## Core Concepts
Mobile applications rely heavily on APIs. If the communication channel is not secured, attackers can intercept, modify, or replay network traffic using Man-in-the-Middle (MitM) attacks.

## Common Weaknesses
- **Cleartext Traffic**: Allowing HTTP traffic instead of enforcing HTTPS.
- **Weak TLS Configurations**: Supporting outdated protocols like TLS 1.0 or weak cipher suites.
- **Missing Certificate Validation**: Accepting self-signed certificates or failing to validate the hostname.
- **Lack of Certificate Pinning**: Trusting the system certificate store without pinning in high-security apps.

## Suggested Verification Tests
1. Intercept traffic using Burp Suite or OWASP ZAP to verify all traffic uses HTTPS.
2. Check the `network_security_config.xml` to ensure `cleartextTrafficPermitted="false"`.
3. Attempt a MitM attack using a custom CA certificate to verify if SSL/TLS Pinning is implemented and effective.
4. Verify that the app rejects connections with invalid or expired certificates.

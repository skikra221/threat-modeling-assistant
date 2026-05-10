# STRIDE Threat Model

## Overview
STRIDE is a threat modeling methodology developed by Microsoft. It categorizes threats into six distinct types to help identify potential security flaws during the design phase.

## Categories
- **Spoofing**: Impersonating something or someone else. (e.g., MAC spoofing, session hijacking).
- **Tampering**: Modifying data or code. (e.g., altering a configuration file, memory manipulation).
- **Repudiation**: Claiming to have not performed an action. (e.g., deleting logs, lack of audit trails).
- **Information Disclosure**: Exposing information to unauthorized individuals. (e.g., data leaks, plaintext storage).
- **Denial of Service (DoS)**: Denying or degrading service to valid users. (e.g., resource exhaustion, crashing an endpoint).
- **Elevation of Privilege**: Gaining higher privileges than intended. (e.g., exploiting a vulnerability to gain root or admin access).

## Application to Mobile Security
When modeling mobile applications, STRIDE helps structure how a malicious user (or app) on the same device or network can interact with the app's components, APIs, and data storage.

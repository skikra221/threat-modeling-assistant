# LINDDUN Privacy Threat Model

## Overview
LINDDUN is a privacy threat modeling methodology designed to systematically identify privacy threats in software architectures.

## Categories
- **Linkability**: The ability to link two or more items of interest (e.g., tracking a user across multiple sessions without their knowledge).
- **Identifiability**: The ability to identify a subject from a set of data (e.g., deanonymizing a dataset).
- **Non-repudiation**: The inability of the user to deny a claim (while useful for security, this can harm privacy if users cannot deny certain actions).
- **Detectability**: The ability to deduce the presence of a user or data item (e.g., observing network traffic patterns).
- **Disclosure of Information**: The exposure of personal data to unauthorized parties.
- **Unawareness**: The user's lack of knowledge about how their data is collected, processed, or shared.
- **Non-compliance**: The failure to comply with privacy policies, regulations (e.g., GDPR), or legislation.

## Application to Mobile Privacy
LINDDUN is particularly relevant for mobile apps that collect location data, biometrics, or device identifiers. It ensures that privacy-by-design principles are incorporated from the start.

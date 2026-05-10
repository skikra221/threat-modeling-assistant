# Preliminary Evaluation Plan and Results Template

**Purpose:** This document outlines the methodology for evaluating the Threat Modeling Assistant (TMA) for academic publication, ensuring robust, reproducible, and academically honest claims.

## 1. Evaluation Methodology

The evaluation will compare the automated Threat Modeling Assistant against standard manual threat modeling workshops (e.g., using STRIDE on a whiteboard/Excel) and traditional static analysis (e.g., MobSF).

**Evaluation Metrics:**
1. **Time-to-Model (TTM):** Time taken from input ingestion to the generation of the first actionable Risk Register. (Measured in seconds for TMA, hours for manual).
2. **Threat Identification Volume:** Absolute number of threats identified.
3. **MASVS Mapping Accuracy:** Percentage of identified threats correctly mapped to a relevant OWASP MASVS 2.0 category (verified by a security expert).
4. **False Positive / False Negative Rate (Indicative):** Comparison against a known ground-truth threat model for a vulnerable application.

## 2. Test Cases (Sample Data)

To prove the versatility of the tool, the evaluation must include a minimum of 4 distinct test cases representing different input types and architectures.

1. **Test Case A (APK - Insecure App):** *InsecureBankv2.apk* or *Damn Vulnerable Bank.apk*. 
   - *Goal:* Prove the tool successfully extracts outdated SDKs, exported components, and cleartext traffic.
2. **Test Case B (APK - Production App):** A modern, hardened open-source app (e.g., Signal or standard Android AOSP app).
   - *Goal:* Prove the tool does not generate excessive false positives for well-configured apps.
3. **Test Case C (YAML - Fintech):** A theoretical banking architecture defined in YAML.
   - *Goal:* Prove the tool can evaluate PII, token storage, and authentication boundaries.
4. **Test Case D (YAML - Healthcare):** A theoretical healthcare tracking architecture.
   - *Goal:* Prove the tool evaluates MASVS-PRIVACY and data logging requirements.

## 3. Results Template (To be filled for the paper)

### Table 1: Performance and Extraction Metrics

| Application / Test Case | Input Type | Time to Report (s) | STRIDE Threats Found | Critical / High Risks | MASVS Categories Covered | PDF Generated? |
|-------------------------|------------|--------------------|----------------------|-----------------------|--------------------------|----------------|
| InsecureBankv2          | APK        | [e.g., 2.3s]       | [e.g., 14]           | [e.g., 6]             | AUTH, NET, PLATFORM      | Yes            |
| Hardened Open Source    | APK        | [e.g., 3.1s]       | [e.g., 3]            | [e.g., 0]             | CODE, PRIVACY            | Yes            |
| Fintech Architecture    | YAML       | [e.g., 0.8s]       | [e.g., 9]            | [e.g., 3]             | STORAGE, AUTH, NET       | Yes            |
| Healthcare Tracker      | YAML       | [e.g., 0.6s]       | [e.g., 7]            | [e.g., 2]             | PRIVACY, STORAGE         | Yes            |

### Table 2: Comparative Analysis (TMA vs Manual vs SAST)

| Capability | Threat Modeling Assistant (TMA) | Manual STRIDE Workshop | Standard SAST (e.g., MobSF) |
|------------|---------------------------------|------------------------|-----------------------------|
| **Primary Input** | Architecture (YAML) & APKs | Human Knowledge / Docs | Source Code / APKs |
| **Speed** | Seconds | Days / Weeks | Minutes |
| **Identifies Logic Flaws?** | Yes (Architectural heuristics) | Yes (Deeply) | No (Focuses on code bugs) |
| **Outputs** | Risk Register, Graph, PDF | Spreadsheets, Diagrams | Vulnerability Scan Report |
| **MASVS Native Mapping** | Yes (Automated) | Manual mapping required| Often mapped, but code-level |
| **Scalability** | High (CI/CD friendly) | Low | High |

## 4. Interpretation of Results (Guidelines for Paper)

When writing the interpretation section of the paper, focus on the following narrative:
- **Efficiency:** TMA drastically reduces the initial barrier to entry for threat modeling. Generating the baseline in seconds allows security teams to focus on complex logical flaws rather than enumerating standard manifest misconfigurations.
- **Accuracy:** The deterministic rule engine ensures that no fundamental Android misconfiguration (like `allowBackup` or cleartext traffic) escapes the threat model, which humans might occasionally overlook in a tiring workshop.
- **Limitations Identified:** Acknowledge that while TMA is fast, it *requires* accurate YAML inputs for theoretical apps, and its APK analysis is limited to static manifest/DEX metadata. It cannot dynamically detect complex server-side authentication bypasses.

## 5. Case Study: InsecureBankv2 Walkthrough
*(To be detailed in the Evaluation section of the paper)*
- Describe the exact flags extracted by `apk_parser.py`.
- Trace how `rules_engine.py` converted `android:exported="true"` into an *Elevation of Privilege* threat.
- Show a snippet of the generated PDF report highlighting this specific finding.

# 4-Page Demo/Artifact Paper Outline

**Target:** Artifact and Demonstration Track at a Cybersecurity Conference
**Format:** IEEE/ACM Standard 2-Column Format
**Estimated Length:** 4 Pages

## Abstract (150 words)
A concise summary of the problem (manual threat modeling is slow), the solution (Threat Modeling Assistant), the methodology (APK/YAML parsing to STRIDE/MASVS), and the demonstration scenario.

## 1. Introduction (0.75 Page)
- **Context:** The importance of Shift-Left security and DevSecOps for mobile applications.
- **Problem:** Threat modeling is a bottleneck; vulnerability scanners miss architectural logic flaws.
- **Solution:** Introduce the Threat Modeling Assistant (TMA).
- **Contributions:** 
  1. Automated STRIDE extraction from APKs/YAML.
  2. Direct MASVS 2.0 mapping and risk scoring.
  3. Interactive UI for data flow visualization and PDF compliance reporting.

## 2. System Architecture and Methodology (1.5 Pages)
*Include Figure 1: High-level pipeline architecture.*
- **Input Parsing Pipeline:** Explain how `apk_parser.py` uses Androguard to extract manifests, components, and endpoints, and how `parser.py` handles declarative YAML architectures.
- **Deterministic Threat Generation:** Explain the `rules_engine.py`. Provide one clear example (e.g., `android:debuggable="true"` -> MASVS-CODE -> Information Disclosure).
- **Risk Scoring:** Briefly mention the Impact x Probability x Exposure formula.
- **Visualization & Reporting:** Explain the generation of the Graphviz data flow diagram and the wkhtmltopdf report generation for audits.

## 3. Demonstration Scenario (1 Page)
*Include Figure 2: The Streamlit Dashboard showing the Risk Register and Architecture Graph.*
- **Setup:** Explain the sample vulnerable application used for the demo (e.g., a purposefully vulnerable APK).
- **Step 1: Ingestion:** The user uploads the APK via the UI.
- **Step 2: Analysis & Triaging:** The dashboard displays the KPI cards and the Risk Register. Walk through a specific high-risk finding shown on screen.
- **Step 3: Exploration:** The user switches to the architecture diagram tab to visually identify the compromised boundary.
- **Step 4: Export:** Generating the remediation roadmap and PDF report for the development team.

## 4. Conclusion and Future Work (0.5 Page)
- **Summary:** TMA bridges the gap between static artifacts and formal threat models.
- **Limitations:** Rule-based limitations and reliance on static analysis.
- **Future Work:** AI-driven dynamic report rewriting and integration directly into CI/CD pipelines.

## References (0.25 Page)
- OWASP Mobile Application Security Verification Standard (MASVS).
- Microsoft STRIDE methodology.
- Key papers on automated threat modeling and mobile security.

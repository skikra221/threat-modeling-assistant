# 6-Page Short Research Paper Outline

**Target:** Short Research Paper Track at a Cybersecurity Conference
**Format:** IEEE/ACM Standard 2-Column Format
**Estimated Length:** 6 Pages

## Abstract (200 words)
Summary of the motivation (DevSecOps bottleneck in mobile), proposed methodology (hybrid deterministic threat extraction mapping to MASVS), the architecture of the Threat Modeling Assistant, and a summary of preliminary evaluation results showing efficiency gains over manual workshops.

## 1. Introduction (1 Page)
- **Background:** Evolution of mobile threats and the OWASP MASVS standard.
- **Problem Statement:** The gap between early-stage architectural design, compiled APK analysis, and actionable threat models. Manual threat modeling (e.g., using STRIDE) does not scale in agile environments.
- **Proposed Solution:** Threat Modeling Assistant, a hybrid pipeline supporting theoretical and compiled inputs.
- **Contributions:** Heuristic-to-STRIDE mapping engine, unified UI, automated risk quantification.

## 2. Related Work (0.75 Page)
- **Static Analysis Tools:** MobSF, JADX, Androguard (explain why they are insufficient for *architectural* threat modeling).
- **Threat Modeling Tools:** Microsoft Threat Modeling Tool, OWASP Threat Dragon (explain their lack of mobile-specific automation and MASVS integration).
- **Positioning:** TMA sits between SAST (code-level) and manual threat modeling (design-level).

## 3. Methodology & System Design (1.5 Pages)
*Include Figure 1: Internal data flow and parsing architecture.*
- **Input Normalization:** How `apk_parser.py` (via Androguard) and `parser.py` (YAML) converge into a unified `app_data` dictionary.
- **Heuristic Threat Extraction:** Detail the `rules_engine.py`. Explain how specific characteristics (e.g., `has_login` and `has_api`) trigger logical threat generation (e.g., "Spoofing" and "MASVS-AUTH").
- **Risk Quantification Framework:** Explain the Impact x Probability x Exposure matrix and how it supports automated prioritization.
*Include Table 1: Example mapping from App Characteristic -> STRIDE -> MASVS.*

## 4. Implementation (0.75 Page)
- **Technology Stack:** Python, Streamlit, Androguard, Graphviz, PDFKit.
- **Reporting & RAG:** Briefly mention how threats are enriched with mitigation advice and exported to compliance-ready formats.

## 5. Preliminary Evaluation and Case Studies (1.25 Pages)
*Include Table 2: Evaluation Results (Time taken, Threats found, MASVS coverage).*
- **Experimental Setup:** Describe the sample set (e.g., 2 open-source vulnerable apps like InsecureBankv2, 2 theoretical YAML architectures).
- **Results:** Compare the time required to generate the baseline threat model using TMA vs. a manual STRIDE workshop.
- **Discussion:** Highlight the accuracy of the rule-based approach for identifying baseline architectural flaws. Note the limitations regarding false negatives for complex business logic.

## 6. Limitations and Future Work (0.5 Page)
- **Limitations:** Lack of dynamic analysis verification; heuristic rules cannot detect novel zero-days.
- **Future Work:** Integration with LLMs for dynamic rule generation; CI/CD headless execution.

## 7. Conclusion (0.25 Page)
- Restate the value proposition: Automating the translation of mobile artifacts into actionable, MASVS-compliant threat models accelerates secure development lifecycles.

## References (0.5 Page)
- Include ~15-20 academic and industry references.

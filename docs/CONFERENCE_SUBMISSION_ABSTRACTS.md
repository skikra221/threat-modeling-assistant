# Conference Submission Abstracts & Positioning

## 1. Project Title Options

**Scientific / Research Paper Titles:**
1. Automated Threat Modeling for Mobile Applications: Bridging the Gap Between Static Analysis and Architectural Risk Assessment.
2. Towards Scalable DevSecOps: A Heuristic-Based STRIDE Threat Modeling Approach for Android APKs.
3. Integrating OWASP MASVS into Automated Threat Modeling Pipelines for Mobile Ecosystems.

**Demo / Artifact Paper Titles:**
1. Demonstrating Threat Modeling Assistant: From Android APKs to Actionable Security Roadmaps.
2. Threat Modeling Assistant: An Interactive Dashboard for Mobile Security Assessment.

**Poster Titles:**
1. Automating STRIDE Analysis for Android Applications.
2. Threat Modeling Assistant: Making OWASP MASVS Accessible.

**Recommendation:** *Automated Threat Modeling for Mobile Applications: Bridging the Gap Between Static Analysis and Architectural Risk Assessment.*

---

## 2. Abstracts

### 150-Word Abstract
Manual threat modeling for mobile applications is a critical but notoriously slow process, often disconnected from the actual codebase. We present the Threat Modeling Assistant, an automated DevSecOps tool that bridges this gap. By ingesting either architectural design files (YAML) or compiled Android binaries (APKs), the system utilizes deterministic heuristics to extract components, endpoints, and permissions. It automatically maps these findings to STRIDE threats and OWASP MASVS 2.0 requirements, calculating risk scores to prioritize remediation. The tool features an interactive dashboard that dynamically generates data flow diagrams, remediation roadmaps, and compliance-ready PDF reports. Our tool significantly reduces the time-to-model for mobile applications, shifting security left and providing developers with immediate, actionable architectural feedback.

### 250-Word Abstract
As mobile applications increasingly handle sensitive user data and complex transactions, ensuring robust security architectures is paramount. However, manual threat modeling is time-consuming, requires specialized expertise, and is difficult to scale within agile DevSecOps environments. While static application security testing (SAST) tools excel at identifying code-level vulnerabilities, they frequently miss fundamental architectural flaws, such as broken trust boundaries or excessive default permissions. 

To address this limitation, we introduce the Threat Modeling Assistant, an automated pipeline designed to rapidly assess mobile application security posture. The system accepts both theoretical system designs (YAML/JSON) and compiled binaries (Android APKs). Using a deterministic heuristics engine, it extracts architectural metadata—such as exported components, API endpoints, and manifest configurations—and automatically infers potential vulnerabilities based on the STRIDE framework. These threats are quantified using an Impact-Probability-Exposure matrix and directly mapped to the OWASP Mobile Application Security Verification Standard (MASVS 2.0). 

The resulting risk register is presented via a highly interactive dashboard that dynamically renders Graphviz-based data flow diagrams and generates actionable remediation roadmaps. Furthermore, the tool exports comprehensive, audit-ready PDF reports. By automating the translation of application artifacts into structured, prioritized threat models, the Threat Modeling Assistant democratizes early-stage security analysis, allowing development teams to identify and remediate architectural flaws before they manifest as critical vulnerabilities in production.

### 500-Word Extended Abstract
*Refer to the combination of the 250-word abstract expanded with the evaluation metrics and case study structures outlined in the Evaluation Plan.*

---

## 3. Reviewer-Facing Contribution Statement
*(To be used in the submission cover letter or introduction)*

**Contributions to the Field:**
1. **Hybrid Threat Inference Pipeline:** We present a novel approach that unifies the parsing of abstract architectural documents (YAML) and empirical artifacts (compiled APKs) into a single, normalized threat modeling engine.
2. **Automated MASVS 2.0 Mapping:** We provide a deterministic mapping strategy connecting low-level Android manifest flags (e.g., `allowBackup`, exported components) and architectural characteristics directly to high-level OWASP MASVS compliance categories.
3. **Interactive Visual Artifact Generation:** We release an open-source, interactive dashboard capable of instantly generating dynamic data flow diagrams and PDF compliance reports, serving as a practical artifact for both academic research and DevSecOps practitioners.

---

## 4. English Conference Pitch
*(For a 1-minute lightning talk or poster presentation intro)*
"Hello, my name is [Name]. While vulnerability scanners are great at finding bad code, they are terrible at finding bad design. Manual threat modeling finds bad design, but it takes weeks of expert time. Today, I am presenting the Threat Modeling Assistant. It is a fully automated tool that ingests your Android APK or architecture files, extracts the critical components, and instantly generates a STRIDE threat model mapped directly to OWASP MASVS. In seconds, it provides you with an interactive risk register, a visual data flow diagram, and a PDF compliance report, proving that we can automate architectural risk assessments at the speed of modern DevSecOps."

---

## 5. French Summary (Résumé)
La modélisation des menaces (threat modeling) pour les applications mobiles est un processus essentiel mais souvent manuel et chronophage. Nous présentons le *Threat Modeling Assistant*, un outil automatisé conçu pour s'intégrer aux pipelines DevSecOps. Capable d'analyser des fichiers d'architecture (YAML) ou des binaires compilés (APK Android), l'outil utilise un moteur de règles heuristiques pour extraire automatiquement les menaces selon la méthode STRIDE et les associer au standard OWASP MASVS 2.0. Le tableau de bord interactif génère instantanément un registre des risques, un diagramme de flux de données et des rapports PDF, permettant d'identifier et de corriger les failles architecturales dès les premières phases de développement.

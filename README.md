# Threat Modeling Assistant

An automated threat modeling tool for mobile applications based on STRIDE and OWASP MASVS.

## Features
- YAML and APK-based architecture input.
- Automatic threat identification via heuristic engine.
- Risk scoring (Impact × Probability × Exposure).
- **Local RAG Knowledge Assistant** (Deterministic enrichment using OWASP MASVS and STRIDE).
- Premium Dashboard UI.
- Export to Markdown and Professional PDF.

## Local RAG Knowledge Base

The application features a "RAG Lite" module that enriches deterministic threat findings with structured knowledge.
- **Privacy-First & Local**: Uses local Markdown documents (`rag_docs/`) without requiring an external LLM or external API keys.
- **No Hallucinations**: The RAG only enriches threats *already* detected by the deterministic rules engine; it does not invent vulnerabilities.
- **Actionable Intelligence**: Provides MASVS rationales, suggested verification tests, and missing information questions to guide manual security reviews.
- **Future-Ready**: The engine is designed modularly, making it trivial to swap the exact string matching with ChromaDB vector search and an LLM in the future.

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Install Playwright browser (required for PDF export):
   ```bash
   python -m playwright install chromium
   ```

## Usage

Run the Streamlit application:
```bash
streamlit run app.py
```

Import the sample file `data/input_app_example.yaml` to see the dashboard in action.

## Forensic Evidence Pack

The application now supports exporting a **Forensic Evidence Pack ZIP**. This feature is critical for academic reproducibility, auditability, and conference artifact submissions.

When analysis completes, you can download a `.zip` package containing:
- **input/**: Original YAML/JSON or extracted APK metadata, alongside an SHA-256 hash.
- **reports/**: The full Threat Model report in Markdown and PDF formats.
- **exports/**: Raw, parsable analysis outputs (`risk_register.csv`, `risk_register.json`, `masvs_mapping.json`, `stride_summary.json`, `rag_explanations.json`).
- **diagrams/**: Generated architectural data flow models (Mermaid/DOT).
- **metadata/**: Execution environment details, timestamps, tool versions, and cryptographic hashes of the inputs and reports (`analysis_metadata.json`).
- **audit_trail/**: A high-level text log of the execution.

This structured pack ensures that every analysis can be independently verified, making the Threat Modeling Assistant highly suitable for DevSecOps pipelines and academic peer-reviewed artifacts.

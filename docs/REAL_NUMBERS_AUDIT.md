# Threat Modeling Assistant: Real Numbers Audit

## 1. Verdict: Real Numbers Found or Not Found

**Verdict: NOT READY (NO REAL NUMBERS FOUND)**

Based on a comprehensive audit of the repository, there are **no real evaluation numbers** present. Every metric, execution time, and threat count currently documented in the repository is a manually written example, a placeholder, or a template. The project codebase is highly mature and functional, but the scientific experiments required to validate it for a research paper have not yet been executed or recorded in the repository.

## 2. Files Inspected

The following files and directories were inspected to search for evidence of measurement:
- `docs/EVALUATION_PLAN.md`: **Inspected** (Contains templates with `[e.g., ...]`)
- `docs/PROJECT_RESEARCH_DOSSIER.md`: **Inspected** (Contains `X`, `Y`, `Z s` placeholders)
- `data/examples/`: **Not found** (Only a single `data/input_app_example.yaml` exists, no varied dataset)
- `reports/`: **Inspected** (Directory is currently empty)
- `artifacts/` / `exports/`: **Not found / Empty** (No generated Evidence Packs, CSVs, or JSON logs)
- `src/evaluation_runner.py` / `src/evaluation.py`: **Not found** (No automated evaluation script exists)
- `app.py`: **Inspected** (Fully functional dashboard, but lacks an automated batch evaluation mode)

## 3. Real Evaluation Results Found

**None.**
There are no CSV files, JSON metadata exports, or analysis logs in the repository that prove the tool was systematically run against a dataset of mobile applications.

## 4. Placeholder / Example Values Found

All numbers found in the documentation are placeholders.
- In `docs/EVALUATION_PLAN.md` (Table 1), the values are explicitly bracketed examples: `[e.g., 2.3s]`, `[e.g., 14]`, `[e.g., 6]`.
- In `docs/PROJECT_RESEARCH_DOSSIER.md` (Section 20), there are hardcoded example rows (e.g., `InsecureBankv2 | APK | 12 | 5`) mixed with explicit placeholder rows: `*App C* | *APK* | *X* | *Y* | *...* | *Z s*`.
- These tables are clearly labeled as "Results Template" and "Proposed Metrics".

## 5. Missing Metrics

To qualify for a scientific or demo paper, the following metrics are currently completely missing and need to be measured empirically:
- **Measured Analysis Time in Seconds:** Real timing for parsing an APK and generating the threat model.
- **Concrete Threat Counts:** Actual number of threats detected per test app.
- **Risk Distribution:** Concrete counts of Critical, High, Medium, and Low risks.
- **Coverage Output:** Verifiable lists of MASVS and STRIDE categories mapped per app.
- **Artifact Generation Status:** Proof that PDF reports and Evidence Pack ZIPs generate successfully for each test case.

## 6. Evidence of Measurement

**Zero evidence.**
- No `evaluation_results.csv` exists.
- No `analysis_metadata.json` from the newly implemented Evidence Pack feature has been saved to the repository.
- There is no automated script (`evaluation_runner.py`) designed to loop through multiple APKs/YAMLs and record their execution metrics.

## 7. What I Need to Run Next

To generate real, paper-ready results, you must perform the following steps:

1. **Build a Dataset:** Create a folder (e.g., `data/evaluation_dataset/`) and place at least 4 distinct inputs in it. As outlined in your plan, you need:
   - 2 real APKs (e.g., `InsecureBankv2.apk` and a standard production APK).
   - 2 distinct YAML architecture files (e.g., your existing `input_app_example.yaml` and one more).
2. **Execute the Tests:**
   - Launch the application (`streamlit run app.py`).
   - Manually upload each of the 4 test cases one by one.
3. **Capture the Evidence:**
   - For each test case, wait for the analysis to finish and click **"Download Evidence Pack ZIP"**.
   - Extract the ZIPs and save the `metadata/analysis_metadata.json` and `reports/threat_model_report.pdf` files into a persistent `evaluation_results/` directory in your project.
4. **Compile the Metrics:**
   - Read the real values from the generated `analysis_metadata.json` files (which contain `threat_count`, `max_score`, `high_risk_count`, etc.).
   - Replace the `[e.g., ...]` placeholders in `docs/EVALUATION_PLAN.md` and `docs/PROJECT_RESEARCH_DOSSIER.md` with these real numbers.
   - Note the real processing time (you may need to time the execution manually or add a timer to `app.py`).

*(Alternatively, you can ask me to write a headless `src/evaluation_runner.py` script that automatically processes all files in a folder and generates the CSV table for you).*

## 8. Paper Readiness Status

**STATUS: PARTIAL / NOT READY FOR IMMEDIATE SUBMISSION**

- **The Software:** **READY.** The tool itself, the UI, the rule engine, and the Evidence Pack generation are highly mature and ready to be demonstrated.
- **The Science (Evaluation):** **NOT READY.** A research or artifact paper cannot be submitted with `[e.g., 14]` in the results table. You *must* run the software against real data and record the outputs before writing the final draft of your paper.

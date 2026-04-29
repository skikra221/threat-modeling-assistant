# Threat Modeling Assistant

An automated threat modeling tool for mobile applications based on STRIDE and OWASP MASVS.

## Features
- YAML-based architecture input.
- Automatic threat identification via heuristic engine.
- Risk scoring (Impact × Probability × Exposure).
- Premium Dashboard UI.
- Export to Markdown and Professional PDF.

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

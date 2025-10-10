Kylo Prototype - Local Testing

This file explains how to run the small prototype in this workspace.

1) Create and activate a virtual env (Windows PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pip install -e .
```

2) Initialize kylo in the current folder:

```powershell
kylo init
```

3) Run the audit test runner:

```powershell
python tests/run_tests.py
```

Notes:
- This prototype includes a simple AST-based auditor. It's intentionally minimal and meant as a starting point for the features you described (README alignment, requirements parsing, state JSON updates).
- For any LLM/"Gemini" integration, ensure keys are never used client-side. Implement server-side proxying and per-request JSON query payloads with strict logging and consent.

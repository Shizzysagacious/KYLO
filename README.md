Kylo (prototype)

Kylo is an AI-powered security code auditor. This repository contains a minimal prototype CLI implementing the following commands:

- `kylo init` — initialize the project, ensure `README.md` exists, create internal state folder `.kylo/`.
- `kylo audit [path]` — perform a static audit (simple AST checks) of Python files and generate a JSON report under `.kylo/state.json`.
- `kylo secure [target]` — run security checks for a target (folder or file) and print recommendations.

Usage

1. Create a virtualenv and install the package in editable mode (optional):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pip install -e .
```

2. Run commands:

```powershell
kylo init
kylo audit myfile.py
kylo secure backend/
```

Notes

- This is a prototype. The real product would include LLM integration (server-side only), CI/CD hooks, team auth, telemetry with consent, and robust rule sets.

# Smoke test for Gemini merging (mocked). Run with: python tests/gemini_smoke_test.py
from kylo.auditor import audit_file
from pathlib import Path
import json

# Create a temp python file
p = Path('tests/_temp_gemini.py')
p.write_text('''user_id = 5
query = f"SELECT * FROM users WHERE id = {user_id}"
''')

# Set env to force gemini (but our analyzer will fail to call without key, so we mock)
import os
os.environ['KYLO_FORCE_GEMINI'] = '0'

report = audit_file(str(p), readme_keywords=['users'])
print('Issues:', len(report))
print(json.dumps(report, indent=2))

# cleanup
p.unlink()
print('SMOKE OK')

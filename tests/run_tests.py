import os
import tempfile
from kylo.auditor import audit_file

# create a temp python file that uses f-string SQL
code = """
user_id = 5
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

fd, path = tempfile.mkstemp(suffix='.py')
with os.fdopen(fd, 'w', encoding='utf-8') as f:
    f.write(code)

issues = audit_file(path, readme_keywords=['users','auth'])
print('Issues found:', len(issues))
for i in issues:
    print(i)

# cleanup
os.remove(path)

if len(issues) == 0:
    raise SystemExit('TEST FAILED: expected issues but found none')
print('TESTS PASSED')

from kylo.secure_storage import SecureStorage
from pathlib import Path
ss = SecureStorage(Path('.'))
# ensure admin exists
ss.set_admin_token('founder-secret-xyz')
ss.store_api_key('gemini','founder-gemini-key-xyz')
print('WROTE')

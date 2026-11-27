"""Authorize the user's own Gmail in the browser, send-only."""
import json
import os
from google_auth_oauthlib.flow import InstalledAppFlow
from live_tools import PRIVATE, TOKEN_FILE, SCOPE

if __name__ == '__main__':
    PRIVATE.mkdir(parents=True, exist_ok=True)
    client = PRIVATE / 'credentials.json'
    if not client.is_file():
        raise SystemExit(f'Download a Desktop OAuth client JSON and save it at:\n{client}')
    flow = InstalledAppFlow.from_client_secrets_file(str(client), [SCOPE])
    creds = flow.run_local_server(port=0, prompt='consent', access_type='offline')
    if not creds.has_scopes([SCOPE]) or not creds.refresh_token:
        raise SystemExit('Send-only authorization or refresh token missing. No token saved.')
    temporary = TOKEN_FILE.with_suffix('.tmp')
    temporary.write_text(creds.to_json(), encoding='utf-8')
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(TOKEN_FILE)
    print('Gmail send-only connection saved. No email was sent.')

# AgentShield live workspace

Extract these files directly into your existing AgentShield project (beside web_app.py). No original files are replaced. Stop the existing server first, then use the existing virtual environment:

```powershell
.\.venv-agentdojo\Scripts\python.exe -m pip install -r live_requirements.txt
.\.venv-agentdojo\Scripts\python.exe -m unittest test_live -v
.\.venv-agentdojo\Scripts\python.exe -u live_app.py
```

Open http://127.0.0.1:8000/live. The original dashboard remains at http://127.0.0.1:8000/. Keep Ollama running with the model configured in web_app.py (originally llama3.2:3b). File analysis and email drafting do not need Gmail authorization.

## Connect Gmail

1. Open https://console.cloud.google.com/ and create/select a project. Enable Gmail API (https://console.cloud.google.com/apis/library/gmail.googleapis.com).
2. Configure Google Auth platform: Branding, Audience (External for personal Gmail), add your own Gmail as a test user if the app is in Testing, and request the scope https://www.googleapis.com/auth/gmail.send under Data Access.
3. Under Clients create a Desktop app OAuth client. Download the client JSON. On Windows, create the directory `%LOCALAPPDATA%\AgentShieldLive` and save the downloaded file there as `credentials.json`. Do not put the file in GitHub or share it. In PowerShell: `New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\AgentShieldLive"`.
4. Run `.\.venv-agentdojo\Scripts\python.exe gmail_setup.py`, select your Gmail in the browser, and approve the send-only permission. No email is sent in this step. Reload the live workspace. Token is stored outside the repository in the same private directory. A test-mode external OAuth app may require reauthorization periodically (typically after seven days).
5. Draft an email, enter your own Gmail as the recipient for the first test, review the exact message, and explicitly click Approve & send real email. Confirm in Gmail Sent. The Gmail API accepting the message is not proof of delivery. If outcome unconfirmed, check Sent before trying again.

## Boundaries

Single-user loopback-only development tool, not a production or multi-user service. New live operations use a separate deterministic approval policy, not the experimental AgentDojo authorization manifest. Documents are explicitly selected by the operator, sent only to local Ollama; never automatically sent to Gmail. Copying analysis to the mail composer is explicit. Only one plain-text recipient; no attachments, inbox reading or deletes. Files: TXT, CSV, MD, JSON, text-based PDF, DOCX; 4 MB, 50 PDF pages, first 12,000 extracted characters; no OCR. Untrusted or malicious documents can still mislead the model or exploit parsers, so use trusted files; file processing isn't OS-sandboxed. The model has no live tools while analyzing. Avoid sensitive data; local Ollama and other software may retain logs. The separate live audit JSONL records status and IDs, not email bodies or file contents. It is not tamper-proof. Tokens are local files, not encrypted by this code; protect the OS account and revoke Google access if necessary. Do not expose port 8000 publicly. Original research results are unaffected. Mock tests do not verify real Gmail or Ollama.

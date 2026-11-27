"""Live operations, separate from AgentDojo and the demo executor."""
import base64
import io
import json
import os
import re
import threading
import time
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from uuid import uuid4

SCOPE = 'https://www.googleapis.com/auth/gmail.send'
PRIVATE = Path(os.environ.get('LOCALAPPDATA') or Path.home() / '.local' / 'share') / 'AgentShieldLive'
TOKEN_FILE = PRIVATE / 'gmail_token.json'
MAX_FILE = 4 * 1024 * 1024
MAX_TEXT = 12000
LOCK = threading.RLock()
PENDING = {}


def audit(event, **fields):
    # Only call with fixed status fields, IDs and non-content metadata.
    PRIVATE.mkdir(parents=True, exist_ok=True)
    with LOCK, (PRIVATE / 'live_audit.jsonl').open('a', encoding='utf-8') as f:
        f.write(json.dumps({'time': datetime.now(timezone.utc).isoformat(), 'event': event, **fields}) + '\n')
        f.flush()
        os.fsync(f.fileno())


def validate_mail(data):
    if not isinstance(data, dict):
        raise ValueError('Invalid email.')
    recipient, subject, body = (data.get(k) for k in ('recipient', 'subject', 'body'))
    if not all(isinstance(x, str) for x in (recipient, subject, body)):
        raise ValueError('Recipient, subject and body are required.')
    # Deliberately limited to one ordinary address, no CC/BCC or headers.
    if len(recipient) > 254 or not re.fullmatch(r'[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', recipient):
        raise ValueError('Enter one valid email address, without spaces or display names.')
    if not subject.strip() or len(subject) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in subject):
        raise ValueError('Subject must be 1–200 characters on one line.')
    if not body.strip() or len(body) > 10000 or '\x00' in body:
        raise ValueError('Body must be 1–10000 characters.')
    return dict(recipient=recipient, subject=subject, body=body)


def gmail_send(mail):
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request, AuthorizedSession
    if not TOKEN_FILE.is_file():
        raise ValueError('Gmail is not connected. Run gmail_setup.py first.')
    creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), [SCOPE])
    if not creds.has_scopes([SCOPE]):
        raise ValueError('Gmail send permission is missing.')
    if not creds.valid:
        creds.refresh(Request())
    msg = EmailMessage()
    msg['To'] = mail['recipient']
    msg['Subject'] = mail['subject']
    msg.set_content(mail['body'])
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('ascii')
    # Do not automatically retry a possibly successful external write.
    with AuthorizedSession(creds, max_refresh_attempts=0) as session:
        response = session.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', json={'raw': raw}, timeout=30)
        if not response.ok:
            raise RuntimeError(f'Gmail returned HTTP {response.status_code}. Check Sent before trying again.')
        message_id = response.json().get('id')
        if not message_id:
            raise RuntimeError('Gmail response did not include a message ID. Check Sent before trying again.')
        return message_id


def purge():
    for key in list(PENDING):
        if PENDING[key][1] <= time.monotonic():
            del PENDING[key]


def prepare(data):
    mail = validate_mail(data)
    if not TOKEN_FILE.is_file():
        raise ValueError('Connect Gmail using gmail_setup.py before requesting approval.')
    with LOCK:
        purge()
        if len(PENDING) >= 30:
            raise ValueError('Too many pending approvals. Wait for expiration.')
        key = str(uuid4())
        audit('EMAIL_REVIEW', request_id=key)
        PENDING[key] = (mail, time.monotonic() + 600)
    return {'approval_id': key, 'mail': mail, 'status': 'REVIEW'}


def approve(data):
    key, choice = data.get('approval_id'), data.get('choice')
    if not isinstance(key, str) or choice not in ('APPROVE', 'DENY'):
        raise ValueError('Invalid approval.')
    with LOCK:
        purge()
        item = PENDING.pop(key, None)
    if item is None:
        raise ValueError('Approval expired, invalid or already used.')
    if choice == 'DENY':
        audit('EMAIL_DENIED', request_id=key)
        return {'status': 'DENIED', 'message': 'No email sent.'}
    # Only the stored, reviewed payload can be sent; ignore any replacement fields.
    audit('EMAIL_APPROVED', request_id=key)
    try:
        message_id = gmail_send(item[0])
    except Exception:
        try:
            audit('EMAIL_OUTCOME_UNCONFIRMED', request_id=key)
        except OSError:
            pass
        return {'status': 'UNCONFIRMED', 'message': 'Sending was not confirmed. Check Gmail Sent before retrying; reconnect Gmail if needed.'}
    try:
        audit('EMAIL_SENT', request_id=key, message_id=message_id)
    except OSError:
        return {'status': 'SENT', 'message': 'Gmail accepted the email; audit recording failed.', 'message_id': message_id}
    return {'status': 'SENT', 'message': 'Gmail accepted the email.', 'message_id': message_id}


def extract_file(name, encoded, check=None):
    def emit(label, status, detail):
        if check is not None:
            check(label, status, detail)
    def reject(label, message):
        emit(label, "FAIL", message)
        raise ValueError(message)
    if not isinstance(name, str) or len(name) > 255 or not isinstance(encoded, str):
        reject('File selection', 'Invalid file selection.')
    if len(encoded) > 4 * ((MAX_FILE + 2) // 3):
        reject('File size', 'File exceeds 4 MB.')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as e:
        reject('File encoding', 'Invalid file data.')
    if not raw or len(raw) > MAX_FILE:
        reject('File size', 'Select a nonempty file of up to 4 MB.')
    emit('File size and encoding', 'PASS', f'{len(raw):,} decoded bytes; nonempty and within 4 MB.')
    ext = Path(name).suffix.lower()
    if ext not in {'.txt', '.csv', '.md', '.json', '.pdf', '.docx'}:
        reject('File extension', 'Unsupported file extension.')
    emit('File extension', 'PASS', f'{ext} is allowlisted; not a malware scan.')
    if ext in {'.txt', '.csv', '.md', '.json'}:
        text = raw.decode('utf-8-sig', errors='replace')
    elif ext == '.pdf':
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            reject('PDF restrictions', 'Encrypted PDFs are not supported.')
        if len(reader.pages) > 50:
            reject('PDF restrictions', 'PDF limit is 50 pages; split the document first.')
        emit('PDF restrictions', 'PASS', f'{len(reader.pages)} pages; not encrypted.')
        text = '\n'.join(p.extract_text() or '' for p in reader.pages)
    elif ext == '.docx':
        from docx import Document
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            if sum(x.file_size for x in z.infolist()) > 30 * 1024 * 1024:
                reject('Word archive size', 'Word document expands beyond the safety limit.')
        emit('Word archive size', 'PASS', 'Declared uncompressed size is within 30 MB.')
        doc = Document(io.BytesIO(raw))
        text = '\n'.join([p.text for p in doc.paragraphs] + [' | '.join(c.text for c in row.cells) for table in doc.tables for row in table.rows])
    else:
        raise ValueError('Supported: TXT, CSV, MD, JSON, PDF, DOCX.')
    if not text.strip():
        reject('Text extraction', 'No readable text found. Scanned PDFs need OCR, which is not supported.')
    emit('Text extraction', 'PASS', 'Readable text extracted; parser is not OS-sandboxed.')
    return text[:MAX_TEXT], len(text) > MAX_TEXT

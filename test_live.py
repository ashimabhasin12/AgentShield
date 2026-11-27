import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import live_tools as t

class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patch = patch.multiple(t, PRIVATE=root, TOKEN_FILE=root/'token.json')
        self.patch.start()
        t.TOKEN_FILE.write_text('{}')
        t.PENDING.clear()
        self.mail = dict(recipient='me@example.com', subject='Test', body='Hello')
    def tearDown(self):
        t.PENDING.clear(); self.patch.stop(); self.tmp.cleanup()
    def test_exact_payload_and_single_use(self):
        key = t.prepare(self.mail)['approval_id']
        with patch.object(t, 'gmail_send', return_value='test-id') as send:
            send.assert_not_called()
            result = t.approve(dict(approval_id=key, choice='APPROVE', recipient='other@example.com'))
            self.assertEqual(result['status'], 'SENT')
            send.assert_called_once_with(self.mail)
            with self.assertRaises(ValueError): t.approve(dict(approval_id=key, choice='APPROVE'))
    def test_denial(self):
        key = t.prepare(self.mail)['approval_id']
        with patch.object(t, 'gmail_send') as send:
            self.assertEqual(t.approve(dict(approval_id=key, choice='DENY'))['status'], 'DENIED')
            send.assert_not_called()
    def test_failure_consumes_approval(self):
        key = t.prepare(self.mail)['approval_id']
        with patch.object(t, 'gmail_send', side_effect=TimeoutError):
            self.assertEqual(t.approve(dict(approval_id=key, choice='APPROVE'))['status'], 'UNCONFIRMED')
            with self.assertRaises(ValueError): t.approve(dict(approval_id=key, choice='APPROVE'))
    def test_expiration(self):
        key = t.prepare(self.mail)['approval_id']
        t.PENDING[key]=(self.mail, 0)
        with patch.object(t,'gmail_send') as send:
            with self.assertRaises(ValueError): t.approve(dict(approval_id=key, choice='APPROVE'))
            send.assert_not_called()
    def test_bad_addresses(self):
        for value in ['a@example.com,b@example.com','a@example.com\nBcc: b@example.com','someone']:
            with self.assertRaises(ValueError): t.prepare(dict(self.mail,recipient=value))
    def test_header_injection(self):
        with self.assertRaises(ValueError): t.prepare(dict(self.mail,subject='Test\nBcc: a@example.com'))
    def test_no_credentials(self):
        t.TOKEN_FILE.unlink()
        with self.assertRaises(ValueError): t.prepare(self.mail)
    def test_selected_file_only(self):
        data=base64.b64encode(b'hello').decode()
        self.assertEqual(t.extract_file('note.txt',data),('hello',False))
        with self.assertRaises(ValueError): t.extract_file('script.exe',data)
        with self.assertRaises(ValueError): t.extract_file('note.txt','!!!')
    def test_truncation(self):
        data=base64.b64encode(b'a'*(t.MAX_TEXT+1)).decode()
        self.assertEqual(t.extract_file('note.txt',data),('a'*t.MAX_TEXT,True))
    def test_audit_failure_prevents_send(self):
        key=t.prepare(self.mail)['approval_id']
        with patch.object(t,'audit',side_effect=OSError),patch.object(t,'gmail_send') as send:
            with self.assertRaises(OSError): t.approve(dict(approval_id=key, choice='APPROVE'))
            send.assert_not_called()

if __name__=='__main__': unittest.main(verbosity=2)

"""AgentShield live workspace; original dashboard remains available at /."""
import json
import secrets
from pathlib import Path
from urllib.request import Request
from http.server import ThreadingHTTPServer
import web_app as demo
import live_tools as tools
import live_document_security as security

STATIC = Path(__file__).resolve().parent / 'live_static'


def model(messages, structured=False):
    payload = {'model': demo.MODEL, 'stream': False, 'messages': messages,
               'options': {'temperature': 0, 'num_predict': 900, 'num_ctx': 8192}}
    if structured:
        payload['format'] = 'json'
    req = Request('http://127.0.0.1:11434/api/chat', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
    with demo.MODEL_LOCK, demo.OPENER.open(req, timeout=300) as response:
        data = json.loads(response.read(1_000_001))
    answer = data['message']['content']
    if not isinstance(answer, str) or not answer.strip():
        raise ValueError('Model returned no answer.')
    return answer


def question(data, key):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        raise ValueError('Enter an instruction of 1–2000 characters.')
    return value


def draft(data):
    instruction = question(data, 'instruction')
    answer = model([{'role': 'system', 'content': 'Draft a plain-text email. Return JSON with only subject and body, both strings. Do not invent facts, recipient addresses, or claim sending. No tools are available.'}, {'role': 'user', 'content': instruction}], structured=True)
    result = json.loads(answer)
    if not isinstance(result, dict) or set(result) != {'subject', 'body'}:
        raise ValueError('Invalid AI draft. Try another instruction.')
    if not all(isinstance(v, str) for v in result.values()):
        raise ValueError('Invalid AI draft.')
    tools.audit('AI_DRAFT_CREATED')
    return result


def analyze(data, *, request_verified=False):
    query = question(data, 'question')
    return security.inspect_and_analyze(data, query, demo.detect_threat, model,
                                        request_verified=request_verified)


class Handler(demo.Handler):
    def do_GET(self):
        if not self.path.startswith('/live'):
            return super().do_GET()
        if not self.trusted():
            return self.reply(403, {'error': 'Untrusted host or origin.'})
        paths = {'/live': ('index.html', 'text/html'), '/live/style.css': ('style.css', 'text/css'), '/live/app.js': ('app.js', 'text/javascript')}
        if self.path == '/live/state':
            return self.reply(200, {'token': demo.TOKEN, 'gmail_configured': tools.TOKEN_FILE.is_file(), 'model': demo.MODEL})
        if self.path in paths:
            filename, mime = paths[self.path]
            return self.reply(200, (STATIC / filename).read_bytes(), mime + '; charset=utf-8')
        return self.reply(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.path.startswith('/live/'):
            return super().do_POST()
        if not self.trusted() or self.headers.get('Origin') != f'http://{demo.HOST}:{demo.PORT}' or not secrets.compare_digest(self.headers.get('X-AgentShield-Token', ''), demo.TOKEN):
            return self.reply(403, {'error': 'Unauthorized local request.'})
        try:
            n = int(self.headers.get('Content-Length', '0'))
            limit = 6 * 1024 * 1024 if self.path == '/live/analyze' else 64000
            if not 0 < n <= limit or self.headers.get_content_type() != 'application/json':
                raise ValueError('Invalid request or size limit exceeded.')
            data = json.loads(self.rfile.read(n))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            routes = {'/live/draft': draft, '/live/analyze': analyze, '/live/prepare': tools.prepare, '/live/approve': tools.approve}
            if self.path not in routes:
                return self.reply(404, {'error': 'Not found.'})
            if self.path == '/live/analyze':
                return self.reply(200, analyze(data, request_verified=True))
            return self.reply(200, routes[self.path](data))
        except (ValueError, TypeError) as exc:
            return self.reply(400, {'error': str(exc)[:300]})
        except Exception:
            return self.reply(500, {'error': 'Operation failed. Check Ollama, document format or local setup. If sending, check Gmail Sent before retrying.'})


if __name__ == '__main__':
    print(f'Original dashboard: http://{demo.HOST}:{demo.PORT}/')
    print(f'Live workspace: http://{demo.HOST}:{demo.PORT}/live')
    with ThreadingHTTPServer((demo.HOST, demo.PORT), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


import os
import secrets
from datetime import timedelta

from flask import (
    Flask,
    request,
    jsonify,
    session,
    render_template
)

from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

from client_database import initialize_database, get_db

from client_auth import (
    register_user,
    login_user,
    logout_user,
    get_current_user,
    login_required
)

load_dotenv()

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.getenv("AGENTSHIELD_SECRET_KEY")
        or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=1024 * 1024
)

csrf = CSRFProtect(app)

initialize_database()


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return jsonify({
        "success": False,
        "message": "Invalid or expired security token."
    }), 400


@app.get("/")
@app.get("/")
def home():
    return render_template("client.html")


@app.get("/api/csrf")
def csrf_token():

    return jsonify({
        "csrf_token": generate_csrf()
    })


@app.post("/api/register")
def register():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid request."
        }), 400

    name = data.get("full_name", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not all(isinstance(v, str)
               for v in (name, email, password)):
        return jsonify({
            "success": False,
            "message": "Invalid account details."
        }), 400

    success, message = register_user(
        name, email, password
    )

    return jsonify({
        "success": success,
        "message": message
    }), 201 if success else 400


@app.post("/api/login")
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid request."
        }), 400

    email = data.get("email", "")
    password = data.get("password", "")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "success": False,
            "message": "Invalid credentials."
        }), 400

    success, result = login_user(email, password)

    if not success:
        return jsonify({
            "success": False,
            "message": result
        }), 401

    session.permanent = True

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": result,
        "csrf_token": generate_csrf()
    })


@app.post("/api/logout")
@login_required
def logout():

    logout_user()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


@app.get("/api/profile")
@login_required
def profile():

    return jsonify({
        "success": True,
        "user": get_current_user()
    })


@app.get("/api/dashboard")
@login_required
def dashboard():

    user = get_current_user()
    user_id = user["id"]

    with get_db() as conn:

        def count(query):
            return conn.execute(
                query, (user_id,)
            ).fetchone()[0]

        stats = {
            "total_tasks": count("""
                SELECT COUNT(*) FROM tasks
                WHERE user_id = ?
            """),

            "completed_tasks": count("""
                SELECT COUNT(*) FROM tasks
                WHERE user_id = ?
                AND status = 'COMPLETED'
            """),

            "blocked_tasks": count("""
                SELECT COUNT(*) FROM tasks
                WHERE user_id = ?
                AND security_decision = 'BLOCK'
            """),

            "pending_approvals": count("""
                SELECT COUNT(*) FROM approvals
                WHERE requested_by = ?
                AND status = 'PENDING'
            """),

            "documents": count("""
                SELECT COUNT(*) FROM documents
                WHERE user_id = ?
            """),

            "conversations": count("""
                SELECT COUNT(*) FROM conversations
                WHERE user_id = ?
            """),

            "workflows": count("""
                SELECT COUNT(*) FROM workflows
                WHERE user_id = ?
            """),

            "connected_services": count("""
                SELECT COUNT(*) FROM integrations
                WHERE user_id = ?
                AND connection_status = 'CONNECTED'
            """)
        }

    return jsonify({
        "success": True,
        "user": user,
        "statistics": stats
    })


@app.get("/api/tasks")
@login_required
def tasks():

    user = get_current_user()

    with get_db() as conn:
        rows = conn.execute("""
            SELECT *
            FROM tasks
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
        """, (user["id"],)).fetchall()

    return jsonify({
        "success": True,
        "tasks": [dict(row) for row in rows]
    })


@app.get("/api/documents")
@login_required
def documents():

    user = get_current_user()

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, filename, file_type,
                   sensitivity, file_size, created_at
            FROM documents
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
        """, (user["id"],)).fetchall()

    return jsonify({
        "success": True,
        "documents": [dict(row) for row in rows]
    })


@app.get("/api/health")
def health():

    try:
        with get_db() as conn:
            conn.execute("SELECT 1")

        return jsonify({
            "backend": "ONLINE",
            "database": "CONNECTED"
        })

    except Exception:
        return jsonify({
            "backend": "ONLINE",
            "database": "ERROR"
        }), 503


if __name__ == "__main__":

    print("=" * 60)
    print("AGENTSHIELD CLIENT APPLICATION V2.0")
    print("=" * 60)
    print("[OK] Flask backend initialized")
    print("[OK] SQLite database initialized")
    print("[OK] Authentication routes registered")
    print("[OK] Session management enabled")
    print("[OK] CSRF protection enabled")
    print("[OK] Dashboard API initialized")
    print("=" * 60)
    print("Server: http://127.0.0.1:5000")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

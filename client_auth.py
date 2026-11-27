
import re
import sqlite3

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask import session
from functools import wraps
from flask import jsonify

from client_database import get_db


def register_user(full_name, email, password):

    full_name = full_name.strip()
    email = email.strip().lower()

    if not full_name or len(full_name) > 100:
        return False, "Invalid full name."

    if len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return False, "Invalid email address."

    if len(password) < 12 or len(password) > 128:
        return False, "Password must contain 12–128 characters."

    password_hash = generate_password_hash(password)

    try:
        with get_db() as conn:

            conn.execute("""
                INSERT INTO users
                (full_name, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            """, (
                full_name,
                email,
                password_hash,
                "employee"
            ))

        return True, "Account created successfully."

    except sqlite3.IntegrityError:
        return False, "Account could not be created."


def authenticate_user(email, password):

    email = email.strip().lower()

    if len(password) > 128:
        return None

    with get_db() as conn:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE email = ?
            AND is_active = 1
        """, (email,)).fetchone()

    if user is None:
        return None

    if not check_password_hash(
        user["password_hash"], password
    ):
        return None

    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"]
    }


def login_user(email, password):

    user = authenticate_user(email, password)

    if user is None:
        return False, "Invalid email or password."

    session.clear()
    session["user_id"] = user["id"]

    return True, user


def logout_user():

    session.clear()

    return True


def get_current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    with get_db() as conn:

        user = conn.execute("""
            SELECT id, full_name, email, role
            FROM users
            WHERE id = ?
            AND is_active = 1
        """, (user_id,)).fetchone()

    if user is None:
        session.clear()
        return None

    return dict(user)


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if get_current_user() is None:
            return jsonify({
                "success": False,
                "message": "Authentication required."
            }), 401

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        user = get_current_user()

        if user is None:
            return jsonify({
                "success": False,
                "message": "Authentication required."
            }), 401

        if user["role"] != "admin":
            return jsonify({
                "success": False,
                "message": "Administrator access required."
            }), 403

        return function(*args, **kwargs)

    return wrapper


if __name__ == "__main__":

    print("=" * 50)
    print("AGENTSHIELD AUTHENTICATION MODULE")
    print("=" * 50)
    print("[OK] Registration module loaded")
    print("[OK] Password hashing module loaded")
    print("[OK] Authentication module loaded")
    print("[OK] Session management module loaded")
    print("[OK] Role-based access decorators loaded")
    print("=" * 50)

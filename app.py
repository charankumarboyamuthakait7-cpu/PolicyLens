"""PolicyLens application factory and configuration.

Run the development server with:   python app.py
Create tables and the first Admin:  python seed.py init

All secrets and settings come from the `.env` file (see `.env.example`).
"""
import logging
import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv
from flask import Flask, render_template, request

from models import db

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _env_int(name, default):
    """Read an integer environment variable, falling back to `default`."""
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


def _env_float(name, default):
    """Read a float environment variable, falling back to `default`."""
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


def _resolve(path_text, default):
    """Turn a configured folder into an absolute path (relative paths start at the project)."""
    p = Path(path_text or default)
    return str(p if p.is_absolute() else (BASE_DIR / p).resolve())


def _database_uri():
    """Build the MySQL connection string from the MYSQL_* variables."""
    user = quote_plus(os.getenv("MYSQL_USER", ""))
    password = quote_plus(os.getenv("MYSQL_PASSWORD", ""))
    host = os.getenv("MYSQL_HOST", "localhost")
    port = os.getenv("MYSQL_PORT", "3306")
    name = os.getenv("MYSQL_DATABASE", "policylens_db")
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{name}?charset=utf8mb4"


class Config:
    """Default configuration, read from environment variables."""

    SECRET_KEY = os.getenv("SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"  # set 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Files and vectors (persistent, configurable)
    UPLOAD_FOLDER = _resolve(os.getenv("UPLOAD_FOLDER"), "instance/uploads/documents")
    CHROMA_PERSIST_DIRECTORY = _resolve(os.getenv("CHROMA_PERSIST_DIRECTORY"), "instance/chroma")
    MAX_CONTENT_LENGTH = _env_int("MAX_CONTENT_LENGTH", 25 * 1024 * 1024)

    # AI services
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    
        # Email services (Password reset OTP)
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = _env_int("MAIL_PORT", 587)
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "")

    # Chunking: sizes are in WORDS (about 1.3 tokens per word)
    CHUNK_WORDS = _env_int("CHUNK_WORDS", 450)
    CHUNK_OVERLAP_WORDS = _env_int("CHUNK_OVERLAP_WORDS", 80)

    # Retrieval
    RAG_TOP_K = _env_int("RAG_TOP_K", 5)
    RAG_MIN_SIMILARITY = _env_float("RAG_MIN_SIMILARITY", 0.30)
    CHROMA_COLLECTION = "policylens_chunks"

    # Dates are stored in UTC and shown in this local time (330 minutes = India, IST)
    DISPLAY_UTC_OFFSET_MINUTES = _env_int("DISPLAY_UTC_OFFSET_MINUTES", 330)

    TESTING = False


def create_app(test_config=None):
    """Create and configure the Flask application.

    Args:
        test_config: optional dict that overrides `Config` (used by the tests).
    """
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    secret = app.config.get("SECRET_KEY", "")
    if not app.config["TESTING"] and (len(secret) < 32 or secret.lower().startswith("change")):
        raise RuntimeError(
            "SECRET_KEY is missing or too short. Generate one with: "
            'python -c "import secrets; print(secrets.token_hex(32))" and put it in .env'
        )

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    for folder in (app.config["UPLOAD_FOLDER"], app.config["CHROMA_PERSIST_DIRECTORY"]):
        os.makedirs(folder, exist_ok=True)

    db.init_app(app)

    from routes import bp  # imported here to avoid circular imports
    app.register_blueprint(bp)

    _register_error_handlers(app)
    _register_security_headers(app)
    return app


def _register_error_handlers(app):
    """Friendly error pages that never reveal internals."""

    def render_error(code, title, message):
        return render_template("errors/error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def bad_request(e):
        return render_error(400, "Bad request", getattr(e, "description", "The request was invalid."))

    @app.errorhandler(403)
    def forbidden(e):
        return render_error(403, "Access denied", "You do not have permission to do that.")

    @app.errorhandler(404)
    def not_found(e):
        return render_error(404, "Not found", "That page or document does not exist, or you cannot access it.")

    @app.errorhandler(413)
    def too_large(e):
        mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_error(413, "File too large", f"The upload is larger than the {mb} MB limit.")

    @app.errorhandler(429)
    def too_many(e):
        return render_error(429, "Too many attempts", "Please wait a few minutes and try again.")

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        app.logger.exception("Unhandled server error")
        return render_error(500, "Something went wrong", "The error was logged. Please try again.")


def _register_security_headers(app):
    """Add browser security headers (helps against XSS and clickjacking)."""

    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; frame-src 'self'; object-src 'self'; frame-ancestors 'self'"
    )

    @app.after_request
    def add_headers(resp):
        if resp.mimetype != "application/pdf":
            resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

if __name__ == "__main__":
    app = create_app()

    print("\n========== REGISTERED LOGIN ROUTES ==========")
    for rule in app.url_map.iter_rules():
        if "login" in rule.rule or "otp" in rule.rule:
            print(rule.rule, "->", rule.endpoint, rule.methods)

    app.run(host="127.0.0.1", port=5000, debug=False)

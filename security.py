"""Authentication, CSRF protection, login rate limiting and document authorization.

This module is the single place that decides WHO may see WHICH document. The RAG
code and every route call these functions, so the rule "unauthorized documents never
reach search, citations or the LLM" is enforced in one layer, in backend code.

Access rules (default):
  * Admin     - every document (view, ask, edit).
  * Others    - documents of their own department (view, ask), documents they uploaded
                (edit), plus any explicit grant in `document_permissions` made to them
                or to their department.
  * Archived documents are visible to Admin only.
"""
import hmac
import secrets
import threading
import time
from functools import wraps

from flask import abort, flash, g, redirect, request, session, url_for
from sqlalchemy import false, or_, select

from models import ROLE_ADMIN, Document, DocumentPermission, User, db

# --------------------------------------------------------------------------
# CSRF protection (token stored in the session, checked on every POST)
# --------------------------------------------------------------------------
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def csrf_token():
    """Return this session's CSRF token, creating it on first use."""
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def verify_csrf():
    """Abort with 400 if a state-changing request lacks a valid CSRF token."""
    if request.method in SAFE_METHODS:
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Your form expired or is invalid. Please reload the page and try again.")


# --------------------------------------------------------------------------
# Login rate limiting (in memory; resets when the server restarts)
# --------------------------------------------------------------------------
MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_failures = {}
_failures_lock = threading.Lock()


def _recent_failures(key):
    """Failure timestamps for `key` inside the current window (also prunes old ones)."""
    now = time.time()
    items = [t for t in _failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _failures[key] = items
    return items


def too_many_attempts(key):
    """True when `key` (ip + username) failed to log in too often recently."""
    with _failures_lock:
        return len(_recent_failures(key)) >= MAX_LOGIN_FAILURES


def record_failure(key):
    """Remember one failed login attempt."""
    with _failures_lock:
        _recent_failures(key).append(time.time())


def clear_failures(key):
    """Forget failures after a successful login."""
    with _failures_lock:
        _failures.pop(key, None)


def reset_rate_limits():
    """Clear all counters (used by the tests)."""
    with _failures_lock:
        _failures.clear()


# --------------------------------------------------------------------------
# Current user and route decorators
# --------------------------------------------------------------------------
def current_user():
    """Return the logged-in, active `User`, or None. Cached for the request."""
    if "_pl_user" in g:
        return g._pl_user
    user = None
    uid = session.get("user_id")
    if uid:
        candidate = db.session.get(User, uid)
        if candidate and candidate.is_active:
            user = candidate
        else:
            session.clear()  # deactivated or deleted: end the session immediately
    g._pl_user = user
    return user


def _safe_next(url):
    """Allow only same-site relative redirect targets (prevents open redirects)."""
    return url if url and url.startswith("/") and not url.startswith("//") else None


def login_required(view):
    """Require a logged-in active user."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("main.login", next=_safe_next(request.full_path.rstrip("?"))))
        return view(*args, **kwargs)

    return wrapper


def roles_required(*roles):
    """Require login AND one of the given roles. The role is read from the database."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user().role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


# --------------------------------------------------------------------------
# Document-level authorization
# --------------------------------------------------------------------------
def accessible_documents_query(user, need="view", include_archived=False):
    """Return a query of the documents `user` may access for `need`.

    Args:
        user: the `User`.
        need: "view", "ask" (use in AI retrieval / comparison) or "edit".
        include_archived: archived documents are only ever returned to Admin.
    """
    if need not in ("view", "ask", "edit"):
        raise ValueError("need must be 'view', 'ask' or 'edit'")
    query = Document.query
    if user.role == ROLE_ADMIN:
        if not include_archived:
            query = query.filter(Document.is_archived.is_(False))
        return query

    query = query.filter(Document.is_archived.is_(False))
    flag = {"view": DocumentPermission.can_view,
            "ask": DocumentPermission.can_ask,
            "edit": DocumentPermission.can_edit}[need]

    # Explicit grants to this user or to this user's department.
    grantee = [DocumentPermission.user_id == user.user_id]
    if user.department_id is not None:  # never compare to NULL: it would match user grants
        grantee.append(DocumentPermission.department_id == user.department_id)
    granted_ids = select(DocumentPermission.document_id).where(flag.is_(True), or_(*grantee))

    # Default rights.
    if need in ("view", "ask"):
        own = (Document.department_id == user.department_id) if user.department_id is not None else false()
    else:  # edit: only documents the user uploaded
        own = Document.uploaded_by == user.user_id
    return query.filter(or_(own, Document.document_id.in_(granted_ids)))


def authorized_document_ids(user, need="view", indexed_only=False):
    """List of document IDs `user` may access. Use this to filter search BEFORE retrieval."""
    query = accessible_documents_query(user, need)
    if indexed_only:
        query = query.filter(Document.status == "Indexed")
    return [row.document_id for row in query.with_entities(Document.document_id).all()]


def can_access_document(user, document, need="view"):
    """True if `user` may access `document` for `need` (re-check before every file access)."""
    if document is None:
        return False
    if document.is_archived and user.role != ROLE_ADMIN:
        return False
    return accessible_documents_query(user, need, include_archived=True) \
        .filter(Document.document_id == document.document_id).first() is not None


def get_authorized_document(doc_id, need="view"):
    """Load a document for the current user or abort with 404.

    404 (not 403) is used so that people cannot learn which documents exist.
    """
    user = current_user()
    document = db.session.get(Document, doc_id)
    if not user or not can_access_document(user, document, need):
        abort(404)
    return document


def can_upload(user):
    """Admins and Analysts may upload (Analysts only into their own department)."""
    return user is not None and user.role in (ROLE_ADMIN, "Analyst")
def can(user, permission):
    """Check whether a user has a named application permission."""
    if user is None:
        return False

    permissions = {
        "upload": can_upload(user),
        "admin": user.role == ROLE_ADMIN,
        "review": user.role in (ROLE_ADMIN, "Reviewer"),
        "analyze": user.role in (ROLE_ADMIN, "Analyst"),
    }

    return permissions.get(permission, False)
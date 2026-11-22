"""Business logic for PolicyLens.

Routes stay thin and call the functions here. Sections:

    1. Audit logging
    2. Users and departments (Admin)
    3. Documents: validation, storage, extraction, chunking, indexing
    4. Document permissions (Admin)
    5. Compliance rules, findings and the review workflow
    6. Dashboard statistics

Functions raise `ValidationError` with a message that is safe to show to the user.
Functions that change data call `db.session.commit()` themselves.
"""
import hashlib
import hmac
import io
import logging
import re
import os
import secrets
import string
import uuid
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from pathlib import Path

from flask import current_app, has_request_context, request
from sqlalchemy import func
from werkzeug.utils import secure_filename

import rag

from models import (
    DOCUMENT_TYPES, ROLE_ADMIN, ROLE_REVIEWER, ROLES, SEVERITIES,
    AnswerSource, AuditLog, ComplianceFinding, ComplianceRule, Department,
    Document, DocumentChunk, DocumentPermission, FindingComment, FindingHistory,
    LoginOTPToken, PasswordResetToken, Question, QuestionDocument, User,
    VectorIndex, db,
)

from security import accessible_documents_query, can ,can_access_document

log = logging.getLogger("policylens.services")


class ValidationError(Exception):
    """Raised for problems the user can fix. The message is shown to the user."""


class ProcessingError(Exception):
    """Raised when a PDF cannot be indexed. The message is stored as the safe error text."""


# ==========================================================================
# 1. Audit logging
# ==========================================================================
_SENSITIVE_KEYS = ("password", "secret", "token", "api_key", "apikey", "hash", "authorization")


def _clean_details(value):
    """Copy `value`, dropping secret-looking keys and truncating long text."""
    if isinstance(value, dict):
        return {k: _clean_details(v) for k, v in value.items()
                if not any(s in str(k).lower() for s in _SENSITIVE_KEYS)}
    if isinstance(value, (list, tuple)):
        return [_clean_details(v) for v in value][:50]
    if isinstance(value, str):
        return value[:500]
    return value


def audit(action, entity_type=None, entity_id=None, details=None, user=None):
    """Add an audit record to the session (the caller commits).

    Passwords, API keys and tokens are never stored.
    The caller should explicitly provide the acting user when available.
    """
    ip = request.remote_addr if has_request_context() else None

    db.session.add(AuditLog(
        user_id=user.user_id if user else None,
        action=action,
        entity_type=entity_type,
        entity_id=None if entity_id is None else str(entity_id),
        details=_clean_details(details) if details else None,
        ip_address=ip,
    ))


# ==========================================================================
# 2. Users and departments
# ==========================================================================
def validate_password(password):
    """Require at least 10 characters including a letter and a digit."""
    if len(password or "") < 10 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationError("Password must be at least 10 characters and contain letters and digits.")


def generate_password(length=14):
    """Create a random temporary password that satisfies `validate_password`."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw):
            return pw


def count_active_admins():
    """Number of active Admin accounts."""
    return User.query.filter_by(role=ROLE_ADMIN, is_active=True).count()


def _valid_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))


def create_user(actor, full_name, username, email, role, department_id, password):
    """Create a user (Admin only; the route enforces the role)."""
    full_name, username, email = (full_name or "").strip(), (username or "").strip(), (email or "").strip().lower()
    if not full_name or not username or not _valid_email(email):
        raise ValidationError("Enter a full name, a username and a valid email.")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,80}", username):
        raise ValidationError("Username may use letters, digits, dot, dash and underscore (3-80 characters).")
    if role not in ROLES:
        raise ValidationError("Role must be Admin, Analyst or Reviewer.")
    dept = db.session.get(Department, int(department_id)) if str(department_id or "").isdigit() else None
    if not dept or not dept.is_active:
        raise ValidationError("Choose an active department.")
    validate_password(password)
    if User.query.filter(func.lower(User.username) == username.lower()).first():
        raise ValidationError("That username is already taken.")
    if User.query.filter(func.lower(User.email) == email).first():
        raise ValidationError("That email already exists.")
    user = User(full_name=full_name, username=username, email=email, role=role,
                department_id=dept.department_id, is_active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    audit("user_created", "user", user.user_id, {"username": username, "role": role,
                                                 "department": dept.department_name}, user=actor)
    db.session.commit()
    return user


def update_user(actor, user, full_name, email, role, department_id, is_active):
    """Change a user's details, role, department or active flag (Admin only).

    Protects the last active Admin and stops admins changing their own role/status.
    """
    if role not in ROLES:
        raise ValidationError("Role must be Admin, Analyst or Reviewer.")
    dept = db.session.get(Department, int(department_id)) if str(department_id or "").isdigit() else None
    if not dept:
        raise ValidationError("Choose a department.")
    email = (email or "").strip().lower()
    if not (full_name or "").strip() or not _valid_email(email):
        raise ValidationError("Enter a full name and a valid email.")
    other = User.query.filter(func.lower(User.email) == email, User.user_id != user.user_id).first()
    if other:
        raise ValidationError("That email already exists.")
    if actor.user_id == user.user_id and (role != user.role or bool(is_active) != user.is_active):
        raise ValidationError("You cannot change your own role or active status.")
    losing_admin = user.role == ROLE_ADMIN and user.is_active and (role != ROLE_ADMIN or not is_active)
    if losing_admin and count_active_admins() <= 1:
        raise ValidationError("The last active Admin cannot be demoted or deactivated.")

    changes = {}
    for field, new in (("role", role), ("department", dept.department_id), ("is_active", bool(is_active))):
        old = {"role": user.role, "department": user.department_id, "is_active": user.is_active}[field]
        if old != new:
            changes[field] = {"from": old, "to": new}
    user.full_name, user.email, user.role = full_name.strip(), email, role
    user.department_id, user.is_active = dept.department_id, bool(is_active)
    audit("user_updated", "user", user.user_id, {"changes": changes}, user=actor)
    if "role" in changes:
        audit("role_changed", "user", user.user_id, changes["role"], user=actor)
    db.session.commit()
    
    
    
def delete_user(user_id, acting_user_id):
    """Delete a user, preventing self-deletion."""
    if user_id == acting_user_id:
        raise ValidationError("You cannot delete your own account.")

    user = db.session.get(User, user_id)

    if not user:
        raise ValidationError("User not found.")

    # Keep the user ID for the audit record.
    deleted_user_id = user.user_id

    audit(
        "user_deleted",
        "user",
        deleted_user_id,
        user=None,
    )

    db.session.delete(user)
    db.session.commit()

    return True


def reset_user_password(actor, user):
    """Give `user` a new random temporary password and return it (shown once to the Admin)."""
    temp = generate_password()
    user.set_password(temp)
    audit("password_reset", "user", user.user_id, user=actor)  # the password itself is never logged
    db.session.commit()
    return temp




# ==========================================================================
# 2.1 Password reset OTP
# ==========================================================================

def _otp_hash(otp):
    """Securely hash an OTP using HMAC-SHA256 and the application secret."""
    secret = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(
        secret,
        otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def _send_reset_email(email, otp):
    """Send a password-reset OTP through the configured SMTP server."""
    import smtplib
    from email.message import EmailMessage

    mail_server = current_app.config.get("MAIL_SERVER") or os.getenv("MAIL_SERVER", "")
    mail_port = int(current_app.config.get("MAIL_PORT") or os.getenv("MAIL_PORT", 587))
    mail_username = current_app.config.get("MAIL_USERNAME") or os.getenv("MAIL_USERNAME", "")
    mail_password = current_app.config.get("MAIL_PASSWORD") or os.getenv("MAIL_PASSWORD", "")
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or os.getenv("MAIL_DEFAULT_SENDER", mail_username)

    if not all([mail_server, mail_username, mail_password, sender]):
        raise RuntimeError("Email settings are not configured.")

    message = EmailMessage()
    message["Subject"] = "PolicyLens - Password Reset OTP"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"""Hello,

We received a request to reset your PolicyLens account password.

Your verification code is: {otp}

This code expires in 5 minutes.

If you did not request a password reset, you can ignore this email.

Regards,
Techtonic Solutions - PolicyLens
"""
    )

    with smtplib.SMTP(mail_server, mail_port, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)
        
        
        
def _send_login_otp_email(email, otp):
    """Send a login verification OTP through the configured SMTP server."""
    import smtplib
    from email.message import EmailMessage

    mail_server = current_app.config.get("MAIL_SERVER") or os.getenv("MAIL_SERVER", "")
    mail_port = int(current_app.config.get("MAIL_PORT") or os.getenv("MAIL_PORT", 587))
    mail_username = current_app.config.get("MAIL_USERNAME") or os.getenv("MAIL_USERNAME", "")
    mail_password = current_app.config.get("MAIL_PASSWORD") or os.getenv("MAIL_PASSWORD", "")
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or os.getenv("MAIL_DEFAULT_SENDER", mail_username)

    if not all([mail_server, mail_username, mail_password, sender]):
        raise RuntimeError("Email settings are not configured.")

    message = EmailMessage()
    message["Subject"] = "PolicyLens - Login Verification OTP"
    message["From"] = sender
    message["To"] = email

    message.set_content(
        f"""Hello,

Your PolicyLens login verification code is:

{otp}

This code expires in 5 minutes.
You have a maximum of 5 verification attempts.

If you did not attempt to sign in, you can ignore this email.

Regards,
Techtonic Solutions - PolicyLens
"""
    )

    with smtplib.SMTP(mail_server, mail_port, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


def request_password_reset(email):
    """Create and email an OTP. Returns False if the email is not registered."""
    email = (email or "").strip().lower()

    if not _valid_email(email):
        return False

    user = User.query.filter(func.lower(User.email) == email, User.is_active.is_(True)).first()
    if not user:
        return False

    now = datetime.utcnow()

    # Enforce a 60-second resend cooldown.
    latest = (PasswordResetToken.query
              .filter_by(user_id=user.user_id)
              .order_by(PasswordResetToken.created_at.desc())
              .first())

    if latest and (now - latest.created_at).total_seconds() < 60:
        raise ValidationError("Please wait 60 seconds before requesting another OTP.")

    # Invalidate any previous OTPs.
    PasswordResetToken.query.filter_by(user_id=user.user_id, is_used=False).update(
        {"is_used": True}, synchronize_session=False
    )

    otp = f"{secrets.randbelow(1000000):06d}"

    token = PasswordResetToken(
        user_id=user.user_id,
        otp_hash=_otp_hash(otp),
        expires_at=now + timedelta(minutes=5),
        attempts=0,
        is_used=False,
    )

    db.session.add(token)
    db.session.flush()

    audit(
        "password_reset_otp_requested",
        "user",
        user.user_id,
        user=None,
    )

    db.session.commit()

    try:
        _send_reset_email(user.email, otp)
    except Exception:
        log.exception("Failed to send password reset email.")
        token.is_used = True
        db.session.commit()
        raise ValidationError("We could not send the email. Please try again later.")

    return True


def request_login_otp(user):
    """Create and email a login OTP with a 60-second resend cooldown."""

    now = datetime.utcnow()

    latest = (
        LoginOTPToken.query
        .filter_by(user_id=user.user_id)
        .order_by(LoginOTPToken.created_at.desc())
        .first()
    )

    if latest and (now - latest.created_at).total_seconds() < 60:
        raise ValidationError("Please wait 60 seconds before requesting another code.")

    # Invalidate any previous unused login OTP.
    LoginOTPToken.query.filter_by(
        user_id=user.user_id,
        is_used=False,
    ).update(
        {"is_used": True},
        synchronize_session=False,
    )

    otp = f"{secrets.randbelow(1000000):06d}"

    token = LoginOTPToken(
        user_id=user.user_id,
        otp_hash=_otp_hash(otp),
        expires_at=now + timedelta(minutes=5),
        attempts=0,
        is_used=False,
    )

    db.session.add(token)
    db.session.commit()

    try:
        _send_login_otp_email(user.email, otp)
    except Exception:
        log.exception("Failed to send login OTP.")
        token.is_used = True
        db.session.commit()
        raise ValidationError("We could not send the verification email. Please try again later.")

    audit("login_otp_requested", "user", user.user_id, user=user)
    db.session.commit()

    return True


def verify_login_otp(user_id, otp):
    """Verify login OTP, enforcing expiry and a maximum of five attempts."""

    otp = (otp or "").strip()

    if not re.fullmatch(r"\d{6}", otp):
        raise ValidationError("Enter a valid 6-digit verification code.")

    now = datetime.utcnow()

    token = (
        LoginOTPToken.query
        .filter_by(user_id=user_id, is_used=False)
        .order_by(LoginOTPToken.created_at.desc())
        .first()
    )

    if not token:
        raise ValidationError("Verification code is invalid or expired. Request a new code.")

    if token.expires_at <= now:
        token.is_used = True
        db.session.commit()
        raise ValidationError("Verification code has expired. Request a new code.")

    if token.attempts >= 5:
        token.is_used = True
        db.session.commit()
        raise ValidationError("Maximum attempts reached. Request a new code.")

    token.attempts += 1

    if not hmac.compare_digest(token.otp_hash, _otp_hash(otp)):
        if token.attempts >= 5:
            token.is_used = True

        db.session.commit()
        raise ValidationError("Incorrect verification code.")

    token.is_used = True
    db.session.commit()

    audit("login_otp_verified", "user", user_id, user=db.session.get(User, user_id))
    db.session.commit()

    return True


def verify_password_reset_otp(email, otp):
    """Verify a reset OTP. Returns its reset_id on success, otherwise None."""
    email = (email or "").strip().lower()
    otp = (otp or "").strip()

    if not re.fullmatch(r"\d{6}", otp):
        return None

    user = User.query.filter(
        func.lower(User.email) == email,
        User.is_active.is_(True)
    ).first()

    if not user:
        return None

    token = (
        PasswordResetToken.query
        .filter_by(user_id=user.user_id, is_used=False, verified=False)
        .order_by(PasswordResetToken.created_at.desc())
        .first()
    )

    if not token:
        return None

    now = datetime.utcnow()

    if token.expires_at <= now:
        token.is_used = True
        db.session.commit()
        return None

    if token.attempts >= 5:
        token.is_used = True
        db.session.commit()
        return None

    if not secrets.compare_digest(token.otp_hash, _otp_hash(otp)):
        token.attempts += 1

        if token.attempts >= 5:
            token.is_used = True

        db.session.commit()
        return None

    # OTP is correct. Mark it as verified so it cannot be verified again.
    token.verified = True
    db.session.commit()

    return token.reset_id

def complete_password_reset(reset_id, email, new_password):
    """Set the new password only for the account whose email was verified."""
    validate_password(new_password)

    email = (email or "").strip().lower()

    token = db.session.get(PasswordResetToken, reset_id)

    if not token or token.is_used or not token.verified:
        raise ValidationError("Please verify your OTP before resetting your password.")

    if token.expires_at <= datetime.utcnow():
        token.is_used = True
        db.session.commit()
        raise ValidationError("Your OTP has expired. Please request a new code.")

    if token.attempts >= 5:
        token.is_used = True
        db.session.commit()
        raise ValidationError("Too many attempts. Please request a new OTP.")

    user = db.session.get(User, token.user_id)

    if not user or not user.is_active:
        raise ValidationError("This account is not available.")

    # Ensure the token belongs to the email verified in this session.
    if user.email.lower() != email:
        raise ValidationError("Password reset verification failed. Please start again.")

    user.set_password(new_password)
    token.is_used = True

    # Invalidate any other outstanding OTPs for this user.
    PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.user_id,
        PasswordResetToken.reset_id != token.reset_id,
        PasswordResetToken.is_used.is_(False),
    ).update({"is_used": True}, synchronize_session=False)

    audit("password_reset_completed", "user", user.user_id, user=None)
    db.session.commit()


def create_department(actor, name, description=""):
    """Create a department."""
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValidationError("Enter a department name (up to 120 characters).")
    if Department.query.filter(func.lower(Department.department_name) == name.lower()).first():
        raise ValidationError("A department with that name already exists.")
    dept = Department(department_name=name, description=(description or "").strip() or None)
    db.session.add(dept)
    db.session.flush()
    audit("department_created", "department", dept.department_id, {"name": name}, user=actor)
    db.session.commit()
    return dept


def update_department(actor, dept, name, description):
    """Rename a department or change its description."""
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValidationError("Enter a department name (up to 120 characters).")
    clash = Department.query.filter(func.lower(Department.department_name) == name.lower(),
                                    Department.department_id != dept.department_id).first()
    if clash:
        raise ValidationError("A department with that name already exists.")
    dept.department_name, dept.description = name, (description or "").strip() or None
    audit("department_updated", "department", dept.department_id, {"name": name}, user=actor)
    db.session.commit()


def set_department_active(actor, dept, active):
    """Activate or deactivate a department. Departments are never deleted.

    A department cannot be deactivated while it still has active users or live documents.
    """
    if not active:
        users = User.query.filter_by(department_id=dept.department_id, is_active=True).count()
        docs = Document.query.filter_by(department_id=dept.department_id, is_archived=False).count()
        if users or docs:
            raise ValidationError(
                f"{dept.department_name} still has {users} active user(s) and {docs} live document(s). "
                "Move or archive them first.")
    dept.is_active = bool(active)
    audit("department_activated" if active else "department_deactivated", "department",
          dept.department_id, {"name": dept.department_name}, user=actor)
    db.session.commit()


# ==========================================================================
# 3. Documents
# ==========================================================================
def storage_file_path(document):
    """Absolute path of a document's PDF. Refuses paths that escape the upload folder."""
    root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    path = (root / document.storage_path).resolve()
    if root != path and root not in path.parents:
        raise ProcessingError("Stored file path is invalid.")
    return path


def validate_pdf(file_storage, max_bytes):
    """Check an uploaded file and return `(bytes, page_count)`.

    Rejects: wrong extension, wrong signature, too large, corrupt, encrypted, zero pages.
    """
    name = (getattr(file_storage, "filename", "") or "").strip()
    if not name:
        raise ValidationError("Choose a PDF file to upload.")
    if not name.lower().endswith(".pdf"):
        raise ValidationError("Only PDF files are accepted.")
    data = file_storage.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValidationError(f"The file is larger than the {max_bytes // (1024 * 1024)} MB limit.")
    if not data.startswith(b"%PDF-"):
        raise ValidationError("The file is not a real PDF (wrong file signature).")
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ValidationError("Password-protected PDFs are not supported.")
        pages = len(reader.pages)
    except ValidationError:
        raise
    except Exception:
        raise ValidationError("The PDF is corrupt or cannot be read.")
    if pages < 1:
        raise ValidationError("The PDF has no pages.")
    return data, pages


def extract_pages(path):
    """Extract text page by page. Returns `[(page_number, text), ...]` with 1-based real page numbers."""
    try:
        try:
            import fitz  # PyMuPDF (preferred)
        except ImportError:
            fitz = None
        if fitz:
            with fitz.open(str(path)) as pdf:
                return [(i, page.get_text("text") or "") for i, page in enumerate(pdf, start=1)]
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        return [(i, page.extract_text() or "") for i, page in enumerate(reader.pages, start=1)]
    except Exception as exc:
        log.exception("PDF extraction failed")
        raise ProcessingError("The PDF text could not be extracted.") from exc


def estimate_tokens(text):
    """Rough token count (about 1.3 tokens per word)."""
    return int(len(text.split()) * 1.3) + 1


def chunk_text(text, max_words=450, overlap=80):
    """Split text into overlapping word windows.

    Args:
        max_words: words per chunk (450 words is about 585 tokens).
        overlap: words shared by neighbouring chunks (80 words is about 104 tokens).
    """
    words = text.split()
    if not words:
        return []
    if overlap >= max_words:
        overlap = max_words // 4
    step = max_words - overlap
    chunks, start = [], 0
    while start < len(words):
        chunks.append(" ".join(words[start:start + max_words]))
        if start + max_words >= len(words):
            break
        start += step
    return chunks


def chunk_pages(pages, max_words=450, overlap=80):
    """Chunk every page separately so a chunk never crosses a page (citations stay exact).

    Returns `[(page_number, chunk_text), ...]` in reading order.
    """
    out = []
    for page_number, text in pages:
        for piece in chunk_text(text, max_words, overlap):
            out.append((page_number, piece))
    return out


def _parse_date(value, label):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise ValidationError(f"{label} must be a valid date.")


def clean_metadata(form):
    """Validate the document metadata fields of an upload / edit form."""
    title = (form.get("title") or "").strip()
    number = (form.get("document_number") or "").strip()
    doc_type = (form.get("document_type") or "").strip()
    if not title or len(title) > 255:
        raise ValidationError("Enter a document title (up to 255 characters).")
    if not number or len(number) > 100:
        raise ValidationError("Enter a document number (up to 100 characters).")
    if doc_type not in DOCUMENT_TYPES:
        raise ValidationError("Document type must be Agreement or Policy.")
    effective = _parse_date(form.get("effective_date"), "Effective date")
    expiry = _parse_date(form.get("expiry_date"), "Expiry date")
    if effective and expiry and expiry < effective:
        raise ValidationError("Expiry date cannot be before the effective date.")
    return {
        "title": title, "document_number": number, "document_type": doc_type,
        "effective_date": effective, "expiry_date": expiry,
        "counterparty": (form.get("counterparty") or "").strip()[:255] or None,
        "description": (form.get("description") or "").strip() or None,
    }


def create_document(user, file_storage, meta, department_id, share_department_ids=()):
    """Validate, store and index an uploaded PDF. Returns the new `Document`.

    Analysts always upload into their own department; Admins pick any active department.
    A new upload with an existing document number becomes the next VERSION; the older
    version is archived and kept (never overwritten).
    """
    if not can_upload(user):
        raise ValidationError("You are not allowed to upload documents.")
    if user.role != ROLE_ADMIN:
        department_id = user.department_id
    dept = db.session.get(Department, int(department_id)) if str(department_id or "").isdigit() else None
    if not dept or not dept.is_active:
        raise ValidationError("Choose an active department.")

    data, page_count = validate_pdf(file_storage, current_app.config["MAX_CONTENT_LENGTH"])
    file_hash = hashlib.sha256(data).hexdigest()
    if Document.query.filter_by(file_hash=file_hash, is_archived=False).first():
        raise ValidationError("An identical file has already been uploaded.")

    previous = (Document.query.filter_by(department_id=dept.department_id,
                                         document_number=meta["document_number"])
                .order_by(Document.version_number.desc()).all())
    version = previous[0].version_number + 1 if previous else 1
    live_previous = [d for d in previous if not d.is_archived]
    if live_previous and not all(can_access_document(user, d, "edit") for d in live_previous):
        raise ValidationError("A document with this number already exists. Ask an Admin to upload a new version.")

    stored_name = f"{uuid.uuid4().hex}.pdf"
    path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_name
    path.write_bytes(data)
    try:
        original = secure_filename(file_storage.filename) or "document.pdf"
        doc = Document(
            title=meta["title"], document_number=meta["document_number"], document_type=meta["document_type"],
            department_id=dept.department_id, uploaded_by=user.user_id, original_filename=original[:255],
            stored_filename=stored_name, storage_path=stored_name, mime_type="application/pdf",
            file_size=len(data), file_hash=file_hash, page_count=page_count,
            effective_date=meta["effective_date"], expiry_date=meta["expiry_date"],
            counterparty=meta["counterparty"], description=meta["description"],
            status="Uploaded", version_number=version,
        )
        db.session.add(doc)
        db.session.flush()
        for old in live_previous:  # keep old versions, but out of search
            old.is_archived, old.status = True, "Archived"
            audit("document_archived", "document", old.document_id,
                  {"reason": f"superseded by version {version}"}, user=user)
        if user.role == ROLE_ADMIN:
            for dep_id in share_department_ids:
                if str(dep_id).isdigit() and int(dep_id) != dept.department_id \
                        and db.session.get(Department, int(dep_id)):
                    db.session.add(DocumentPermission(document_id=doc.document_id, department_id=int(dep_id),
                                                      can_view=True, can_ask=True, can_edit=False,
                                                      granted_by=user.user_id))
        audit("document_uploaded", "document", doc.document_id,
              {"title": doc.title, "version": version, "pages": page_count}, user=user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        path.unlink(missing_ok=True)
        raise
    process_document(doc.document_id, user)
    return db.session.get(Document, doc.document_id)


def process_document(document_id, actor=None):
    """Extract, chunk, embed and index a document. Safe to call again (re-processing).

    Order: text -> chunks in MySQL -> vectors in ChromaDB -> vector mappings in MySQL.
    A vector mapping is only written AFTER the vector was stored. On any failure the
    document is marked Failed with a safe message and partial vectors are removed.
    """
    doc = db.session.get(Document, document_id)
    doc.status, doc.processing_error = "Processing", None
    db.session.commit()
    try:
        pages = extract_pages(storage_file_path(doc))
        if sum(len(text.strip()) for _, text in pages) < 30:
            raise ProcessingError("No text could be extracted. This looks like a scanned PDF: OCR is required.")

        # Remove any earlier index of this document (re-processing).
        rag.delete_document_vectors(doc.document_id)
        VectorIndex.query.filter_by(document_id=doc.document_id).delete()
        DocumentChunk.query.filter_by(document_id=doc.document_id).delete()

        cfg = current_app.config
        rows = []
        for index, (page_number, piece) in enumerate(chunk_pages(pages, cfg["CHUNK_WORDS"], cfg["CHUNK_OVERLAP_WORDS"])):
            rows.append(DocumentChunk(
                document_id=doc.document_id, page_number=page_number, chunk_index=index,
                chunk_text=piece, token_count=estimate_tokens(piece),
                content_hash=hashlib.sha256(piece.encode("utf-8")).hexdigest()))
        db.session.add_all(rows)
        db.session.flush()  # assigns chunk_id values

        embedding_ids = rag.add_chunks(doc, rows)  # stores vectors in ChromaDB first
        for row in rows:
            db.session.add(VectorIndex(
                chunk_id=row.chunk_id, document_id=doc.document_id, vector_store="ChromaDB",
                collection_name=cfg["CHROMA_COLLECTION"], embedding_id=embedding_ids[row.chunk_id],
                embedding_model=cfg["EMBEDDING_MODEL"], index_status="Indexed"))
        doc.page_count = len(pages)
        doc.status = "Indexed"
        audit("document_indexed", "document", doc.document_id, {"chunks": len(rows)}, user=actor)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        message = str(exc) if isinstance(exc, ProcessingError) else \
            "Indexing failed. Check the server log, then use Reprocess."
        if not isinstance(exc, ProcessingError):
            log.exception("Indexing failed for document %s", document_id)
        try:
            rag.delete_document_vectors(document_id)  # drop any partly written vectors
        except Exception:
            log.exception("Vector cleanup failed for document %s", document_id)
        doc = db.session.get(Document, document_id)
        doc.status, doc.processing_error = "Failed", message[:1000]
        audit("document_index_failed", "document", document_id, {"error": message}, user=actor)
        db.session.commit()
    return db.session.get(Document, document_id)


def update_document_metadata(actor, doc, meta):
    """Edit a document's metadata (not the PDF itself)."""
    for key, value in meta.items():
        setattr(doc, key, value)
    audit("document_updated", "document", doc.document_id, {"title": doc.title}, user=actor)
    db.session.commit()


def archive_document(actor, doc):
    """Archive a document (kept in storage, hidden from search and from non-admins)."""
    doc.is_archived, doc.status = True, "Archived"
    audit("document_archived", "document", doc.document_id, {"title": doc.title}, user=actor)
    db.session.commit()


def restore_document(actor, doc):
    """Admin: bring an archived document back (status follows whether it is indexed)."""
    indexed = DocumentChunk.query.filter_by(document_id=doc.document_id).count() > 0
    doc.is_archived, doc.status = False, ("Indexed" if indexed else "Uploaded")
    audit("document_restored", "document", doc.document_id, {"title": doc.title}, user=actor)
    db.session.commit()


def purge_document(actor, doc):
    """Permanently delete a document: file, chunks, vectors, mappings and permissions.

    Refused when answers or findings still cite the document (archive it instead).
    """
    cited = (AnswerSource.query.filter_by(document_id=doc.document_id).count()
             + ComplianceFinding.query.filter_by(document_id=doc.document_id).count())
    if cited:
        raise ValidationError("This document is cited by answers or findings. Archive it instead.")
    path, doc_id, title = storage_file_path(doc), doc.document_id, doc.title
    rag.delete_document_vectors(doc_id)
    QuestionDocument.query.filter_by(document_id=doc_id).delete()
    VectorIndex.query.filter_by(document_id=doc_id).delete()
    DocumentChunk.query.filter_by(document_id=doc_id).delete()
    DocumentPermission.query.filter_by(document_id=doc_id).delete()
    db.session.delete(doc)
    audit("document_purged", "document", doc_id, {"title": title}, user=actor)
    db.session.commit()
    path.unlink(missing_ok=True)


# ==========================================================================
# 4. Document permissions
# ==========================================================================
def grant_permission(actor, doc, grantee_type, grantee_id, can_view, can_ask, can_edit):
    """Grant (or update) access to a document for one user or one department (Admin only)."""
    if grantee_type not in ("user", "department") or not str(grantee_id or "").isdigit():
        raise ValidationError("Choose who receives access.")
    grantee_id = int(grantee_id)
    if not (can_view or can_ask or can_edit):
        raise ValidationError("Select at least one permission.")
    if grantee_type == "user":
        grantee = db.session.get(User, grantee_id)
        existing = DocumentPermission.query.filter_by(document_id=doc.document_id, user_id=grantee_id).first()
        label = grantee.username if grantee else None
    else:
        grantee = db.session.get(Department, grantee_id)
        existing = DocumentPermission.query.filter_by(document_id=doc.document_id, department_id=grantee_id).first()
        label = grantee.department_name if grantee else None
    if not grantee:
        raise ValidationError("That user or department does not exist.")
    perm = existing or DocumentPermission(
        document_id=doc.document_id, granted_by=actor.user_id,
        user_id=grantee_id if grantee_type == "user" else None,
        department_id=grantee_id if grantee_type == "department" else None)
    # Asking and editing both imply viewing.
    perm.can_view, perm.can_ask, perm.can_edit = bool(can_view or can_ask or can_edit), bool(can_ask), bool(can_edit)
    perm.granted_by = actor.user_id
    db.session.add(perm)
    db.session.flush()
    audit("permission_granted", "document", doc.document_id,
          {"grantee_type": grantee_type, "grantee": label, "view": perm.can_view,
           "ask": perm.can_ask, "edit": perm.can_edit}, user=actor)
    db.session.commit()
    return perm


def revoke_permission(actor, permission_id):
    """Remove a grant. Access stops immediately because every request re-checks permissions."""
    perm = db.session.get(DocumentPermission, permission_id)
    if not perm:
        raise ValidationError("That permission no longer exists.")
    audit("permission_revoked", "document", perm.document_id,
          {"user_id": perm.user_id, "department_id": perm.department_id}, user=actor)
    db.session.delete(perm)
    db.session.commit()


# ==========================================================================
# 5. Compliance rules, findings and the review workflow
# ==========================================================================
def create_rule(actor, name, description, department_id, severity):
    """Create an internal compliance rule (Admin only)."""
    name, description = (name or "").strip(), (description or "").strip()
    if not name or not description:
        raise ValidationError("Enter a rule name and its requirement text.")
    if severity not in SEVERITIES:
        raise ValidationError("Choose a severity.")
    dept_id = int(department_id) if str(department_id or "").isdigit() else None
    if dept_id and not db.session.get(Department, dept_id):
        raise ValidationError("That department does not exist.")
    rule = ComplianceRule(rule_name=name[:255], description=description, department_id=dept_id,
                          severity=severity, created_by=actor.user_id)
    db.session.add(rule)
    db.session.flush()
    audit("rule_created", "compliance_rule", rule.rule_id, {"name": name}, user=actor)
    db.session.commit()
    return rule


def set_rule_active(actor, rule, active):
    """Activate or deactivate a rule."""
    rule.is_active = bool(active)
    audit("rule_activated" if active else "rule_deactivated", "compliance_rule", rule.rule_id, user=actor)
    db.session.commit()


def _finding_fields(user, data):
    """Validate the editable fields of a finding and return them as a dict."""
    title, description = (data.get("title") or "").strip(), (data.get("description") or "").strip()
    if not title or not description:
        raise ValidationError("Enter a title and a description.")
    severity = data.get("severity")
    if severity not in SEVERITIES:
        raise ValidationError("Choose a severity.")
    doc_id = int(data["document_id"]) if str(data.get("document_id") or "").isdigit() else None
    doc = db.session.get(Document, doc_id) if doc_id else None
    if not doc or not can_access_document(user, doc, "view"):
        raise ValidationError("Choose a document you can access.")
    page = None
    if str(data.get("page_number") or "").strip():
        if not str(data["page_number"]).strip().isdigit() or int(data["page_number"]) < 1:
            raise ValidationError("Page number must be a positive whole number.")
        page = int(data["page_number"])
        if doc.page_count and page > doc.page_count:
            raise ValidationError(f"That document only has {doc.page_count} pages.")
    rule_id = int(data["rule_id"]) if str(data.get("rule_id") or "").isdigit() else None
    if rule_id and not db.session.get(ComplianceRule, rule_id):
        raise ValidationError("That rule does not exist.")
    return {"title": title[:255], "description": description, "severity": severity,
            "document_id": doc.document_id, "page_number": page, "rule_id": rule_id,
            "evidence_text": (data.get("evidence_text") or "").strip() or None}


def _move(finding, actor, to_status, note=None):
    """Change a finding's status and record it in the review history."""
    db.session.add(FindingHistory(finding_id=finding.finding_id, actor_id=actor.user_id,
                                  from_status=finding.status, to_status=to_status,
                                  note=(note or "")[:500] or None))
    finding.status = to_status
    audit("finding_" + to_status.lower().replace(" ", "_"), "finding", finding.finding_id, user=actor)


def create_finding(user, data):
    """Create a Draft finding (Analyst)."""
    fields = _finding_fields(user, data)
    finding = ComplianceFinding(created_by=user.user_id, status="Draft", **fields)
    db.session.add(finding)
    db.session.flush()
    db.session.add(FindingHistory(finding_id=finding.finding_id, actor_id=user.user_id,
                                  from_status=None, to_status="Draft", note="Created"))
    audit("finding_created", "finding", finding.finding_id, {"title": finding.title}, user=user)
    db.session.commit()
    return finding


def update_finding(user, finding, data):
    """Edit a finding while it is a Draft or has Changes Requested (creator only)."""
    if finding.created_by != user.user_id or finding.status not in ("Draft", "Changes Requested"):
        raise ValidationError("This finding can no longer be edited.")
    for key, value in _finding_fields(user, data).items():
        setattr(finding, key, value)
    audit("finding_updated", "finding", finding.finding_id, user=user)
    db.session.commit()


def eligible_reviewers(finding):
    """Active Reviewers who may view the finding's document (and are not its creator)."""
    out = []
    for reviewer in User.query.filter_by(role=ROLE_REVIEWER, is_active=True).order_by(User.full_name).all():
        if reviewer.user_id != finding.created_by and can_access_document(reviewer, finding.document, "view"):
            out.append(reviewer)
    return out


def submit_finding(user, finding, reviewer_id):
    """Submit a Draft / Changes Requested finding to a Reviewer."""
    if finding.created_by != user.user_id or finding.status not in ("Draft", "Changes Requested"):
        raise ValidationError("Only the creator can submit a Draft or Changes Requested finding.")
    reviewer = db.session.get(User, int(reviewer_id)) if str(reviewer_id or "").isdigit() else None
    if reviewer not in eligible_reviewers(finding):
        raise ValidationError("Choose a Reviewer who has access to this document.")
    finding.assigned_reviewer_id = reviewer.user_id
    _move(finding, user, "Submitted", f"Submitted to {reviewer.full_name}")
    db.session.commit()


def reassign_reviewer(actor, finding, reviewer_id):
    """Admin: change the Reviewer of a finding that is waiting for review."""
    if finding.status not in ("Submitted", "In Review"):
        raise ValidationError("Only findings waiting for review can be reassigned.")
    reviewer = db.session.get(User, int(reviewer_id)) if str(reviewer_id or "").isdigit() else None
    if reviewer not in eligible_reviewers(finding):
        raise ValidationError("Choose a Reviewer who has access to this document.")
    finding.assigned_reviewer_id = reviewer.user_id
    db.session.add(FindingHistory(finding_id=finding.finding_id, actor_id=actor.user_id,
                                  from_status=finding.status, to_status=finding.status,
                                  note=f"Reassigned to {reviewer.full_name}"))
    audit("finding_reassigned", "finding", finding.finding_id, {"reviewer": reviewer.username}, user=actor)
    db.session.commit()


def _assert_assigned_reviewer(user, finding):
    """The decision maker must be the assigned Reviewer, not the creator, with document access."""
    if user.role != ROLE_REVIEWER or finding.assigned_reviewer_id != user.user_id:
        raise ValidationError("Only the assigned Reviewer can do this.")
    if finding.created_by == user.user_id:
        raise ValidationError("You cannot review your own finding.")
    if not can_access_document(user, finding.document, "view"):
        raise ValidationError("You do not have access to this finding's document.")


def start_review(user, finding):
    """Reviewer picks up a Submitted finding."""
    _assert_assigned_reviewer(user, finding)
    if finding.status != "Submitted":
        raise ValidationError("Only Submitted findings can be moved to In Review.")
    _move(finding, user, "In Review")
    db.session.commit()


DECISIONS = {"approve": "Approved", "reject": "Rejected", "request_changes": "Changes Requested"}


def decide_finding(user, finding, decision, comment):
    """Reviewer approves, rejects or requests changes (recorded with identity and time)."""
    _assert_assigned_reviewer(user, finding)
    if decision not in DECISIONS:
        raise ValidationError("Choose approve, reject or request changes.")
    if finding.status not in ("Submitted", "In Review"):
        raise ValidationError("This finding is not waiting for a decision.")
    comment = (comment or "").strip()
    if decision != "approve" and not comment:
        raise ValidationError("Add a comment explaining a rejection or a change request.")
    if comment:
        db.session.add(FindingComment(finding_id=finding.finding_id, user_id=user.user_id, comment_text=comment))
    _move(finding, user, DECISIONS[decision], comment[:500] if comment else None)
    db.session.commit()


def close_finding(user, finding):
    """Close a decided finding (Admin or its creator)."""
    if finding.status not in ("Approved", "Rejected"):
        raise ValidationError("Only Approved or Rejected findings can be closed.")
    if user.role != ROLE_ADMIN and finding.created_by != user.user_id:
        raise ValidationError("Only the creator or an Admin can close this finding.")
    _move(finding, user, "Closed")
    db.session.commit()


def can_view_finding(user, finding):
    """Admin sees all; the creator sees theirs; the assigned Reviewer sees assigned ones they can open."""
    if user.role == ROLE_ADMIN or finding.created_by == user.user_id:
        return True
    return (user.role == ROLE_REVIEWER and finding.assigned_reviewer_id == user.user_id
            and finding.status != "Draft" and can_access_document(user, finding.document, "view"))


def visible_findings_query(user):
    """Findings the user may list (before the per-document access check in `can_view_finding`)."""
    query = ComplianceFinding.query
    if user.role == ROLE_ADMIN:
        return query
    if user.role == ROLE_REVIEWER:
        return query.filter(ComplianceFinding.assigned_reviewer_id == user.user_id,
                            ComplianceFinding.status != "Draft")
    return query.filter(ComplianceFinding.created_by == user.user_id)


def add_comment(user, finding, text):
    """Add a comment (creator, assigned Reviewer or Admin)."""
    text = (text or "").strip()
    if not text:
        raise ValidationError("Write a comment first.")
    if not can_view_finding(user, finding):
        raise ValidationError("You cannot comment on this finding.")
    db.session.add(FindingComment(finding_id=finding.finding_id, user_id=user.user_id, comment_text=text))
    audit("finding_commented", "finding", finding.finding_id, user=user)
    db.session.commit()


# ==========================================================================
# 6. Dashboard statistics (all numbers come from the database)
# ==========================================================================
def dashboard_stats(user):
    """Return the numbers and lists for the role-specific dashboard."""
    docs = accessible_documents_query(user, "view")
    open_states = ("Draft", "Submitted", "In Review", "Changes Requested")
    stats = {
        "documents": docs.count(),
        "agreements": docs.filter(Document.document_type == "Agreement").count(),
        "policies": docs.filter(Document.document_type == "Policy").count(),
        "awaiting": docs.filter(Document.status.in_(("Uploaded", "Processing"))).count(),
        "failed": docs.filter(Document.status == "Failed").count(),
        "recent_uploads": docs.order_by(Document.created_at.desc()).limit(5).all(),
    }
    questions = Question.query if user.role == ROLE_ADMIN else Question.query.filter_by(user_id=user.user_id)
    stats["recent_questions"] = questions.order_by(Question.created_at.desc()).limit(5).all()
    findings = visible_findings_query(user)
    stats["open_findings"] = findings.filter(ComplianceFinding.status.in_(open_states)).count()
    stats["pending_reviews"] = (ComplianceFinding.query.filter_by(assigned_reviewer_id=user.user_id)
                                .filter(ComplianceFinding.status.in_(("Submitted", "In Review"))).count()
                                if user.role == ROLE_REVIEWER else 0)
    if user.role == ROLE_ADMIN:
        stats["users"] = User.query.count()
        stats["active_users"] = User.query.filter_by(is_active=True).count()
        stats["departments"] = Department.query.count()
        stats["audit_events"] = AuditLog.query.count()
        stats["by_department"] = (db.session.query(Department.department_name, func.count(Document.document_id))
                                  .outerjoin(Document, (Document.department_id == Department.department_id)
                                             & (Document.is_archived.is_(False)))
                                  .group_by(Department.department_name).order_by(Department.department_name).all())
        stats["activity"] = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
    else:
        stats["activity"] = (AuditLog.query.filter_by(user_id=user.user_id)
                             .order_by(AuditLog.created_at.desc()).limit(6).all())
    return stats

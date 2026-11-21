"""All web routes of PolicyLens (one Flask blueprint named "main").

Every route re-checks the user's role and the document permissions on the server;
hiding a menu item is never the only protection. Routes are thin: validation and
business rules live in `services.py`, search and answers live in `rag.py`.

Sections: auth, dashboard, documents, assistant and comparison, findings and review,
admin (users, departments, permissions, rules, audit, status).
"""
from datetime import datetime, timedelta

from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect, render_template,
    request, send_file, session, url_for,
)
from sqlalchemy import func, or_, text
from werkzeug.security import check_password_hash, generate_password_hash

import rag
import services
from models import (
    DOC_STATUSES, DOCUMENT_TYPES, FINDING_STATUSES, ROLE_ADMIN, ROLE_ANALYST, ROLE_REVIEWER, ROLES,
    SEVERITIES, AuditLog, ComplianceFinding, ComplianceRule, Department, Document, DocumentChunk,
    DocumentPermission, FindingHistory, Question, User, VectorIndex, db, utcnow,
)
from security import (
    accessible_documents_query, authorized_document_ids, can_access_document, can_upload,
    clear_failures, csrf_token, current_user, get_authorized_document, login_required,
    record_failure, roles_required, too_many_attempts, verify_csrf, _safe_next,
)
from services import ValidationError

bp = Blueprint("main", __name__)

# A password hash used to keep login timing similar when the username does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password")

STATUS_CLASS = {"Indexed": "g", "Processing": "b", "Uploaded": "b", "Failed": "r", "Archived": "n",
                "Draft": "n", "Submitted": "b", "In Review": "v", "Changes Requested": "a",
                "Approved": "g", "Rejected": "r", "Closed": "n"}
SEVERITY_CLASS = {"Low": "g", "Medium": "a", "High": "r", "Critical": "r"}


@bp.before_request
def _csrf_guard():
    """Check the CSRF token of every POST request."""
    verify_csrf()


@bp.record_once
def _register_jinja_globals(state):
    """Register helpers as Jinja *globals*.

    Macros imported with ``{% from ... import ... %}`` cannot see context-processor
    variables, so anything a macro uses (csrf_token, the pill colour maps) must be a global.
    """
    state.app.jinja_env.globals.update(
        csrf_token=csrf_token, STATUS_CLASS=STATUS_CLASS, SEVERITY_CLASS=SEVERITY_CLASS)


@bp.app_context_processor
def _template_context():
    """Per-request variables available in every template (not used inside macros)."""
    user = current_user()
    return {"user": user, "nav": nav_for(user)}


@bp.app_template_filter("dt")
def _format_datetime(value, with_time=True):
    """Show a stored UTC datetime in the configured local time (default India, IST)."""
    if not value:
        return "-"
    if isinstance(value, datetime):
        value = value + timedelta(minutes=current_app.config.get("DISPLAY_UTC_OFFSET_MINUTES", 330))
        return value.strftime("%d %b %Y %H:%M" if with_time else "%d %b %Y")
    return value.strftime("%d %b %Y")


def nav_for(user):
    """Sidebar entries for the user's role: list of (endpoint, label, icon)."""
    if not user:
        return []
    items = [("main.dashboard", "Dashboard", "dash"), ("main.documents", "Documents", "doc")]
    if can_upload(user):
        items.append(("main.upload", "Upload", "up"))
    items += [("main.assistant", "AI assistant", "chat"), ("main.compare", "Compare clauses", "cmp"),
              ("main.history", "Question history", "clock")]
    if user.role == ROLE_REVIEWER:
        items.append(("main.review_queue", "Review queue", "flag"))
    items.append(("main.findings", "Compliance findings", "flag"))
    if user.role == ROLE_ADMIN:
        items += [("main.users", "Users", "users"), ("main.departments", "Departments", "bld"),
                  ("main.permissions", "Permissions", "lock"), ("main.rules", "Compliance rules", "tag"),
                  ("main.audit_logs", "Audit history", "clock"), ("main.status", "System status", "set")]
    return items


def _warn(error):
    """Show a ValidationError to the user."""
    flash(str(error), "danger")


# ==========================================================================
# Authentication
# ==========================================================================

@bp.route("/login", methods=["GET", "POST"])
def login():
    """Validate credentials, then require email OTP before creating a session."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""

        key = f"{request.remote_addr}|{identifier.lower()}"

        if too_many_attempts(key):
            flash("Too many failed attempts. Please wait 15 minutes and try again.", "danger")
            return render_template("login.html"), 429

        candidate = User.query.filter(
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower()
            )
        ).first() if identifier else None

        if candidate and candidate.is_active and candidate.check_password(password):

            clear_failures(key)

            # Clear the old session to prevent session fixation.
            session.clear()

            # The user is NOT logged in yet. Store only pending OTP details.
            session["login_otp_user_id"] = candidate.user_id
            session["login_otp_next"] = _safe_next(request.args.get("next"))

            try:
                services.request_login_otp(candidate)

                flash("Your verification code has been sent to your registered email.", "info")
                return redirect(url_for("main.login_verify_otp"))

            except ValidationError as exc:
                session.pop("login_otp_user_id", None)
                session.pop("login_otp_next", None)
                flash(str(exc), "danger")

        else:
            if not candidate:
                check_password_hash(_DUMMY_HASH, password)

            record_failure(key)

            services.audit(
                "login_failed",
                "user",
                candidate.user_id if candidate else None,
                {"identifier": identifier[:80]}
            )
            db.session.commit()

            flash("Invalid username or password, or the account is inactive.", "danger")

    return render_template("login.html")




@bp.route("/login/verify-otp", methods=["GET", "POST"])
def login_verify_otp():
    print("========== LOGIN VERIFY OTP ROUTE HIT ==========")
    """Verify the login OTP and only then authenticate the user."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    pending_user_id = session.get("login_otp_user_id")

    if not pending_user_id:
        return redirect(url_for("main.login"))

    user = db.session.get(User, pending_user_id)

    if not user or not user.is_active:
        session.pop("login_otp_user_id", None)
        session.pop("login_otp_next", None)
        flash("Login verification expired. Please log in again.", "warning")
        return redirect(url_for("main.login"))

    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()

        try:
            services.verify_login_otp(user.user_id, otp)

            next_url = session.get("login_otp_next")

            session.clear()
            session["user_id"] = user.user_id
            session.permanent = True

            user.last_login_at = utcnow()

            services.audit("login", "user", user.user_id, user=user)
            db.session.commit()

            flash("Login successful. Welcome to PolicyLens!", "success")
            return redirect(next_url or url_for("main.dashboard"))

        except ValidationError as exc:
            flash(str(exc), "danger")

    return render_template("login_verify_otp.html", email=user.email)



@bp.route("/login/resend-otp", methods=["POST"])
def login_resend_otp():
    """Resend the login OTP to the pending user's registered email."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    pending_user_id = session.get("login_otp_user_id")

    if not pending_user_id:
        flash("Your login verification session has expired. Please log in again.", "warning")
        return redirect(url_for("main.login"))

    user = db.session.get(User, pending_user_id)

    if not user or not user.is_active:
        session.pop("login_otp_user_id", None)
        session.pop("login_otp_next", None)
        flash("This account is unavailable. Please log in again.", "danger")
        return redirect(url_for("main.login"))

    try:
        services.request_login_otp(user)
        flash("A new verification code has been sent to your email.", "success")

    except ValidationError as exc:
        flash(str(exc), "warning")

    return redirect(url_for("main.login_verify_otp"))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """End the session."""
    services.audit("logout", "user", current_user().user_id)
    db.session.commit()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.login"))



# ==========================================================================
# Authentication: Forgot password / OTP reset
# ==========================================================================

@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request a password-reset OTP through the registered email address."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        # Start a fresh password-reset flow.
        session.pop("pw_reset_email", None)
        session.pop("pw_reset_id", None)

        try:
            services.request_password_reset(email)
        except ValidationError:
            # Avoid revealing whether an account exists.
            pass

        # Use the same response for registered and unregistered emails.
        session["pw_reset_email"] = email
        flash("If the email is registered, a verification code has been sent.", "info")
        return redirect(url_for("main.verify_otp"))

    return render_template("forgot_password.html")


@bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if current_user():
        return redirect(url_for("main.dashboard"))

    email = session.get("pw_reset_email")

    if not email:
        return redirect(url_for("main.forgot_password"))

    if request.method == "POST":
        otp = (request.form.get("otp") or "").strip()

        try:
            reset_id = services.verify_password_reset_otp(email, otp)

            if not reset_id:
                flash(
                    "Invalid or expired verification code. Please try again.",
                    "danger"
                )
            else:
                session["pw_reset_id"] = reset_id

                flash(
                    "Email verified. You can now set your new password.",
                    "success"
                )

                return redirect(url_for("main.reset_password"))

        except ValidationError as exc:
            flash(str(exc), "danger")

    return render_template("verify_otp.html", email=email)


@bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Set a new password after successful OTP verification."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    reset_id = session.get("pw_reset_id")
    email = session.get("pw_reset_email")

    # Both the verified reset ID and email must exist in the session.
    if not reset_id or not email:
        session.pop("pw_reset_id", None)
        session.pop("pw_reset_email", None)
        return redirect(url_for("main.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            try:
                services.complete_password_reset(reset_id, email, password)

                # Clear reset information after successful password change.
                session.pop("pw_reset_email", None)
                session.pop("pw_reset_id", None)

                flash("Password changed successfully. Please log in.", "success")
                return redirect(url_for("main.login"))

            except ValidationError as exc:
                flash(str(exc), "danger")

                # If the reset token is invalid, expired or already used,
                # restart the reset flow.
                if "expired" in str(exc).lower() or "verify" in str(exc).lower():
                    session.pop("pw_reset_id", None)
                    return redirect(url_for("main.forgot_password"))

    return render_template("reset_password.html")


@bp.route("/")
@login_required
def dashboard():
    """Role-specific dashboard. Every number comes from the database."""
    user = current_user()
    return render_template("dashboard.html", stats=services.dashboard_stats(user))


# ==========================================================================
# Documents
# ==========================================================================
def _parse_filter_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d") if value else None
    except ValueError:
        return None


@bp.route("/documents")
@login_required
def documents():
    """Document repository with search, filters and pagination (only authorized documents)."""
    user = current_user()
    show_archived = user.role == ROLE_ADMIN and request.args.get("archived") == "1"
    query = accessible_documents_query(user, "view", include_archived=show_archived)

    term = (request.args.get("q") or "").strip()
    if term:
        like = f"%{term}%"
        query = query.filter(or_(Document.title.ilike(like), Document.document_number.ilike(like),
                                 Document.counterparty.ilike(like)))
    if request.args.get("department", "").isdigit():
        query = query.filter(Document.department_id == int(request.args["department"]))
    if request.args.get("type") in DOCUMENT_TYPES:
        query = query.filter(Document.document_type == request.args["type"])
    if request.args.get("status") in DOC_STATUSES:
        query = query.filter(Document.status == request.args["status"])
    if request.args.get("uploader", "").isdigit():
        query = query.filter(Document.uploaded_by == int(request.args["uploader"]))
    start, end = _parse_filter_date(request.args.get("from")), _parse_filter_date(request.args.get("to"))
    if start:
        query = query.filter(Document.created_at >= start)
    if end:
        query = query.filter(Document.created_at < end + timedelta(days=1))

    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(Document.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    base = accessible_documents_query(user, "view", include_archived=show_archived)
    dept_ids = [r[0] for r in base.with_entities(Document.department_id).distinct().all()]
    uploader_ids = [r[0] for r in base.with_entities(Document.uploaded_by).distinct().all()]
    return render_template(
        "documents.html", pagination=pagination, show_archived=show_archived,
        departments=Department.query.filter(Department.department_id.in_(dept_ids)).order_by(Department.department_name).all(),
        uploaders=User.query.filter(User.user_id.in_(uploader_ids)).order_by(User.full_name).all(),
        doc_types=DOCUMENT_TYPES, statuses=DOC_STATUSES, args=request.args)


@bp.route("/documents/upload", methods=["GET", "POST"])
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def upload():
    """Upload a PDF; it is stored, extracted, chunked, embedded and indexed."""
    user = current_user()
    if user.role == ROLE_ADMIN:
        departments = Department.query.filter_by(is_active=True).order_by(Department.department_name).all()
    else:
        departments = [user.department] if user.department and user.department.is_active else []
    if request.method == "POST":
        try:
            meta = services.clean_metadata(request.form)
            doc = services.create_document(
                user, request.files.get("file"), meta, request.form.get("department_id"),
                request.form.getlist("share_department_ids") if user.role == ROLE_ADMIN else [])
        except ValidationError as exc:
            _warn(exc)
        else:
            if doc.status == "Indexed":
                flash(f"'{doc.title}' (version {doc.version_number}) was uploaded and indexed.", "success")
            else:
                flash(f"'{doc.title}' was saved but indexing failed: {doc.processing_error}", "warning")
            return redirect(url_for("main.document_view", doc_id=doc.document_id))
    return render_template("upload.html", departments=departments, doc_types=DOCUMENT_TYPES,
                           form=request.form, max_mb=current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024))


@bp.route("/documents/<int:doc_id>")
@login_required
def document_view(doc_id):
    """Document details with an in-page PDF preview."""
    user = current_user()
    doc = get_authorized_document(doc_id, "view")
    versions = [d for d in Document.query.filter_by(department_id=doc.department_id,
                                                    document_number=doc.document_number)
                .order_by(Document.version_number.desc()).all() if can_access_document(user, d, "view")]
    return render_template(
        "document_detail.html", doc=doc, versions=versions,
        chunk_count=DocumentChunk.query.filter_by(document_id=doc.document_id).count(),
        vector_count=VectorIndex.query.filter_by(document_id=doc.document_id).count(),
        can_edit=can_access_document(user, doc, "edit"), doc_types=DOCUMENT_TYPES)


def _send_pdf(doc_id, as_attachment):
    """Re-check permission, then stream the stored PDF. The server path is never exposed."""
    doc = get_authorized_document(doc_id, "view")
    path = services.storage_file_path(doc)
    if not path.is_file():
        abort(404)
    if as_attachment:
        services.audit("document_downloaded", "document", doc.document_id, {"title": doc.title})
        db.session.commit()
    name = (doc.original_filename or f"document-{doc.document_id}.pdf")
    return send_file(path, mimetype="application/pdf", as_attachment=as_attachment, download_name=name)


@bp.route("/documents/<int:doc_id>/file")
@login_required
def document_file(doc_id):
    """Inline PDF for the preview frame."""
    return _send_pdf(doc_id, as_attachment=False)


@bp.route("/documents/<int:doc_id>/download")
@login_required
def document_download(doc_id):
    """PDF download (audited)."""
    return _send_pdf(doc_id, as_attachment=True)


@bp.route("/documents/<int:doc_id>/edit", methods=["POST"])
@login_required
def document_edit(doc_id):
    """Edit document metadata (needs edit permission)."""
    doc = get_authorized_document(doc_id, "edit")
    try:
        services.update_document_metadata(current_user(), doc, services.clean_metadata(request.form))
        flash("Document details saved.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.document_view", doc_id=doc_id))


@bp.route("/documents/<int:doc_id>/archive", methods=["POST"])
@login_required
def document_archive(doc_id):
    """Archive a document (needs edit permission)."""
    doc = get_authorized_document(doc_id, "edit")
    services.archive_document(current_user(), doc)
    flash("Document archived. It is hidden from search but kept in storage.", "success")
    return redirect(url_for("main.documents"))


@bp.route("/documents/<int:doc_id>/restore", methods=["POST"])
@roles_required(ROLE_ADMIN)
def document_restore(doc_id):
    """Admin: restore an archived document."""
    doc = get_authorized_document(doc_id, "view")
    services.restore_document(current_user(), doc)
    flash("Document restored.", "success")
    return redirect(url_for("main.document_view", doc_id=doc_id))


@bp.route("/documents/<int:doc_id>/reprocess", methods=["POST"])
@login_required
def document_reprocess(doc_id):
    """Re-run extraction and indexing (needs edit permission)."""
    doc = get_authorized_document(doc_id, "edit")
    if doc.is_archived:
        flash("Restore the document before reprocessing it.", "warning")
    else:
        doc = services.process_document(doc.document_id, current_user())
        flash("Indexing finished." if doc.status == "Indexed" else f"Indexing failed: {doc.processing_error}",
              "success" if doc.status == "Indexed" else "danger")
    return redirect(url_for("main.document_view", doc_id=doc_id))


# ==========================================================================
# AI assistant, comparison and question history
# ==========================================================================
def _askable_documents(user):
    """Indexed documents the user may ask about (also the scope choices on screen)."""
    return (accessible_documents_query(user, "ask").filter(Document.status == "Indexed")
            .order_by(Document.title).all())


@bp.route("/assistant")
@login_required
def assistant():
    """Chat page. Questions are sent to `assistant_ask` with fetch()."""
    user = current_user()
    docs = _askable_documents(user)
    departments = {d.department_id: d.department.department_name for d in docs}
    return render_template("assistant.html", docs=docs, departments=sorted(departments.items(), key=lambda x: x[1]),
                           llm_ready=bool(current_app.config["GROQ_API_KEY"]))


@bp.route("/assistant/ask", methods=["POST"])
@login_required
def assistant_ask():
    """Answer a question as JSON (permission filtering happens inside `rag.ask_question`)."""
    data = request.get_json(silent=True) or {}
    selected = [i for i in data.get("document_ids", []) if str(i).isdigit()]
    department = data.get("department_id") if str(data.get("department_id", "")).isdigit() else None
    result = rag.ask_question(current_user(), data.get("question"), selected, department)
    return jsonify(result), (400 if result.get("error") and "answer" not in result else 200)


@bp.route("/compare")
@login_required
def compare():
    """Clause comparison page (2 to 5 documents)."""
    return render_template("comparison.html", docs=_askable_documents(current_user()),
                           llm_ready=bool(current_app.config["GROQ_API_KEY"]))


@bp.route("/compare/run", methods=["POST"])
@login_required
def compare_run():
    """Compare a topic across the selected documents and return JSON."""
    data = request.get_json(silent=True) or {}
    result = rag.compare_documents(current_user(), data.get("document_ids", []), data.get("topic"))
    return jsonify(result), (400 if result.get("error") else 200)


@bp.route("/history")
@login_required
def history():
    """Personal question history (Admin sees everyone's). Citations to documents the user can
    no longer open are hidden."""
    user = current_user()
    query = Question.query if user.role == ROLE_ADMIN else Question.query.filter_by(user_id=user.user_id)
    pagination = query.order_by(Question.created_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    viewable = None if user.role == ROLE_ADMIN else set(authorized_document_ids(user, "view"))
    return render_template("history.html", pagination=pagination, viewable=viewable)


# ==========================================================================
# Compliance findings and the review queue
# ==========================================================================
def _finding_or_404(finding_id):
    """Load a finding the current user may see, else 404."""
    finding = db.session.get(ComplianceFinding, finding_id)
    if not finding or not services.can_view_finding(current_user(), finding):
        abort(404)
    return finding


@bp.route("/findings")
@login_required
def findings():
    """Findings the user may see: own (Analyst), assigned (Reviewer), all (Admin)."""
    user = current_user()
    query = services.visible_findings_query(user)
    if request.args.get("status") in FINDING_STATUSES:
        query = query.filter(ComplianceFinding.status == request.args["status"])
    pagination = query.order_by(ComplianceFinding.updated_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=15, error_out=False)
    return render_template("findings.html", pagination=pagination, statuses=FINDING_STATUSES,
                           current_status=request.args.get("status", ""))


@bp.route("/findings/new", methods=["GET", "POST"])
@roles_required(ROLE_ANALYST)
def finding_new():
    """Create a Draft finding (Analyst)."""
    user = current_user()
    if request.method == "POST":
        try:
            finding = services.create_finding(user, request.form)
        except ValidationError as exc:
            _warn(exc)
        else:
            flash("Finding saved as a Draft. Submit it to a Reviewer when it is ready.", "success")
            return redirect(url_for("main.finding_view", finding_id=finding.finding_id))
    docs = accessible_documents_query(user, "view").order_by(Document.title).all()
    rules = ComplianceRule.query.filter(ComplianceRule.is_active.is_(True),
                                        or_(ComplianceRule.department_id.is_(None),
                                            ComplianceRule.department_id == user.department_id)).all()
    return render_template("finding_form.html", docs=docs, rules=rules, severities=SEVERITIES,
                           form=request.form, finding=None)


@bp.route("/findings/<int:finding_id>")
@login_required
def finding_view(finding_id):
    """Finding details, evidence, comments and review history."""
    user = current_user()
    finding = _finding_or_404(finding_id)
    editing = request.args.get("edit") == "1" and finding.created_by == user.user_id \
        and finding.status in ("Draft", "Changes Requested")
    reviewers = services.eligible_reviewers(finding) if (
        (finding.created_by == user.user_id and finding.status in ("Draft", "Changes Requested"))
        or (user.role == ROLE_ADMIN and finding.status in ("Submitted", "In Review"))) else []
    docs = rules = None
    if editing:
        docs = accessible_documents_query(user, "view").order_by(Document.title).all()
        rules = ComplianceRule.query.filter_by(is_active=True).all()
    return render_template("finding_detail.html", finding=finding, reviewers=reviewers, editing=editing,
                           docs=docs, rules=rules, severities=SEVERITIES, form=finding)


def _finding_action(finding_id, action, success):
    """Run a service call on a finding, flash the result and return to the finding page."""
    finding = _finding_or_404(finding_id)
    try:
        action(current_user(), finding)
        flash(success, "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.finding_view", finding_id=finding_id))


@bp.route("/findings/<int:finding_id>/edit", methods=["POST"])
@login_required
def finding_edit(finding_id):
    """Save changes to a Draft / Changes Requested finding."""
    return _finding_action(finding_id, lambda u, f: services.update_finding(u, f, request.form),
                           "Finding updated.")


@bp.route("/findings/<int:finding_id>/submit", methods=["POST"])
@login_required
def finding_submit(finding_id):
    """Submit the finding to a chosen Reviewer."""
    return _finding_action(finding_id,
                           lambda u, f: services.submit_finding(u, f, request.form.get("reviewer_id")),
                           "Finding submitted for review.")


@bp.route("/findings/<int:finding_id>/start", methods=["POST"])
@login_required
def finding_start(finding_id):
    """Reviewer starts reviewing."""
    return _finding_action(finding_id, services.start_review, "Review started.")


@bp.route("/findings/<int:finding_id>/decide", methods=["POST"])
@login_required
def finding_decide(finding_id):
    """Reviewer approves, rejects or requests changes."""
    return _finding_action(
        finding_id,
        lambda u, f: services.decide_finding(u, f, request.form.get("decision"), request.form.get("comment")),
        "Decision recorded.")


@bp.route("/findings/<int:finding_id>/comment", methods=["POST"])
@login_required
def finding_comment(finding_id):
    """Add a comment."""
    return _finding_action(finding_id, lambda u, f: services.add_comment(u, f, request.form.get("comment")),
                           "Comment added.")


@bp.route("/findings/<int:finding_id>/close", methods=["POST"])
@login_required
def finding_close(finding_id):
    """Close an approved or rejected finding."""
    return _finding_action(finding_id, services.close_finding, "Finding closed.")


@bp.route("/findings/<int:finding_id>/reassign", methods=["POST"])
@roles_required(ROLE_ADMIN)
def finding_reassign(finding_id):
    """Admin: change the assigned Reviewer."""
    return _finding_action(finding_id,
                           lambda u, f: services.reassign_reviewer(u, f, request.form.get("reviewer_id")),
                           "Reviewer reassigned.")


@bp.route("/review")
@roles_required(ROLE_REVIEWER)
def review_queue():
    """Reviewer queue: findings assigned to me that wait for a decision, plus my decisions."""
    user = current_user()
    pending = [f for f in ComplianceFinding.query
               .filter(ComplianceFinding.assigned_reviewer_id == user.user_id,
                       ComplianceFinding.status.in_(("Submitted", "In Review")))
               .order_by(ComplianceFinding.updated_at).all() if services.can_view_finding(user, f)]
    decided = (FindingHistory.query.filter(FindingHistory.actor_id == user.user_id,
                                           FindingHistory.to_status.in_(("Approved", "Rejected", "Changes Requested")))
               .order_by(FindingHistory.created_at.desc()).limit(20).all())
    return render_template("review_queue.html", pending=pending, decided=decided)


# ==========================================================================
# Admin: users, departments, permissions, rules, audit, status
# ==========================================================================
def _users_context(**extra):
    """Template data for the Users page."""
    term = (request.args.get("q") or "").strip()
    query = User.query
    if term:
        like = f"%{term}%"
        query = query.filter(or_(User.full_name.ilike(like), User.username.ilike(like), User.email.ilike(like)))
    return dict(users=query.order_by(User.full_name).all(), roles=ROLES, term=term,
                departments=Department.query.filter_by(is_active=True).order_by(Department.department_name).all(),
                all_departments=Department.query.order_by(Department.department_name).all(), **extra)


@bp.route("/admin/users",methods=["GET", "POST"])
@roles_required(ROLE_ADMIN)
def users():
    """User management."""
    return render_template("users.html", **_users_context(temp=None))


@bp.route("/admin/users/create", methods=["POST"])
@roles_required(ROLE_ADMIN)
def user_create():
    """Create a user account (there is no public registration)."""
    f = request.form
    try:
        created = services.create_user(current_user(), f.get("full_name"), f.get("username"), f.get("email"),
                                       f.get("role"), f.get("department_id"), f.get("password"))
        flash(f"User '{created.username}' created.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.users"))


@bp.route("/admin/users/<int:user_id>/update", methods=["POST"])
@roles_required(ROLE_ADMIN)
def user_update(user_id):
    """Change role, department, details or active status."""
    target = db.get_or_404(User, user_id)
    f = request.form
    try:
        services.update_user(current_user(), target, f.get("full_name"), f.get("email"), f.get("role"),
                             f.get("department_id"), f.get("is_active") == "1")
        flash(f"{target.username} updated.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.users"))


# PASTE THE NEW ADMIN RESET PASSWORD ROUTE HERE
@bp.route("/admin/users/<int:user_id>/reset-password", methods=["GET", "POST"])
@roles_required(ROLE_ADMIN)
def admin_reset_password(user_id):
    """Allow an Admin to reset another user's password."""
    target = db.get_or_404(User, user_id)

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("admin_reset_password.html", target=target)

        try:
            services.validate_password(password)
            target.set_password(password)

            services.audit(
                "admin_password_reset",
                "user",
                target.user_id,
                {"username": target.username},
                user=current_user()
            )

            db.session.commit()

            flash(f"Password reset successfully for {target.username}.", "success")
            return redirect(url_for("main.users"))

        except ValidationError as exc:
            db.session.rollback()
            flash(str(exc), "danger")

    return render_template("admin_reset_password.html", target=target)


@bp.route("/admin/departments")
@roles_required(ROLE_ADMIN)
def departments():
    """Department management with user and document counts."""
    rows = []
    for dept in Department.query.order_by(Department.department_name).all():
        rows.append({"dept": dept,
                     "users": User.query.filter_by(department_id=dept.department_id).count(),
                     "docs": Document.query.filter_by(department_id=dept.department_id).count()})
    return render_template("departments.html", rows=rows)


@bp.route("/admin/departments/create", methods=["POST"])
@roles_required(ROLE_ADMIN)
def department_create():
    """Create a department."""
    try:
        services.create_department(current_user(), request.form.get("name"), request.form.get("description"))
        flash("Department created.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.departments"))


@bp.route("/admin/departments/<int:dept_id>/update", methods=["POST"])
@roles_required(ROLE_ADMIN)
def department_update(dept_id):
    """Rename a department."""
    dept = db.get_or_404(Department, dept_id)
    try:
        services.update_department(current_user(), dept, request.form.get("name"), request.form.get("description"))
        flash("Department updated.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.departments"))


@bp.route("/admin/departments/<int:dept_id>/toggle", methods=["POST"])
@roles_required(ROLE_ADMIN)
def department_toggle(dept_id):
    """Activate or deactivate a department."""
    dept = db.get_or_404(Department, dept_id)
    try:
        services.set_department_active(current_user(), dept, not dept.is_active)
        flash("Department status changed.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.departments"))


@bp.route("/admin/permissions")
@roles_required(ROLE_ADMIN)
def permissions():
    """View, grant and revoke document permissions."""
    return render_template(
        "permissions.html",
        grants=DocumentPermission.query.order_by(DocumentPermission.created_at.desc()).all(),
        docs=Document.query.filter_by(is_archived=False).order_by(Document.title).all(),
        users=User.query.filter_by(is_active=True).order_by(User.full_name).all(),
        departments=Department.query.filter_by(is_active=True).order_by(Department.department_name).all())


@bp.route("/admin/permissions/grant", methods=["POST"])
@roles_required(ROLE_ADMIN)
def permission_grant():
    """Grant or update a permission."""
    f = request.form
    doc = db.session.get(Document, int(f["document_id"])) if f.get("document_id", "").isdigit() else None
    try:
        if not doc:
            raise ValidationError("Choose a document.")
        services.grant_permission(current_user(), doc, f.get("grantee_type"),
                                  f.get("user_id") if f.get("grantee_type") == "user" else f.get("department_id"),
                                  f.get("can_view") == "1", f.get("can_ask") == "1", f.get("can_edit") == "1")
        flash("Permission saved.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.permissions"))


@bp.route("/admin/permissions/<int:permission_id>/revoke", methods=["POST"])
@roles_required(ROLE_ADMIN)
def permission_revoke(permission_id):
    """Revoke a permission."""
    try:
        services.revoke_permission(current_user(), permission_id)
        flash("Permission revoked. Access stops immediately.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.permissions"))


@bp.route("/admin/rules")
@roles_required(ROLE_ADMIN)
def rules():
    """Internal compliance rules."""
    return render_template("rules.html", rules=ComplianceRule.query.order_by(ComplianceRule.rule_name).all(),
                           departments=Department.query.filter_by(is_active=True).all(), severities=SEVERITIES)


@bp.route("/admin/rules/create", methods=["POST"])
@roles_required(ROLE_ADMIN)
def rule_create():
    """Create a rule."""
    f = request.form
    try:
        services.create_rule(current_user(), f.get("rule_name"), f.get("description"),
                             f.get("department_id"), f.get("severity"))
        flash("Rule created.", "success")
    except ValidationError as exc:
        _warn(exc)
    return redirect(url_for("main.rules"))


@bp.route("/admin/rules/<int:rule_id>/toggle", methods=["POST"])
@roles_required(ROLE_ADMIN)
def rule_toggle(rule_id):
    """Activate / deactivate a rule."""
    rule = db.get_or_404(ComplianceRule, rule_id)
    services.set_rule_active(current_user(), rule, not rule.is_active)
    flash("Rule status changed.", "success")
    return redirect(url_for("main.rules"))


@bp.route("/admin/audit")
@roles_required(ROLE_ADMIN)
def audit_logs():
    """Audit history (read-only) with filters."""
    query = AuditLog.query
    if request.args.get("action"):
        query = query.filter(AuditLog.action == request.args["action"])
    if request.args.get("user_id", "").isdigit():
        query = query.filter(AuditLog.user_id == int(request.args["user_id"]))
    start, end = _parse_filter_date(request.args.get("from")), _parse_filter_date(request.args.get("to"))
    if start:
        query = query.filter(AuditLog.created_at >= start)
    if end:
        query = query.filter(AuditLog.created_at < end + timedelta(days=1))
    pagination = query.order_by(AuditLog.created_at.desc(), AuditLog.audit_id.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=40, error_out=False)
    actions = [r[0] for r in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    return render_template("audit_logs.html", pagination=pagination, actions=actions,
                           users=User.query.order_by(User.full_name).all(), args=request.args)


@bp.route("/admin/status")
@roles_required(ROLE_ADMIN)
def status():
    """System status. Secrets (API keys) are never displayed, only whether they are set."""
    try:
        db.session.execute(text("SELECT 1"))
        db_ok, db_detail = True, f"connected ({db.engine.dialect.name})"
    except Exception as exc:
        db_ok, db_detail = False, f"unavailable ({type(exc).__name__})"
    vec_ok, vec_detail = rag.vector_store_status()
    cfg = current_app.config
    counts = dict(db.session.query(Document.status, func.count(Document.document_id)).group_by(Document.status).all())
    failed = Document.query.filter_by(status="Failed").order_by(Document.updated_at.desc()).all()
    return render_template(
        "status.html", db_ok=db_ok, db_detail=db_detail, vec_ok=vec_ok, vec_detail=vec_detail,
        llm_provider="Groq", llm_model=cfg["GROQ_MODEL"], llm_key_set=bool(cfg["GROQ_API_KEY"]),
        embedding_model=cfg["EMBEDDING_MODEL"], counts=counts, failed=failed,
        retrieval={"Chunk size (words)": cfg["CHUNK_WORDS"], "Chunk overlap (words)": cfg["CHUNK_OVERLAP_WORDS"],
                   "Passages per answer (top-k)": cfg["RAG_TOP_K"],
                   "Minimum semantic similarity": cfg["RAG_MIN_SIMILARITY"],
                   "Maximum upload (MB)": cfg["MAX_CONTENT_LENGTH"] // (1024 * 1024)},
        statuses=DOC_STATUSES)

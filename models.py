"""ORM models for PolicyLens (Flask-SQLAlchemy).

One Python class per database table. The baseline schema has the 12 core tables
from the specification, plus four supporting tables that the required features need:

    question_documents  - which documents a question was scoped to
    finding_comments    - reviewer / analyst comments on a finding
    finding_history     - status changes of a finding (review history)

Every table uses InnoDB, primary keys, foreign keys and indexes (MySQL default engine).
Timestamps are stored as naive UTC datetimes.
"""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, UniqueConstraint, event
from sqlalchemy.dialects.mysql import LONGTEXT
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

# --------------------------------------------------------------------------
# Constants shared by the whole application
# --------------------------------------------------------------------------
ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Analyst"
ROLE_REVIEWER = "Reviewer"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_REVIEWER)  # exactly three roles, never more

DOCUMENT_TYPES = ("Agreement", "Policy")
DOC_STATUSES = ("Uploaded", "Processing", "Indexed", "Failed", "Archived")
SEVERITIES = ("Low", "Medium", "High", "Critical")
FINDING_STATUSES = (
    "Draft", "Submitted", "In Review", "Changes Requested", "Approved", "Rejected", "Closed",
)


def utcnow():
    """Return the current UTC time as a naive datetime (what MySQL DATETIME stores)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Column types that behave well on MySQL (LONGTEXT, BIGINT) and still work in tests.
LongText = db.Text().with_variant(LONGTEXT(), "mysql")
BigInt = db.BigInteger().with_variant(db.Integer(), "sqlite")


# --------------------------------------------------------------------------
# 1. departments
# --------------------------------------------------------------------------
class Department(db.Model):
    """A company department. Documents and users belong to one department."""

    __tablename__ = "departments"

    department_id = db.Column(db.Integer, primary_key=True)
    department_name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    users = db.relationship("User", back_populates="department")
    documents = db.relationship("Document", back_populates="department")

    def __repr__(self):
        return f"<Department {self.department_name}>"


# --------------------------------------------------------------------------
# 2. users
# --------------------------------------------------------------------------
class User(db.Model):
    """An application user. Passwords are stored only as salted hashes."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('Admin','Analyst','Reviewer')", name="ck_users_role"),
    )

    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.department_id"), index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    department = db.relationship("Department", back_populates="users")

    def set_password(self, password):
        """Hash and store a password (never keep the plain text)."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Return True if `password` matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# --------------------------------------------------------------------------
# 3. documents
# --------------------------------------------------------------------------
class Document(db.Model):
    """Metadata of an uploaded PDF. The PDF itself lives in file storage."""

    __tablename__ = "documents"
    __table_args__ = (
        Index("ix_documents_dept_number", "department_id", "document_number"),
        Index("ix_documents_status", "status"),
    )

    document_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    document_number = db.Column(db.String(100), nullable=False)
    document_type = db.Column(db.String(30), nullable=False)  # Agreement / Policy
    department_id = db.Column(db.Integer, db.ForeignKey("departments.department_id"), nullable=False, index=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    # Path RELATIVE to UPLOAD_FOLDER. Never shown to users.
    storage_path = db.Column(db.String(500), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False, default="application/pdf")
    file_size = db.Column(db.BigInteger, nullable=False)
    file_hash = db.Column(db.CHAR(64), nullable=False, index=True)  # SHA-256
    page_count = db.Column(db.Integer)
    effective_date = db.Column(db.Date)
    expiry_date = db.Column(db.Date)
    counterparty = db.Column(db.String(255))
    description = db.Column(db.Text)
    status = db.Column(db.String(30), nullable=False, default="Uploaded")
    processing_error = db.Column(db.Text)
    version_number = db.Column(db.Integer, nullable=False, default=1)
    is_archived = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    department = db.relationship("Department", back_populates="documents")
    uploader = db.relationship("User", foreign_keys=[uploaded_by])
    chunks = db.relationship("DocumentChunk", back_populates="document",
                             cascade="all, delete-orphan", passive_deletes=True)
    permissions = db.relationship("DocumentPermission", back_populates="document",
                                  cascade="all, delete-orphan", passive_deletes=True)

    def __repr__(self):
        return f"<Document {self.document_id} {self.title!r} v{self.version_number}>"


# --------------------------------------------------------------------------
# 4. document_permissions
# --------------------------------------------------------------------------
class DocumentPermission(db.Model):
    """Extra access to one document for ONE user or ONE department (never both)."""

    __tablename__ = "document_permissions"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL AND department_id IS NULL) OR "
            "(user_id IS NULL AND department_id IS NOT NULL)",
            name="ck_perm_one_grantee",
        ),
        UniqueConstraint("document_id", "user_id", name="uq_perm_doc_user"),
        UniqueConstraint("document_id", "department_id", name="uq_perm_doc_dept"),
    )

    permission_id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id", ondelete="CASCADE"),
                            nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), index=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.department_id"), index=True)
    can_view = db.Column(db.Boolean, nullable=False, default=True)
    can_ask = db.Column(db.Boolean, nullable=False, default=False)
    can_edit = db.Column(db.Boolean, nullable=False, default=False)
    granted_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    document = db.relationship("Document", back_populates="permissions")
    user = db.relationship("User", foreign_keys=[user_id])
    department = db.relationship("Department", foreign_keys=[department_id])
    granter = db.relationship("User", foreign_keys=[granted_by])


# --------------------------------------------------------------------------
# 5. document_chunks
# --------------------------------------------------------------------------
class DocumentChunk(db.Model):
    """A piece of text from ONE page of a document (chunks never cross pages)."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_index", name="uq_chunk_doc_index"),
        Index("ix_chunks_doc_page", "document_id", "page_number"),
    )

    chunk_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id", ondelete="CASCADE"),
                            nullable=False)
    page_number = db.Column(db.Integer, nullable=False)  # real PDF page, 1-based
    chunk_index = db.Column(db.Integer, nullable=False)
    chunk_text = db.Column(LongText, nullable=False)
    token_count = db.Column(db.Integer, nullable=False, default=0)
    content_hash = db.Column(db.CHAR(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    document = db.relationship("Document", back_populates="chunks")
    vector = db.relationship("VectorIndex", back_populates="chunk", uselist=False,
                             cascade="all, delete-orphan", passive_deletes=True)


# --------------------------------------------------------------------------
# 6. vector_index
# --------------------------------------------------------------------------
class VectorIndex(db.Model):
    """Maps a MySQL chunk to its ChromaDB vector. Written only AFTER the vector is stored."""

    __tablename__ = "vector_index"

    vector_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    chunk_id = db.Column(BigInt, db.ForeignKey("document_chunks.chunk_id", ondelete="CASCADE"),
                         nullable=False, unique=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id", ondelete="CASCADE"),
                            nullable=False, index=True)
    vector_store = db.Column(db.String(50), nullable=False, default="ChromaDB")
    collection_name = db.Column(db.String(150), nullable=False)
    embedding_id = db.Column(db.String(255), nullable=False, unique=True)
    embedding_model = db.Column(db.String(150), nullable=False)
    index_status = db.Column(db.String(30), nullable=False, default="Indexed")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    chunk = db.relationship("DocumentChunk", back_populates="vector")


# --------------------------------------------------------------------------
# 7. questions (+ question_documents)
# --------------------------------------------------------------------------
class Question(db.Model):
    """A question a user asked the AI assistant."""

    __tablename__ = "questions"

    question_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    question_text = db.Column(db.Text, nullable=False)
    scope_type = db.Column(db.String(30), nullable=False, default="all")  # all / selected / department
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User")
    documents = db.relationship("QuestionDocument", cascade="all, delete-orphan")
    answers = db.relationship("Answer", back_populates="question", cascade="all, delete-orphan")


class QuestionDocument(db.Model):
    """The documents a question was searched in (one row per document)."""

    __tablename__ = "question_documents"

    question_id = db.Column(BigInt, db.ForeignKey("questions.question_id", ondelete="CASCADE"),
                            primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id"), primary_key=True)


# --------------------------------------------------------------------------
# 8. answers
# --------------------------------------------------------------------------
class Answer(db.Model):
    """The assistant's answer to a question."""

    __tablename__ = "answers"

    answer_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    question_id = db.Column(BigInt, db.ForeignKey("questions.question_id", ondelete="CASCADE"),
                            nullable=False, index=True)
    answer_text = db.Column(LongText, nullable=False)
    model_name = db.Column(db.String(150))
    retrieval_metadata = db.Column(db.JSON)
    # Qualitative only. We never invent numeric confidence scores.
    confidence_label = db.Column(db.String(30))
    insufficient_evidence = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    question = db.relationship("Question", back_populates="answers")
    sources = db.relationship("AnswerSource", back_populates="answer",
                              cascade="all, delete-orphan", order_by="AnswerSource.source_order")


# --------------------------------------------------------------------------
# 9. answer_sources
# --------------------------------------------------------------------------
class AnswerSource(db.Model):
    """One citation of an answer. Always points at a really retrieved, authorized chunk."""

    __tablename__ = "answer_sources"

    source_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    answer_id = db.Column(BigInt, db.ForeignKey("answers.answer_id", ondelete="CASCADE"),
                          nullable=False, index=True)
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id"), nullable=False)
    chunk_id = db.Column(BigInt, db.ForeignKey("document_chunks.chunk_id"), nullable=False)
    page_number = db.Column(db.Integer, nullable=False)
    quoted_text = db.Column(LongText, nullable=False)
    relevance_score = db.Column(db.Float)
    source_order = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    answer = db.relationship("Answer", back_populates="sources")
    document = db.relationship("Document")


# --------------------------------------------------------------------------
# 10. compliance_rules
# --------------------------------------------------------------------------
class ComplianceRule(db.Model):
    """An INTERNAL company requirement that findings can refer to (never invented law)."""

    __tablename__ = "compliance_rules"

    rule_id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.department_id"), index=True)
    severity = db.Column(db.String(30), nullable=False, default="Medium")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    department = db.relationship("Department")
    creator = db.relationship("User", foreign_keys=[created_by])


# --------------------------------------------------------------------------
# 11. compliance_findings (+ finding_comments, finding_history)
# --------------------------------------------------------------------------
class ComplianceFinding(db.Model):
    """A potential compliance issue raised by an Analyst and checked by a Reviewer."""

    __tablename__ = "compliance_findings"
    __table_args__ = (Index("ix_findings_status", "status"),)

    finding_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("compliance_rules.rule_id"))
    document_id = db.Column(db.Integer, db.ForeignKey("documents.document_id"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    assigned_reviewer_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(30), nullable=False, default="Medium")
    status = db.Column(db.String(30), nullable=False, default="Draft")
    evidence_text = db.Column(db.Text)
    page_number = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    rule = db.relationship("ComplianceRule")
    document = db.relationship("Document")
    creator = db.relationship("User", foreign_keys=[created_by])
    reviewer = db.relationship("User", foreign_keys=[assigned_reviewer_id])
    comments = db.relationship("FindingComment", cascade="all, delete-orphan",
                               order_by="FindingComment.created_at")
    history = db.relationship("FindingHistory", cascade="all, delete-orphan",
                              order_by="FindingHistory.created_at")


class FindingComment(db.Model):
    """A comment on a finding (by the analyst, the reviewer or an admin)."""

    __tablename__ = "finding_comments"

    comment_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    finding_id = db.Column(BigInt, db.ForeignKey("compliance_findings.finding_id", ondelete="CASCADE"),
                           nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User")


class FindingHistory(db.Model):
    """Every status change of a finding, with who did it and when (review history)."""

    __tablename__ = "finding_history"

    history_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    finding_id = db.Column(BigInt, db.ForeignKey("compliance_findings.finding_id", ondelete="CASCADE"),
                           nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    from_status = db.Column(db.String(30))
    to_status = db.Column(db.String(30), nullable=False)
    note = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    actor = db.relationship("User")


# --------------------------------------------------------------------------
# 12. audit_logs
# --------------------------------------------------------------------------
class AuditLog(db.Model):
    """Append-only history of important actions. Rows can be added, never changed."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_created", "created_at"), Index("ix_audit_action", "action"))

    audit_id = db.Column(BigInt, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(80))
    entity_id = db.Column(db.String(100))
    details = db.Column(db.JSON)  # safe metadata only: no passwords, keys or tokens
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User")


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _audit_is_append_only(mapper, connection, target):
    """Refuse to modify or delete an audit row through the ORM."""
    raise RuntimeError("Audit log rows are append-only.")



class PasswordResetToken(db.Model):
    """Temporary OTP records used for password recovery."""

    __tablename__ = "password_reset_tokens"

    reset_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    verified = db.Column(db.Boolean, nullable=False, default=False)

    otp_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        db.Index("ix_password_reset_user_active", "user_id", "is_used", "expires_at"),
    )








class LoginOTPToken(db.Model):
    """Temporary OTP records used only for login verification."""

    __tablename__ = "login_otp_tokens"

    login_otp_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )

    otp_hash = db.Column(db.String(255), nullable=False)

    expires_at = db.Column(db.DateTime, nullable=False)

    attempts = db.Column(db.Integer, nullable=False, default=0)

    is_used = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
    )

    __table_args__ = (
        db.Index(
            "ix_login_otp_user_active",
            "user_id",
            "is_used",
            "expires_at",
        ),
    )
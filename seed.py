"""Setup and maintenance commands for PolicyLens.

    python seed.py init            create all tables, the departments and the first Admin
    python seed.py demo-users      add a few sample Analyst / Reviewer accounts (for demos)
    python seed.py reindex         rebuild chunks and vectors of every live document
    python seed.py purge <doc_id>  permanently delete one document (file, chunks, vectors)

Passwords come from the environment (ADMIN_PASSWORD / DEMO_PASSWORD) or are generated
randomly and printed ONCE. They are never written to a file.
"""
import argparse
import os
import sys

from app import create_app
from models import ROLE_ADMIN, ROLE_ANALYST, ROLE_REVIEWER, Department, Document, User, db
import services

# PLACEHOLDER departments. Replace them with the names from the approved Excel sheet
# (rename them on the Departments page, or edit this list before running `init`).
DEFAULT_DEPARTMENTS = [
    ("Legal", "Contracts, NDAs and legal agreements"),
    ("Finance", "Payments, expenses and credit terms"),
    ("HR", "Employment agreements and people policies"),
    ("Procurement", "Vendor purchasing and sourcing"),
    ("IT", "Information technology and systems"),
    ("Operations", "Day-to-day business operations"),
]

DEMO_USERS = [
    ("Priya Nair", "priya.nair", ROLE_ANALYST, "Legal"),
    ("Rahul Verma", "rahul.verma", ROLE_REVIEWER, "Legal"),
    ("Sneha Reddy", "sneha.reddy", ROLE_ANALYST, "Finance"),
    ("Kavya Iyer", "kavya.iyer", ROLE_REVIEWER, "Finance"),
    ("Arjun Mehta", "arjun.mehta", ROLE_ANALYST, "HR"),
]


def cmd_init():
    """Create tables, seed departments and create the first Admin account."""
    db.create_all()
    created = 0
    for name, description in DEFAULT_DEPARTMENTS:
        if not Department.query.filter_by(department_name=name).first():
            db.session.add(Department(department_name=name, description=description))
            created += 1
    db.session.commit()
    print(f"Tables ready. Departments added: {created}.")

    if User.query.filter_by(role=ROLE_ADMIN).first():
        print("An Admin account already exists. Nothing more to do.")
        return
    username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.getenv("ADMIN_PASSWORD", "").strip()
    generated = not password
    if generated:
        password = services.generate_password()
    services.validate_password(password)
    it_dept = Department.query.filter_by(department_name="IT").first() or Department.query.first()
    admin = User(full_name=os.getenv("ADMIN_FULL_NAME", "System Administrator"), username=username,
                 email=os.getenv("ADMIN_EMAIL", "admin@techtonic.example").strip().lower(),
                 role=ROLE_ADMIN, department_id=it_dept.department_id, is_active=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.flush()
    services.audit("user_created", "user", admin.user_id, {"username": username, "role": ROLE_ADMIN,
                                                           "source": "seed.py init"}, user=admin)
    db.session.commit()
    print(f"First Admin created. Username: {username}")
    if generated:
        print(f"Temporary password (shown once, copy it now): {password}")
    else:
        print("Password: the value of ADMIN_PASSWORD in your .env file.")


def cmd_demo_users():
    """Create sample Analyst and Reviewer accounts for demonstrations."""
    shared = os.getenv("DEMO_PASSWORD", "").strip()
    admin = User.query.filter_by(role=ROLE_ADMIN).first()
    if not admin:
        sys.exit("Run `python seed.py init` first.")
    for full_name, username, role, dept_name in DEMO_USERS:
        if User.query.filter_by(username=username).first():
            print(f"{username}: already exists")
            continue
        dept = Department.query.filter_by(department_name=dept_name).first()
        if not dept:
            print(f"{username}: skipped, department {dept_name} does not exist")
            continue
        password = shared or services.generate_password()
        services.create_user(admin, full_name, username, f"{username}@techtonic.example",
                             role, dept.department_id, password)
        print(f"{username:14} {role:9} {dept_name:12} password: {password}")


def cmd_reindex():
    """Re-extract, re-chunk and re-embed every live document (rebuilds ChromaDB if it was lost)."""
    docs = Document.query.filter_by(is_archived=False).order_by(Document.document_id).all()
    print(f"Re-indexing {len(docs)} document(s)...")
    for doc in docs:
        result = services.process_document(doc.document_id)
        note = f" ({result.processing_error})" if result.processing_error else ""
        print(f"  #{doc.document_id} {doc.title}: {result.status}{note}")


def cmd_purge(doc_id):
    """Permanently delete one document and everything that belongs to it."""
    doc = db.session.get(Document, doc_id)
    if not doc:
        sys.exit(f"No document with id {doc_id}.")
    confirm = input(f"Permanently delete '{doc.title}' (id {doc_id})? Type YES to confirm: ")
    if confirm.strip() != "YES":
        sys.exit("Cancelled.")
    services.purge_document(None, doc)
    print("Deleted.")


def main():
    """Parse the command line and run the chosen command inside the Flask app context."""
    parser = argparse.ArgumentParser(description="PolicyLens setup and maintenance")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("demo-users")
    sub.add_parser("reindex")
    purge = sub.add_parser("purge")
    purge.add_argument("doc_id", type=int)
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.command == "init":
            cmd_init()
        elif args.command == "demo-users":
            cmd_demo_users()
        elif args.command == "reindex":
            cmd_reindex()
        elif args.command == "purge":
            cmd_purge(args.doc_id)


if __name__ == "__main__":
    main()

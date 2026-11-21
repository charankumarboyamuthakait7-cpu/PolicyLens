# PolicyLens

Enterprise contract and policy intelligence platform for **Techtonic Solutions Pvt. Ltd.**
(academic project, fictional documents, **not legal advice and not production-approved**).

Users upload PDFs. PolicyLens extracts the text page by page, chunks it, embeds it, and answers
questions with **exact document and page citations**, using hybrid (semantic + keyword) search that
only ever looks inside documents the user is authorized to open.

## Architecture (layered three-tier monolith)

```
Browser (Bootstrap 5, JS)                       <- presentation tier
   |
Flask app                                       <- application tier
   routes.py     pages and JSON endpoints (thin)
   security.py   login, CSRF, rate limit, ROLE + DOCUMENT permission checks  <- one choke point
   services.py   users, upload, extraction, chunking, indexing, findings, audit
   rag.py        hybrid retrieval, Groq call, citation validation, clause comparison
   models.py     SQLAlchemy ORM (one class per table)
   |
MySQL (metadata, chunks, answers, findings, audit)  |  PDF files on disk  |  ChromaDB (vectors)   <- data tier
   |
Groq LLM (external)  |  all-MiniLM-L6-v2 embeddings (local)
```

The rule that matters most: **permissions are decided in backend code before retrieval**. The list of
authorized document IDs is built from MySQL, search is restricted to it, every retrieved chunk is
re-checked against it, and only those passages are sent to the LLM. The LLM never decides access.

## Files (7 application files + 1 test file)

| File | Purpose |
|---|---|
| `app.py` | configuration (`.env`), app factory, error pages, security headers |
| `models.py` | all ORM tables |
| `security.py` | authentication, CSRF, login rate limit, document authorization |
| `services.py` | business logic (users, documents, indexing, permissions, findings, audit) |
| `rag.py` | embeddings, ChromaDB, hybrid search, Groq, citations, comparison |
| `routes.py` | every page and endpoint |
| `seed.py` | `init`, `demo-users`, `reindex`, `purge` commands |
| `tests/test_policylens.py` | automated tests |

## Database tables (ORM)

Core 12: `departments`, `users`, `documents`, `document_permissions`, `document_chunks`, `vector_index`,
`questions`, `answers`, `answer_sources`, `compliance_rules`, `compliance_findings`, `audit_logs`.
Added because required features need them: `question_documents` (selected documents of a question),
`finding_comments`, `finding_history` (review history). Document versions use the `version_number` and
`is_archived` columns of `documents`, so no extra table is needed.

## Setup on Windows (PowerShell)

Use **Python 3.11 or 3.12** (ChromaDB and sentence-transformers publish wheels for these first).

1. **Create the empty database** (once). In MySQL Workbench run `create_database.sql`, or:
   ```sql
   CREATE DATABASE policylens_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```
   Do **not** create tables. The app creates them.
2. **Install packages**
   ```powershell
   cd PolicyLens
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Configure**
   ```powershell
   copy .env.example .env
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Open `.env` and set `SECRET_KEY` (paste the value printed above), `MYSQL_USER`, `MYSQL_PASSWORD`,
   and the AI settings. **The AI needs only these two lines:**
   ```env
   GROQ_API_KEY=your_key_here
   GROQ_MODEL=openai/gpt-oss-120b
   ```
4. **Create tables, departments and the first Admin**
   ```powershell
   python seed.py init
   ```
   Expected: `Tables ready. Departments added: 6.` then the Admin username and a one-time password.
   Optional sample accounts: `python seed.py demo-users`.
5. **Run**
   ```powershell
   python app.py
   ```
   Open http://127.0.0.1:5000 and sign in as the Admin. The first indexing run downloads the
   embedding model (about 90 MB) once.
6. **Test**
   ```powershell
   python -m pytest -v
   ```

Useful commands: `python seed.py reindex` rebuilds all chunks and vectors (for example if the
`instance/chroma` folder was deleted); `python seed.py purge <id>` permanently deletes one document.

## Roles

| Role | Can do |
|---|---|
| Admin | everything: users, departments, permissions, rules, audit, status, all documents, upload, archive, reprocess |
| Analyst | upload to own department, browse authorized documents, ask questions, compare clauses, create and submit findings |
| Reviewer | review assigned findings (approve, reject, request changes, comment) on documents they may open |

An Analyst can never approve their own finding. The last active Admin cannot be removed or deactivated.

## Document access rules

Default: a user sees documents of their own department. Admin sees all. Extra access comes from
`document_permissions` grants to a user or a department (view, ask, edit). Archived documents are
visible to Admin only. Revoking a grant takes effect on the next request.

## RAG behaviour

* Answers cite `[S1]`, `[S2]` markers that map to real retrieved passages; invented markers are removed.
* Page numbers come from PDF extraction, never from the model.
* No evidence means no LLM call and the message "I could not find sufficient supporting information...".
* Document text is fenced and treated as untrusted data; instructions inside PDFs are ignored.
* Clause comparison searches each document separately and shows "Not found in this document." for gaps.

## Known limitations

* Scanned PDFs are reported as needing OCR; OCR is not included.
* Login rate limiting is in memory (resets on restart; single server process).
* Indexing runs during the upload request (no background queue).
* The department list in `seed.py` is a placeholder until replaced with the approved Excel sheet names.

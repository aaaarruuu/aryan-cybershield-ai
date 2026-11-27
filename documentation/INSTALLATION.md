# Installation and Operations Guide

## 1. Requirements
Python 3.11+ (developed on 3.13), Node 20.19+ (developed on 22), PostgreSQL 16 (optional locally; SQLite works for development), Docker + Compose for container deployment. ~2 GB RAM is plenty.

## 2. Local development
```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # full pinned lock (130 packages)
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export DATABASE_URL=sqlite:///./cybershield.db          # or the PostgreSQL URL in section 4
export DEMO_MODE=true APP_ENV=development
alembic upgrade head
uvicorn app.main:app --reload --port 8000                # API docs: http://localhost:8000/docs
cd ../frontend && npm install && npm run dev             # http://localhost:5173 (proxies /api to :8000)
```
The phishing model trains automatically on first use (~1 s) into `backend/app/ml/artifacts/`. Retrain: `python -m app.ml.phishing_model` (set `PHISHING_CSV=/path/real.csv` to train on a real `text,label` file).

Regenerate sample data: `python scripts/generate_sample_data.py`. Rebuild ATT&CK summary: `python -I scripts/build_attack_kb.py enterprise-attack.json sample_data/knowledge/mitre_attack_techniques.md` (STIX file from github.com/mitre/cti).

## 3. First run
1. Register: the **first** account becomes admin. Do this before exposing the service.
2. Admin -> Knowledge Base -> *Load MITRE ATT&CK + playbooks* (needed for cited recommendations).
3. See [DEMO.md](DEMO.md).

## 4. PostgreSQL
```sql
CREATE USER cybershield WITH PASSWORD '...'; CREATE DATABASE cybershield OWNER cybershield;
```
`DATABASE_URL=postgresql+psycopg://cybershield:<password>@host:5432/cybershield`, then `alembic upgrade head`. Tests against PostgreSQL: `TEST_DATABASE_URL=<url> pytest` (use a throw-away database: the fixture drops all tables).

## 5. Docker
```bash
cp .env.example .env     # set POSTGRES_PASSWORD, SECRET_KEY (python -c "import secrets;print(secrets.token_urlsafe(48))")
docker compose up --build -d
docker compose ps        # db, backend, frontend should become healthy
```
UI on port 8080. The database has no published port. Volumes: `pgdata`, `chroma`, `mlartifacts`. The backend entrypoint applies migrations then starts uvicorn. **Status: written and `docker compose config`-validated, not built in the development sandbox - verify on first run.**

## 6. Configuration (environment variables)
| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | none in compose | >= 32 chars; production refuses the built-in dev key |
| `APP_ENV` | development | `production` hides `/docs` |
| `DATABASE_URL` | sqlite | PostgreSQL in production |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 30 | |
| `CORS_ORIGINS` | localhost:5173,8080 | comma-separated allow-list; set to your real origin |
| `DEMO_MODE` | true | false = live VirusTotal |
| `VIRUSTOTAL_API_KEY` | empty | backend only; never sent to the browser. Free API keys are rate-limited (429 -> `unavailable`) |
| `CHROMA_PATH` | ./chroma_data | persistent volume |
| `UPLOAD_MAX_MB` | 10 | |
| `RATE_LIMIT_AUTH` | 20/minute | login/register |

## 7. Production hardening checklist
* Terminate **TLS** in front of nginx (ALB, Caddy or certbot). The shipped nginx listens on HTTP only.
* Generate strong `SECRET_KEY` and `POSTGRES_PASSWORD`; keep `.env` out of git; use a secrets manager where available.
* Set `CORS_ORIGINS` to the real HTTPS origin; keep `APP_ENV=production`.
* Register the admin immediately; create analyst accounts; disable unused ones.
* Do not expose PostgreSQL or any ChromaDB server publicly.
* Run backend as the shipped non-root user; keep images and dependencies updated; re-run `pip-audit` / `npm audit`.
* Rate limiting is per-process: put a WAF/proxy limit in front for internet exposure.

## 7a. AWS-compatible deployment (guidance, not tested on AWS)
* **Simplest:** one EC2 instance (t3.medium), Docker + Compose, Elastic IP, security group allowing 80/443 only, ALB or Caddy for TLS, EBS snapshots for volumes.
* **Managed:** images to ECR; backend + frontend on ECS Fargate behind an ALB; PostgreSQL on RDS (private subnet, security group allows only the backend); ChromaDB path on EFS (`CHROMA_PATH`) - run a single backend task because embedded Chroma is single-writer; secrets in Secrets Manager injected as env vars; CloudWatch for logs (the app logs to stdout).
* Health endpoint for target groups: `GET /api/health`.

## 8. Backup and recovery
```bash
# PostgreSQL
docker compose exec -T db pg_dump -U cybershield cybershield > backup_$(date +%F).sql
docker compose exec -T db psql -U cybershield cybershield < backup_2026-01-01.sql      # restore into an empty DB
# Chroma + model artifacts (stop backend for a consistent copy)
docker compose stop backend
docker run --rm -v cybershield-ai_chroma:/d -v "$PWD":/b alpine tar czf /b/chroma.tgz -C /d .
docker compose start backend
```
(Volume names are prefixed by the compose project directory name; check `docker volume ls`.) If the Chroma store is lost, re-upload documents: relational records are unaffected, but `knowledge_documents.chunk_count` will refer to missing vectors until you delete and re-upload.

## 9. Troubleshooting
| Symptom | Fix |
|---|---|
| Backend exits: *SECRET_KEY must be at least 32 characters* / *Refusing to start in production with the default SECRET_KEY* | set a real key |
| `docker compose` says variable is required | fill `POSTGRES_PASSWORD` and `SECRET_KEY` in `.env` |
| UI shows "Cannot reach the server" | backend not running/healthy: `docker compose logs backend`; in dev ensure uvicorn is on :8000 |
| API not answering for several seconds after start | importing scikit-learn/chromadb takes a few seconds; wait for `/api/health` |
| 429 on login | auth rate limit; wait a minute |
| Investigation stuck on `running` | backend restarted mid-run; start a new one |
| Threat intel says `unavailable` | `DEMO_MODE=false` without `VIRUSTOTAL_API_KEY`, key rejected (401/403) or VT rate limit (429) - by design no verdict is invented |
| Recommendations have no citations | knowledge base empty: load the built-in documents |
| Upload rejected | type must be csv/json/txt/log (logs) or pdf/txt/md/csv/json (knowledge); UTF-8; <= 10 MB; scanned PDFs without text are unsupported |
| `psycopg` import error on a minimal OS | `pip install "psycopg[binary]"` (already in requirements) |
| Tests hang on PostgreSQL | another session holds locks; use a dedicated empty test database |

# LifeFlow - Smart Blood Bank Management and Donor Connect

FastAPI + SQLAlchemy backend, vanilla HTML/CSS/JS frontend, Chart.js. Synthetic data only.

## Run
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cd backend && uvicorn app:app --reload
Open http://127.0.0.1:8000. SQLite is used by default; set DATABASE_URL (see .env.example) for PostgreSQL.
Demo accounts (password `Passw0rd!`): admin@, staff@, hospital@, donor@ `lifeflow.test`.
Tests: `cd backend && pytest`

## Implemented
Role-based JWT auth (admin, staff, hospital, donor, public); donor appointments; collection with testing->release gate;
inventory with component expiry and low-stock alerts; hospital requests with reserve/issue (no double issue, expired units never issued);
emergency alerts to consenting donors with matching group (contacts never exposed); in-app notifications; unit lookup with audit trail;
dashboard + Chart.js; CSV export; audit log; user approval/deactivation; light/dark mode.

## Not yet built (next phases)
Email verification and password reset, real email/SMS sending (stub in `create_req`), PDF/Excel export, QR image generation and camera scanning,
AI forecasting (Module 12), reschedule appointments, map-based centre discovery, full pages per module, Alembic migrations, rate limiting.
Verify Indian blood-centre regulations and privacy law before any real deployment.

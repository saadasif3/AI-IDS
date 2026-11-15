# AI-IDS

FastAPI + SQLAlchemy backend, React dashboard. Detection combines threshold signatures with an Isolation Forest anomaly model that learns a baseline from the first 40 traffic windows (10 s each) after monitoring starts.

## Run
```
cp .env.example .env && export $(cat .env | xargs)   # JWT_SECRET is required
cd backend && python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
uvicorn app.main:app --reload            # http://localhost:8000/docs
cd ../frontend && npm i && npm run dev   # http://localhost:5173
pytest ../tests                          # detection tests
```
Register the first account (becomes admin). Start **simulation** to see the engines run on synthetic, clearly labelled traffic, or **live capture** on an interface (needs libpcap and root/admin; monitor only networks you are authorized to).

## Limits (read before relying on it)
- Detection thresholds are untuned defaults; false-positive/negative rates are **not measured**. The Isolation Forest is unsupervised and unvalidated; its alerts mean "unusual", not "attack".
- Brute force is inferred from connection counts, not failed logins. Encrypted traffic is not inspected.
- Not implemented: Suricata/Zeek integration, supervised classifiers (CIC-IDS2017 etc.), SHAP, threat-intel APIs, incidents/timelines, topology view, reports/PDF/CSV, automated blocking, audit log, rate limiting, Docker/Prometheus, TimescaleDB/Redis, Tailwind/shadcn/Recharts, protocol parsing beyond TCP/UDP/ICMP/DNS names.

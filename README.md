# Thread Intelligence System

A local-first Security Operations Center (SOC) dashboard for network telemetry, ML-assisted threat classification, and **application-only** IP blocking. It never changes the host firewall.

For complete installation and hackathon presentation instructions, see [Setup and Demo Guide](docs/SETUP_AND_DEMO.md).

```text
Safe local generator / Scapy capture → Flask prediction pipeline → MongoDB
                                      ↓                    ↕ Socket.IO
                            In-app block middleware ← React SOC dashboard
```

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

Open `http://localhost:5173`. Demo credentials are `admin / admin123` and `viewer / viewer123`.

### Local development

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py

cd ../frontend
npm install
npm run dev
```

The backend starts in a fully seeded demo mode if MongoDB is not running. Supply `MONGO_URI` to persist data.

## Safe traffic demonstration

The simulator signs in to the local demo API automatically. Its hard safety guard accepts only loopback/private Docker network targets, and its synthetic source address (`10.240.0.42`) is distinct from the browser's loopback request so demonstrating auto-blocking does not lock out the local dashboard.

```bash
python scripts/safe_traffic_generator.py --attack
```

It emits telemetry to the local `/api/predict` endpoint; it does not scan or flood real network targets.

## CIC-IDS2017 training

Download CIC-IDS2017 CSV flow data from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html), put all downloaded CSVs or extracted folders under `dataset/`, then run:

```bash
pip install pandas
python ml/train_model.py dataset --max-rows-per-file 50000
```

The script cleans numeric flows, trains/evaluates a Random Forest, prints quality metrics, and stores the model at `backend/models/cic_ids_rf.joblib`. The runtime includes a transparent rules-based fallback for an immediately runnable demo until that artifact is integrated.

## API

All `/api/*` endpoints except `/health` and `/auth/login` require `Authorization: Bearer <JWT>`.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/login` | Receive JWT with role |
| GET | `/dashboard`, `/traffic`, `/alerts`, `/statistics` | Dashboard data |
| POST | `/predict` | Ingest/predict local telemetry |
| GET/POST | `/blocked-ips`, `/block-ip` | Application block management |
| POST | `/unblock-ip` | Admin unblock |
| GET | `/attack-history`, `/reports/csv`, `/settings` | Analysis/export/config |

## Security design

The Flask `before_request` middleware checks every normal application request against `blocked_ips` and returns the required `403` JSON payload for an active block. Expired entries automatically cease blocking. This scope deliberately excludes host-level firewall changes.

## Project layout

`frontend/` Vite React dashboard · `backend/` Flask/Socket.IO APIs · `ml/` training · `scripts/` safe demo tooling · `dataset/` local dataset files · `docker-compose.yml` deployment.

## Future improvements

Integrate the trained artifact into runtime feature mapping, add an authenticated Scapy capture worker, email provider configuration, scheduled PDF reports, true container health probes, and audited production user storage.

## License

MIT

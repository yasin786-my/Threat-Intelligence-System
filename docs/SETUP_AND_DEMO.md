# Thread Intelligence System — Setup and Demo Guide

This guide explains how to run the project locally and present a safe cyberattack-detection demo. All simulated traffic is limited to the local machine or private Docker networks.

## 1. Requirements

Install the following:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (recommended)
- Git (optional, for cloning)
- Python 3.11+ and Node.js 20+ only if running without Docker

Start Docker Desktop before continuing.

## 2. Run with Docker (recommended)

Open a terminal in the project folder:

```powershell
docker compose up --build
```

The first run downloads container images and installs packages, so it can take a few minutes. Keep this terminal open while demonstrating.

When startup completes, open:

| Service | URL |
|---|---|
| SOC Dashboard | http://localhost:5173 |
| Flask API health check | http://localhost:5000/api/health |

To stop the project, press `Ctrl+C` in the terminal. To stop and remove containers later:

```powershell
docker compose down
```

To also delete the local MongoDB demo data:

```powershell
docker compose down -v
```

## 3. Log in

Use one of the built-in demonstration accounts:

| Role | Username | Password | Permissions |
|---|---|---|---|
| Administrator | `admin` | `admin123` | View data, edit policy, manually block/unblock IPs |
| Viewer | `viewer` | `viewer123` | View dashboard and analytics only |

> Change the demo credentials and `SECRET_KEY` before any public deployment.

## 4. Demonstrate the dashboard

1. Sign in as `admin`.
2. Open **Dashboard** to show overview cards, traffic trend, attack distribution, alerts, and threat score.
3. Open **Traffic Monitor** to show packet/event details and use the search field to filter by IP, protocol, or attack type.
4. Open **Threat Intelligence** to show top attacking IPs and model metrics.
5. Open **Blocked IPs** to show the application-level block list and manual unblock control.
6. Open **Settings** and change the auto-block confidence threshold or block duration. Click **Save policy**.

The dashboard starts with seeded demonstration data when no persisted MongoDB data exists.

## 5. Generate safe local traffic

Open a **second** PowerShell terminal in the project folder. The generator logs into the local API and sends only synthetic telemetry. It refuses public/external targets.

### Normal traffic

```powershell
python scripts\safe_traffic_generator.py
```

### Simulated abnormal high-volume traffic

```powershell
python scripts\safe_traffic_generator.py --attack
```

For Docker, the command targets `http://127.0.0.1:5000/api/predict` by default, which is correct. Press `Ctrl+C` to stop the generator.

Return to the browser and show:

- New live traffic rows arriving through Socket.IO.
- A `DDoS` prediction with confidence and severity.
- A real-time alert notification.
- Automatic addition of synthetic source IP `10.240.0.42` to **Blocked IPs**.

The block is intentionally enforced only in Flask. No host firewall settings are modified.

## 6. Demonstrate manual response

1. In **Blocked IPs**, click **Unblock** next to an active record.
2. Run the `--attack` simulator again.
3. Explain that the policy threshold triggers automatic blocking when prediction confidence meets the configured limit.
4. In **Settings**, increase the threshold (for example to `95%`), generate traffic again, and show that lower-confidence events are logged but not automatically blocked.

## 7. Export a report

From **Profile**, select **Export traffic CSV**. The export contains the currently stored telemetry records.

## 8. Run without Docker (development mode)

Use two terminals.

### Terminal 1: backend

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

If `python` is unavailable, use `py app.py`. The backend works in seeded in-memory demo mode if MongoDB is not running.

### Terminal 2: frontend

```powershell
npm.cmd install
npm.cmd run dev
```

Open the Vite URL shown in the terminal, usually `http://localhost:5173`.

## 9. Train the CIC-IDS2017 model (optional for presentation)

1. Download CIC-IDS2017 flow CSV files from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html).
2. Put **all** downloaded CSV files (or their extracted folders) inside `dataset/`.
3. From the project root, train with every CSV in that directory:

```powershell
pip install pandas scikit-learn joblib
python ml\train_model.py dataset --max-rows-per-file 50000
```

The script recursively finds every `.csv` file, samples up to 50,000 records from each file by default, combines their numeric CIC flow features, then creates `backend/models/cic_ids_rf.joblib` and `backend/models/cic_ids_rf.metrics.json`. You train once and reuse this saved file. Restart the backend after training so it loads the model; Docker mounts the local `backend/models/` folder into the backend container. Use `--max-rows-per-file 0` only when your computer has sufficient RAM.

If training reports metrics and then stops while printing a class report, update the project and run the same command again; no model is saved until the final `Model saved to ...` message appears.

## 10. Suggested 3-minute hackathon demo script

1. **Problem (20 seconds):** “Traditional monitoring shows traffic but does not consistently automate response.”
2. **Dashboard (40 seconds):** Show system health, total packets, suspicious traffic, live charts, and attack distribution.
3. **Detection (40 seconds):** Start `python scripts\safe_traffic_generator.py --attack`; point out the DDoS prediction, confidence, severity, and recommended action.
4. **Response (40 seconds):** Show the alert and automatic IP block appearing live. Explain that this is application-only blocking, so it is safe for a demo environment.
5. **Control (25 seconds):** Use Blocked IPs to manually unblock; use Settings to change the confidence threshold.
6. **Analytics (15 seconds):** Show Threat Intelligence and CSV export.

## Troubleshooting

| Problem | Resolution |
|---|---|
| `docker compose` does not work | Start Docker Desktop, then reopen PowerShell. |
| Port 5000 or 5173 is already in use | Stop the existing service or change the host port in `docker-compose.yml`. |
| Browser cannot reach API in local mode | Start the Flask backend first; the Vite proxy routes `/api` and Socket.IO to port 5000. |
| PowerShell blocks `npm` | Use `npm.cmd install` and `npm.cmd run dev`. |
| Simulator reports a login error | Confirm the backend is running and use the default `admin/admin123` credentials or pass `--username` and `--password`. |
| No new data is visible | Refresh the dashboard and check `http://localhost:5000/api/health`. |

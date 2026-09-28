\# AI-IDPS: AI-Powered Intrusion Detection and Prevention System



B.Tech final-year project. A working IDS + IPS that classifies network events with a hybrid of rule-based detection and machine learning, raises real-time alerts, and responds automatically.



Safe by design: it only processes synthetic simulated traffic and uploaded PCAP files on localhost. It never attacks, scans or touches any external system. Prevention actions only change the application's own blocklist.


 Abstract



AI-IDPS monitors traffic events, classifies them (BENIGN, DoS, Probe, Brute Force, Bot) using a rule engine and a Random Forest model, assigns a severity, creates alerts, and automatically blocks high-severity sources in a controlled, simulated environment. A React dashboard shows everything live over WebSockets. PostgreSQL is the permanent store; Redis provides fast counters and rate limiting.



\## Features



\- JWT authentication with ADMIN and VIEWER roles (bcrypt password hashing)

\- Simulation engine with 5 safe scenarios: BENIGN, HIGH\_CONNECTION\_RATE, BRUTE\_FORCE, ANOMALY, BOT\_ACTIVITY

\- Hybrid detection: rule engine + Random Forest; when they disagree, the higher-confidence result wins

\- Severity from confidence: LOW, MEDIUM (>=0.50), HIGH (>=0.70), CRITICAL (>=0.85)

\- Alerts with a status lifecycle: NEW, ACKNOWLEDGED, RESOLVED, FALSE\_POSITIVE

\- Automatic prevention: HIGH/CRITICAL sources are added to an application-level blocklist, with a full audit log; admin-only manual block/unblock

\- Redis for alert counters and login rate limiting, with graceful fallback (PostgreSQL stays the source of truth)

\- Real-time dashboard over WebSockets: statistics, threat chart, live events, alerts, prevention, ML model metrics

\- PCAP upload and analysis using Scapy

\- Security: rate limiting, secure headers, centralized error handling, structured logging

\- 18 automated pytest tests



\## Architecture



```

Simulation / PCAP upload

&#x20;       |

Feature extraction -> Rule engine + Random Forest -> Hybrid decision

&#x20;       |

Severity -> Alert + Prevention (blocklist) -> PostgreSQL (+ Redis counters)

&#x20;       |

FastAPI -> WebSocket -> React dashboard

```



\## Tech stack



| Layer | Technology |

|---|---|

| Backend | Python 3.13, FastAPI, SQLAlchemy, Pydantic |

| Database / cache | PostgreSQL 16, Redis 7 |

| ML | scikit-learn (Random Forest), pandas, numpy, joblib |

| Network | Scapy (PCAP parsing) |

| Frontend | React, Vite, Recharts |

| Auth | JWT (python-jose), bcrypt (passlib) |

| Testing | pytest, httpx |

| Deployment | Docker, Docker Compose |



\## Quick start (Docker, recommended)



Requires Docker Desktop (on Windows, with the WSL2 backend).



```

git clone https://github.com/YOUR-USERNAME/AI-IDPS.git

cd AI-IDPS

copy backend\\.env.example backend\\.env

docker compose up --build -d

```



Edit `backend\\.env` and set `JWT\_SECRET\_KEY` to a long random string. Then:



\- Dashboard: http://localhost:5173

\- API docs (Swagger): http://localhost:8000/docs



A fresh database has no users. Create the first admin in Swagger with `POST /api/auth/register`:



```

{"name": "Admin", "email": "admin@example.com", "password": "choose-a-password", "role": "ADMIN"}

```



Then log in on the dashboard.



\## Run without Docker (development)



```

docker compose up -d postgres redis



python -m venv venv

venv\\Scripts\\Activate.ps1

cd backend

pip install -r requirements.txt

uvicorn app.main:app --reload

```



In a second terminal:



```

cd frontend

npm install

npm run dev

```



\## Machine learning



The trained model is included in `backend/app/ml/models/`. To retrain:



```

cd datasets\\sample

python generate\_dataset.py

cd ..\\..\\backend

python -m app.ml.train

```



The dataset is \*\*synthetic\*\*: `generate\_dataset.py` creates 2000 rows across 5 classes, with features loosely modelled on public datasets such as CIC-IDS2017 and UNSW-NB15. No real dataset is bundled.



\## Demo



1\. Log in to the dashboard.

2\. Choose a scenario (for example HIGH\_CONNECTION\_RATE) and click \*\*Generate + Detect\*\*.

3\. Watch the statistics, live event feed, alerts table and blocked sources update.



PCAP demo (Windows):



```

python -c "from scapy.all import wrpcap, IP, TCP; wrpcap('sample.pcap', \[IP(src='192.168.1.10', dst='10.0.0.5')/TCP(sport=5000+i, dport=80) for i in range(50)])"

curl.exe -X POST "http://127.0.0.1:8000/api/traffic/upload-pcap" -H "Authorization: Bearer YOUR\_TOKEN" -F "file=@sample.pcap"

```



\## API overview



Interactive docs at `/docs`. Main groups: `/api/auth`, `/api/traffic`, `/api/simulation`, `/api/detection`, `/api/alerts`, `/api/prevention`, `/api/analytics`, `/api/ml`, plus `/health` and the `/ws/events` WebSocket.



\## Testing



Needs PostgreSQL and Redis running and `backend/.env` in place:



```

cd backend

python -m pytest -v

```



\## Limitations



\- \*\*The ML metrics are not real-world accuracy.\*\* The \~99% accuracy, precision, recall and F1 are measured on clean synthetic data. Real traffic is far noisier, so these numbers must not be read as real detection performance. Benign and bot traffic overlap in the synthetic data, which causes the few misclassifications.

\- Detection uses only packet count, byte count, protocol and ports. There are no flow-duration or TCP-flag features.

\- Prevention is application-level only (a blocklist plus an audit log). No real firewall is touched. `ACTIVE-LAB` mode behaves the same as `SIMULATION`.

\- The dashboard is a single page. Separate Live Monitoring, Analytics and Settings pages, model activation, and latency/events-per-second metrics are not implemented.

\- Live packet capture is not implemented; input comes from simulation and PCAP upload.

\- `POST /api/auth/register` lets the caller choose the ADMIN role, which is acceptable for a demo but must be restricted in production.

\- Logout only discards the token client-side, and the WebSocket endpoint is unauthenticated.

\- `docker-compose.yml` uses a development-only database password.

\- Tests run against the real PostgreSQL and Redis rather than an isolated test database.



\## Future scope



Train on the real CIC-IDS2017 or UNSW-NB15 dataset, add flow-level features, live capture in a controlled lab, restricted registration with role management, WebSocket authentication, configurable thresholds from the UI, model versioning and activation, and an isolated test database.


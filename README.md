# PHISHGUARD
Defensive phishing/scam detection MVP based on the supplied hackathon specification.

## Run backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

## Run frontend
Serve `frontend/index.html` with a local static server, e.g. from frontend:
python3 -m http.server 5173
Then open http://127.0.0.1:5173

This MVP implements the real Regex engine, URL analysis, brand similarity, risk scoring, SMS analysis, and an explainable dashboard. It intentionally leaves external threat-intelligence APIs as a next integration stage so the core works without API keys.

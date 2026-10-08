# ClockGuard — Member 3: GenAI + Backend + Frontend

This package is built against the actual Member 2 `member2_ai_intelligence.csv` supplied for the project. The input contains 6,713 rows and 27 columns.

## What Member 3 does
- FastAPI backend
- LangGraph incident workflow
- Local RAG knowledge base
- Optional OpenAI LLM
- Compliance screening
- AI incident reports in JSON/Markdown
- Timeline, MITRE and NIST endpoints
- React dashboard
- Investigator chat
- Automated tests

## Important boundary
Member 3 does NOT recreate anomaly detection, incident classification, risk scoring, severity, MITRE mapping, or NIST mapping. Those are consumed from Member 2.

## 1. Backend setup (Windows)
```powershell
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
copy .env.example .env
python scripts\\run_member3.py
```
Open: http://127.0.0.1:8003/docs

Optional LLM: put `OPENAI_API_KEY=...` in `.env`. Without it, fallback mode is fully usable.

## 2. Test
```powershell
pytest -q
```

## 3. Frontend
```powershell
cd frontend
npm install
npm run dev
```
Open the URL Vite prints, normally http://localhost:5173.

## API
- GET /health
- GET /api/summary
- GET /api/incidents
- GET /api/incidents/{incident_id}
- GET /api/timeline/{incident_id}
- GET /api/mitre/{incident_id}
- GET /api/nist/{incident_id}
- GET /api/analyze/{incident_id}
- POST /api/compliance/{incident_id}
- POST /api/report/{incident_id}
- POST /api/chat/{incident_id}

Generated files:
`data/output/ai_reports/`, `data/output/compliance_reports/`, `data/output/incident_analysis/`.

"""from pathlib import Path
import os
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
INPUT_FILE = ROOT / "data" / "input" / "member2_ai_intelligence.csv"
KB_DIR = ROOT / "data" / "knowledge_base"
OUTPUT_DIR = ROOT / "data" / "output"
AI_REPORT_DIR = OUTPUT_DIR / "ai_reports"
COMPLIANCE_DIR = OUTPUT_DIR / "compliance_reports"
ANALYSIS_DIR = OUTPUT_DIR / "incident_analysis"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8003"))
for d in (AI_REPORT_DIR, COMPLIANCE_DIR, ANALYSIS_DIR):
    d.mkdir(parents=True, exist_ok=True)"""


from pathlib import Path
import os
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

INPUT_FILE = ROOT / "data" / "input" / "member2_ai_intelligence.csv"
KB_DIR = ROOT / "data" / "knowledge_base"
OUTPUT_DIR = ROOT / "data" / "output"
AI_REPORT_DIR = OUTPUT_DIR / "ai_reports"
COMPLIANCE_DIR = OUTPUT_DIR / "compliance_reports"
ANALYSIS_DIR = OUTPUT_DIR / "incident_analysis"

# Azure OpenAI / Microsoft Foundry
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
AZURE_OPENAI_DEPLOYMENT = os.getenv(
    "AZURE_OPENAI_DEPLOYMENT",
    "gpt-4.1-mini"
).strip()

API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8003"))

for d in (AI_REPORT_DIR, COMPLIANCE_DIR, ANALYSIS_DIR):
    d.mkdir(parents=True, exist_ok=True)

"""from pathlib import Path
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from .config import INPUT_FILE, KB_DIR, AI_REPORT_DIR, COMPLIANCE_DIR, ANALYSIS_DIR
from .services.data_service import DataService
from .services.rag_service import RAGService
from .services.compliance_service import ComplianceService
from .services.llm_service import LLMService
from .agents.incident_graph import IncidentGraph

app = FastAPI(title="ClockGuard Member 3 API", version="1.0.0", description="GenAI, RAG, compliance and incident-reporting layer for ClockGuard")
data = DataService(INPUT_FILE)
rag = RAGService(KB_DIR)
compliance = ComplianceService()
llm = LLMService()
graph = IncidentGraph(data, rag, compliance, llm)

class ChatRequest(BaseModel):
    question: str

@app.get("/health")
def health():
    return {"status": "ok", "module": "Member 3", "rows": len(data.df), "input_file": str(INPUT_FILE.name)}

@app.get("/api/summary")
def summary():
    return data.summary()

@app.get("/api/incidents")
def incidents(limit: int = Query(100, ge=1, le=1000), severity: str | None = None, incident_type: str | None = None):
    return data.list_incidents(limit, severity, incident_type)

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    rows = data.get_rows(incident_id)
    if not rows:
        raise HTTPException(404, "Incident not found")
    return {"incident": rows[0], "rows": rows}

@app.get("/api/timeline/{incident_id}")
def timeline(incident_id: str):
    rows = data.get_rows(incident_id)
    if not rows:
        raise HTTPException(404, "Incident not found")
    return [{"timestamp": r["timestamp"], "attack_step": r["attack_step"], "event": r["command"], "evidence": r["evidence"], "incident_type": r["incident_type"]} for r in rows]

@app.get("/api/mitre/{incident_id}")
def mitre(incident_id: str):
    rows = data.get_rows(incident_id)
    if not rows:
        raise HTTPException(404, "Incident not found")
    seen = set(); out=[]
    for r in rows:
        key=(r.get("mitre_technique_id"),r.get("mitre_technique_name"),r.get("mitre_tactic"))
        if key not in seen:
            seen.add(key); out.append({"technique_id":key[0],"technique_name":key[1],"tactic":key[2],"confidence":r.get("mitre_confidence"),"reason":r.get("mitre_reason")})
    return out

@app.get("/api/nist/{incident_id}")
def nist(incident_id: str):
    rows = data.get_rows(incident_id)
    if not rows:
        raise HTTPException(404, "Incident not found")
    return {"function": rows[0].get("nist_function"), "phase": rows[0].get("nist_phase"), "confidence": rows[0].get("nist_confidence"), "reason": rows[0].get("nist_reason")}

@app.get("/api/analyze/{incident_id}")
def analyze(incident_id: str):
    try:
        result = graph.run(incident_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    payload = {"incident": result["incident"], "timeline": result["rows"], "retrieved_context": result["context"], "compliance": result["compliance"], "report": result["report"]}
    (ANALYSIS_DIR / f"{incident_id}.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return payload

@app.post("/api/compliance/{incident_id}")
def compliance_check(incident_id: str):
    rows=data.get_rows(incident_id)
    if not rows: raise HTTPException(404,"Incident not found")
    result=compliance.evaluate(rows)
    (COMPLIANCE_DIR / f"{incident_id}.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    return result

@app.post("/api/report/{incident_id}")
def report(incident_id: str):
    result=graph.run(incident_id)
    report=result["report"]
    (AI_REPORT_DIR / f"{incident_id}.json").write_text(json.dumps(report,indent=2,default=str),encoding="utf-8")
    md=f"# ClockGuard Incident Report\n\n## Executive Summary\n{report.get('executive_summary','')}\n\n## Key Findings\n```json\n{json.dumps(report.get('key_findings',{}),indent=2,default=str)}\n```\n\n## Evidence Assessment\n" + "\n".join(f"- {x}" for x in report.get('evidence_assessment',[])) + "\n\n## Response Actions\n" + "\n".join(f"- {x}" for x in report.get('response_actions',[])) + "\n\n## Compliance\n```json\n" + json.dumps(report.get('compliance_summary',{}),indent=2,default=str) + "\n```\n\n## Limitations\n" + "\n".join(f"- {x}" for x in report.get('limitations',[]))
    (AI_REPORT_DIR / f"{incident_id}.md").write_text(md,encoding="utf-8")
    return report

@app.post("/api/chat/{incident_id}")
def chat(incident_id: str, body: ChatRequest):
    rows=data.get_rows(incident_id)
    if not rows: raise HTTPException(404,"Incident not found")
    i=rows[0]
    context=rag.retrieve(f"{i.get('incident_type')} {i.get('mitre_technique_id')} {i.get('nist_phase')} {body.question}",5)
    comp=compliance.evaluate(rows)
    return {"answer":llm.chat(i,rows,body.question,context,comp),"sources":context}"""

import json

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import (
    INPUT_FILE,
    KB_DIR,
    AI_REPORT_DIR,
    COMPLIANCE_DIR,
    ANALYSIS_DIR,
)

from .services.data_service import DataService
from .services.rag_service import RAGService
from .services.compliance_service import ComplianceService
from .services.llm_service import LLMService
from .agents.incident_graph import IncidentGraph


# =========================================================
# FastAPI Application
# =========================================================

app = FastAPI(
    title="ClockGuard Member 3 API",
    version="1.0.0",
    description=(
        "GenAI, RAG, compliance and incident-reporting "
        "layer for ClockGuard"
    ),
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# Services
# =========================================================

data = DataService(INPUT_FILE)
rag = RAGService(KB_DIR)
compliance = ComplianceService()
llm = LLMService()
graph = IncidentGraph(
    data,
    rag,
    compliance,
    llm,
)


# =========================================================
# Request Models
# =========================================================

class ChatRequest(BaseModel):
    question: str


# =========================================================
# Health
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "module": "Member 3",
        "rows": len(data.df),
        "input_file": str(INPUT_FILE.name),
    }


# =========================================================
# Summary
# =========================================================

@app.get("/api/summary")
def summary():
    return data.summary()


# =========================================================
# Incidents
# =========================================================

@app.get("/api/incidents")
def incidents(
    limit: int = Query(
        100,
        ge=1,
        le=1000,
    ),
    severity: str | None = None,
    incident_type: str | None = None,
):
    return data.list_incidents(
        limit,
        severity,
        incident_type,
    )


# =========================================================
# Incident Details
#
# IMPORTANT:
# Build incident-level values from ALL rows.
# Do not blindly use rows[0] for risk/anomaly/severity.
# =========================================================

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):

    rows = data.get_rows(incident_id)

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    # -----------------------------------------------------
    # Safe numeric helper
    # -----------------------------------------------------

    def num(value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    # -----------------------------------------------------
    # Highest-risk event
    # -----------------------------------------------------

    risk_row = max(
        rows,
        key=lambda r: num(
            r.get("risk_score")
        ),
    )

    # -----------------------------------------------------
    # Highest-anomaly event
    # -----------------------------------------------------

    anomaly_row = max(
        rows,
        key=lambda r: num(
            r.get("anomaly_score")
        ),
    )

    # -----------------------------------------------------
    # Severity hierarchy
    # -----------------------------------------------------

    severity_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    severity_row = max(
        rows,
        key=lambda r: severity_rank.get(
            str(
                r.get(
                    "severity",
                    "",
                )
            ),
            0,
        ),
    )

    # -----------------------------------------------------
    # Start with incident metadata
    # -----------------------------------------------------

    incident_summary = dict(rows[0])

    # -----------------------------------------------------
    # Authoritative incident-level values
    # -----------------------------------------------------

    incident_summary["incident_id"] = incident_id

    incident_summary["risk_score"] = (
        risk_row.get("risk_score")
    )

    incident_summary["severity"] = (
        severity_row.get("severity")
    )

    incident_summary["anomaly_score"] = (
        anomaly_row.get("anomaly_score")
    )

    incident_summary["anomaly_flag"] = any(
        bool(
            r.get("anomaly_flag")
        )
        for r in rows
    )

    incident_summary["event_count"] = len(
        rows
    )

    incident_summary["risk_reason"] = (
        risk_row.get("risk_reason")
    )

    # -----------------------------------------------------
    # Return
    # -----------------------------------------------------

    return {
        "incident": incident_summary,
        "rows": rows,
    }


# =========================================================
# Timeline
#
# IMPORTANT FIX:
# Previously only timestamp, attack_step, event,
# evidence and incident_type were returned.
#
# Now every timeline event also contains:
# - MITRE ATT&CK mapping
# - NIST response state
# - AI/anomaly/risk information
#
# This allows the frontend to build:
#   1. Response Timeline
#   2. MITRE ATT&CK timeline
#   3. Attack Path
#   4. Evidence view
# =========================================================

@app.get("/api/timeline/{incident_id}")
def timeline(incident_id: str):

    rows = data.get_rows(incident_id)

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    timeline_rows = []

    for r in rows:

        timeline_rows.append(
            {
                # -----------------------------------------
                # Time / attack progression
                # -----------------------------------------

                "timestamp": r.get(
                    "timestamp"
                ),

                "attack_step": r.get(
                    "attack_step"
                ),

                # -----------------------------------------
                # Evidence
                # -----------------------------------------

                "event": (
                    r.get("command")
                    or r.get("event")
                    or r.get("evidence")
                ),

                "command": r.get(
                    "command"
                ),

                "evidence": r.get(
                    "evidence"
                ),

                "extracted_evidence": r.get(
                    "extracted_evidence"
                ),

                # -----------------------------------------
                # Incident classification
                # -----------------------------------------

                "incident_type": (
                    r.get("incident_type")
                    or r.get("threat_class")
                ),

                "threat_class": r.get(
                    "threat_class"
                ),

                # -----------------------------------------
                # MITRE ATT&CK
                # -----------------------------------------

                "mitre_technique_id": r.get(
                    "mitre_technique_id"
                ),

                "mitre_technique_name": r.get(
                    "mitre_technique_name"
                ),

                "mitre_tactic": r.get(
                    "mitre_tactic"
                ),

                "mitre_confidence": r.get(
                    "mitre_confidence"
                ),

                "mitre_reason": r.get(
                    "mitre_reason"
                ),

                # -----------------------------------------
                # NIST Incident Response
                # -----------------------------------------

                "nist_function": r.get(
                    "nist_function"
                ),

                "nist_phase": r.get(
                    "nist_phase"
                ),

                "nist_confidence": r.get(
                    "nist_confidence"
                ),

                "nist_reason": r.get(
                    "nist_reason"
                ),

                # -----------------------------------------
                # AI / anomaly / risk
                # -----------------------------------------

                "anomaly_flag": r.get(
                    "anomaly_flag"
                ),

                "anomaly_score": r.get(
                    "anomaly_score"
                ),

                "risk_score": r.get(
                    "risk_score"
                ),

                "severity": r.get(
                    "severity"
                ),

                "risk_reason": r.get(
                    "risk_reason"
                ),
            }
        )

    return timeline_rows


# =========================================================
# MITRE ATT&CK
# =========================================================

@app.get("/api/mitre/{incident_id}")
def mitre(incident_id: str):

    rows = data.get_rows(
        incident_id
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    seen = set()
    out = []

    for r in rows:

        technique_id = r.get(
            "mitre_technique_id"
        )

        technique_name = r.get(
            "mitre_technique_name"
        )

        tactic = r.get(
            "mitre_tactic"
        )

        # Ignore completely empty MITRE records
        if not technique_id and not technique_name:
            continue

        key = (
            technique_id,
            technique_name,
            tactic,
        )

        if key in seen:
            continue

        seen.add(key)

        out.append(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
                "confidence": r.get(
                    "mitre_confidence"
                ),
                "reason": r.get(
                    "mitre_reason"
                ),
            }
        )

    return out


# =========================================================
# NIST
#
# NOTE:
# This remains an INCIDENT-LEVEL endpoint.
# It is not used as the event-by-event timeline.
# =========================================================

@app.get("/api/nist/{incident_id}")
def nist(incident_id: str):

    rows = data.get_rows(
        incident_id
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "function": rows[0].get(
            "nist_function"
        ),
        "phase": rows[0].get(
            "nist_phase"
        ),
        "confidence": rows[0].get(
            "nist_confidence"
        ),
        "reason": rows[0].get(
            "nist_reason"
        ),
    }


# =========================================================
# AI Analysis
# =========================================================

@app.get("/api/analyze/{incident_id}")
def analyze(incident_id: str):

    try:

        result = graph.run(
            incident_id
        )

    except ValueError as e:

        raise HTTPException(
            status_code=404,
            detail=str(e),
        )

    payload = {
        "incident": result["incident"],
        "timeline": result["rows"],
        "retrieved_context": result["context"],
        "compliance": result["compliance"],
        "report": result["report"],
    }

    (
        ANALYSIS_DIR
        / f"{incident_id}.json"
    ).write_text(
        json.dumps(
            payload,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return payload


# =========================================================
# Compliance
# =========================================================

@app.post("/api/compliance/{incident_id}")
def compliance_check(
    incident_id: str,
):

    rows = data.get_rows(
        incident_id
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    result = compliance.evaluate(
        rows
    )

    (
        COMPLIANCE_DIR
        / f"{incident_id}.json"
    ).write_text(
        json.dumps(
            result,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return result


# =========================================================
# Report Generation
# =========================================================

@app.post("/api/report/{incident_id}")
def report(incident_id: str):

    try:
        result = graph.run(
            incident_id
        )
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e),
        )

    report_data = result["report"]

    (
        AI_REPORT_DIR
        / f"{incident_id}.json"
    ).write_text(
        json.dumps(
            report_data,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    markdown_report = (
        "# ClockGuard Incident Report\n\n"

        "## Executive Summary\n"
        f"{report_data.get('executive_summary', '')}\n\n"

        "## Key Findings\n"
        "```json\n"
        f"{json.dumps(report_data.get('key_findings', {}), indent=2, default=str)}"
        "\n```\n\n"

        "## Evidence Assessment\n"
        + "\n".join(
            f"- {x}"
            for x in report_data.get(
                "evidence_assessment",
                [],
            )
        )
        + "\n\n"

        "## Response Actions\n"
        + "\n".join(
            f"- {x}"
            for x in report_data.get(
                "response_actions",
                [],
            )
        )
        + "\n\n"

        "## Compliance\n"
        "```json\n"
        + json.dumps(
            report_data.get(
                "compliance_summary",
                {},
            ),
            indent=2,
            default=str,
        )
        + "\n```\n\n"

        "## Limitations\n"
        + "\n".join(
            f"- {x}"
            for x in report_data.get(
                "limitations",
                [],
            )
        )
    )

    (
        AI_REPORT_DIR
        / f"{incident_id}.md"
    ).write_text(
        markdown_report,
        encoding="utf-8",
    )

    return report_data


# =========================================================
# Investigator Chat
# =========================================================

@app.post("/api/chat/{incident_id}")
def chat(
    incident_id: str,
    body: ChatRequest,
):

    rows = data.get_rows(
        incident_id
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    incident_data = rows[0]

    context = rag.retrieve(
        f"{incident_data.get('incident_type')} "
        f"{incident_data.get('mitre_technique_id')} "
        f"{incident_data.get('nist_phase')} "
        f"{body.question}",
        5,
    )

    comp = compliance.evaluate(
        rows
    )

    answer = llm.chat(
        incident_data,
        rows,
        body.question,
        context,
        comp,
    )

    return {
        "answer": answer,
        "sources": context,
    }
import json

from . import __init__

from ..config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_DEPLOYMENT,
)


class LLMService:
    """
    ClockGuard Azure OpenAI / Microsoft Foundry LLM service.

    Responsibilities:
    - Generate evidence-grounded incident investigation reports.
    - Explain existing Member 2 risk/anomaly signals.
    - Answer contextual SOC investigation questions.
    - Never recalculate or invent security signals.
    - Provide deterministic fallback output if Azure is unavailable.
    """

    # =========================================================
    # INITIALIZATION
    # =========================================================

    def __init__(self):
        self.client = None
        self.init_error = None

        if AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT:
            try:
                from openai import OpenAI

                endpoint = AZURE_OPENAI_ENDPOINT.rstrip("/")

                self.client = OpenAI(
                    api_key=AZURE_OPENAI_API_KEY,
                    base_url=f"{endpoint}/openai/v1/",
                )

            except Exception as exc:
                self.init_error = str(exc)
                self.client = None

        else:
            self.init_error = (
                "AZURE_OPENAI_API_KEY or "
                "AZURE_OPENAI_ENDPOINT is missing from .env"
            )

    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def _unique_techniques(rows):
        """
        Extract unique MITRE techniques from supplied backend rows.
        """

        techniques = []
        seen = set()

        for row in rows or []:
            technique_id = row.get("mitre_technique_id")
            technique_name = row.get("mitre_technique_name")
            tactic = row.get("mitre_tactic")
            confidence = row.get("mitre_confidence")
            reason = row.get("mitre_reason")

            if not technique_id:
                continue

            key = (
                str(technique_id),
                str(technique_name),
            )

            if key in seen:
                continue

            seen.add(key)

            techniques.append(
                {
                    "id": technique_id,
                    "name": technique_name,
                    "tactic": tactic,
                    "confidence": confidence,
                    "reason": reason,
                }
            )

        return techniques

    @staticmethod
    def _unique_evidence(rows, limit=20):
        """
        Extract unique evidence records while preserving order.
        """

        evidence = []
        seen = set()

        for row in rows or []:
            value = row.get("evidence")

            if not value:
                continue

            value = str(value).strip()

            if not value or value in seen:
                continue

            seen.add(value)

            evidence.append(
                {
                    "timestamp": row.get("timestamp"),
                    "command": row.get("command"),
                    "evidence": value,
                    "attack_step": row.get("attack_step"),
                    "threat_class": row.get("threat_class"),
                    "mitre_technique_id": row.get(
                        "mitre_technique_id"
                    ),
                    "mitre_technique_name": row.get(
                        "mitre_technique_name"
                    ),
                }
            )

            if len(evidence) >= limit:
                break

        return evidence

    @staticmethod
    def _timeline(rows, limit=30):
        """
        Build an evidence-grounded timeline.
        """

        timeline = []

        for row in rows or []:
            timeline.append(
                {
                    "timestamp": row.get("timestamp"),
                    "attack_step": row.get("attack_step"),
                    "command": row.get("command"),
                    "evidence": row.get("evidence"),
                    "threat_class": row.get("threat_class"),
                    "mitre_technique_id": row.get(
                        "mitre_technique_id"
                    ),
                    "mitre_technique_name": row.get(
                        "mitre_technique_name"
                    ),
                    "mitre_tactic": row.get("mitre_tactic"),
                }
            )

            if len(timeline) >= limit:
                break

        return timeline

    # =========================================================
    # MARKDOWN REPORT
    # =========================================================

    def _build_markdown_report(
        self,
        incident,
        report,
    ):
        """
        Convert structured report data into a clean Markdown
        report that the frontend can display/download.
        """

        executive_summary = report.get(
            "executive_summary",
            "No executive summary was generated.",
        )

        evidence = report.get(
            "evidence_assessment",
            [],
        )

        mitre = report.get(
            "mitre_interpretation",
            [],
        )

        nist = report.get(
            "nist_response_state",
            {},
        )

        risk = report.get(
            "risk_explanation",
            {},
        )

        actions = report.get(
            "response_actions",
            [],
        )

        compliance = report.get(
            "compliance_summary",
            {},
        )

        timeline = report.get(
            "timeline_notes",
            [],
        )

        limitations = report.get(
            "limitations",
            [],
        )

        lines = []

        lines.append("# CLOCKGUARD SECURITY OPERATIONS")
        lines.append("")
        lines.append("# Incident Investigation Report")
        lines.append("")

        lines.append(
            f"**Incident:** "
            f"{incident.get('incident_id', 'Unknown')}"
        )

        lines.append(
            f"**Severity:** "
            f"{incident.get('severity', 'Unknown')}"
        )

        lines.append(
            f"**Risk Score:** "
            f"{incident.get('risk_score', 'Unknown')}"
        )

        lines.append("")

        # -----------------------------------------------------
        # Executive Summary
        # -----------------------------------------------------

        lines.append("## Executive Summary")
        lines.append("")
        lines.append(str(executive_summary))
        lines.append("")

        # -----------------------------------------------------
        # Evidence
        # -----------------------------------------------------

        lines.append("## Evidence")
        lines.append("")

        if evidence:
            for index, item in enumerate(evidence, start=1):
                lines.append(
                    f"### Evidence {index}"
                )

                if item.get("timestamp"):
                    lines.append(
                        f"- **Timestamp:** "
                        f"{item.get('timestamp')}"
                    )

                if item.get("command"):
                    lines.append(
                        f"- **Command:** "
                        f"`{item.get('command')}`"
                    )

                if item.get("threat_class"):
                    lines.append(
                        f"- **Threat class:** "
                        f"{item.get('threat_class')}"
                    )

                if item.get("evidence"):
                    lines.append(
                        f"- **Observed evidence:** "
                        f"{item.get('evidence')}"
                    )

                lines.append("")

        else:
            lines.append(
                "No explicit evidence records were supplied "
                "for this incident."
            )
            lines.append("")

        # -----------------------------------------------------
        # MITRE
        # -----------------------------------------------------

        lines.append(
            "## MITRE ATT&CK Interpretation"
        )
        lines.append("")

        if mitre:
            for item in mitre:
                technique_id = item.get(
                    "id",
                    "Unknown",
                )

                technique_name = item.get(
                    "name",
                    "Unknown technique",
                )

                lines.append(
                    f"### {technique_id} — "
                    f"{technique_name}"
                )

                if item.get("tactic"):
                    lines.append(
                        f"- **Tactic:** "
                        f"{item.get('tactic')}"
                    )

                if item.get("confidence"):
                    lines.append(
                        f"- **Confidence:** "
                        f"{item.get('confidence')}"
                    )

                if item.get("reason"):
                    lines.append(
                        f"- **Mapping basis:** "
                        f"{item.get('reason')}"
                    )

                lines.append("")

        else:
            lines.append(
                "No MITRE ATT&CK technique mapping "
                "was supplied for this incident."
            )
            lines.append("")

        # -----------------------------------------------------
        # NIST
        # -----------------------------------------------------

        lines.append(
            "## NIST Response State"
        )
        lines.append("")

        if nist:
            if nist.get("function"):
                lines.append(
                    f"- **Function:** "
                    f"{nist.get('function')}"
                )

            if nist.get("phase"):
                lines.append(
                    f"- **Phase:** "
                    f"{nist.get('phase')}"
                )

            if nist.get("confidence"):
                lines.append(
                    f"- **Confidence:** "
                    f"{nist.get('confidence')}"
                )

            if nist.get("reason"):
                lines.append(
                    f"- **Reason:** "
                    f"{nist.get('reason')}"
                )

        else:
            lines.append(
                "No NIST response-state information "
                "was supplied."
            )

        lines.append("")
        lines.append(
            "NIST response-state labels in ClockGuard "
            "are derived from observed evidence and are "
            "not CAM-LDS ground truth."
        )
        lines.append("")

        # -----------------------------------------------------
        # Risk
        # -----------------------------------------------------

        lines.append(
            "## Risk Explanation"
        )
        lines.append("")

        if risk:
            if risk.get("risk_score") is not None:
                lines.append(
                    f"- **Risk score:** "
                    f"{risk.get('risk_score')}"
                )

            if risk.get("severity"):
                lines.append(
                    f"- **Severity:** "
                    f"{risk.get('severity')}"
                )

            if risk.get("anomaly_flag") is not None:
                lines.append(
                    f"- **Anomaly detected:** "
                    f"{risk.get('anomaly_flag')}"
                )

            if risk.get("anomaly_score") is not None:
                lines.append(
                    f"- **Anomaly score:** "
                    f"{risk.get('anomaly_score')}"
                )

            if risk.get("explanation"):
                lines.append("")
                lines.append(
                    risk.get("explanation")
                )

        lines.append("")

        # -----------------------------------------------------
        # Actions
        # -----------------------------------------------------

        lines.append(
            "## Recommended Actions"
        )
        lines.append("")

        if actions:
            for action in actions:
                lines.append(
                    f"- {action}"
                )

        else:
            lines.append(
                "No additional response actions "
                "were generated."
            )

        lines.append("")

        # -----------------------------------------------------
        # Compliance
        # -----------------------------------------------------

        lines.append(
            "## Compliance Considerations"
        )
        lines.append("")

        if isinstance(compliance, dict):

            if compliance.get("status"):
                lines.append(
                    f"- **Status:** "
                    f"{compliance.get('status')}"
                )

            if compliance.get("review_required") is not None:
                lines.append(
                    f"- **Manual review required:** "
                    f"{compliance.get('review_required')}"
                )

            if compliance.get("jurisdiction"):
                lines.append(
                    f"- **Jurisdiction:** "
                    f"{compliance.get('jurisdiction')}"
                )

            if compliance.get("regulations"):
                lines.append(
                    f"- **Regulations:** "
                    f"{compliance.get('regulations')}"
                )

            if compliance.get("reason"):
                lines.append("")
                lines.append(
                    compliance.get("reason")
                )

        elif compliance:
            lines.append(
                str(compliance)
            )

        else:
            lines.append(
                "No specific compliance determination "
                "was supplied. Manual review is recommended."
            )

        lines.append("")

        # -----------------------------------------------------
        # Timeline
        # -----------------------------------------------------

        lines.append(
            "## Timeline Notes"
        )
        lines.append("")

        if timeline:
            for item in timeline:

                timestamp = item.get(
                    "timestamp",
                    "Unknown time",
                )

                description = (
                    item.get("evidence")
                    or item.get("command")
                    or item.get("threat_class")
                    or "Observed event"
                )

                lines.append(
                    f"- **{timestamp}** — "
                    f"{description}"
                )

        else:
            lines.append(
                "No timeline records were supplied."
            )

        lines.append("")

        # -----------------------------------------------------
        # Limitations
        # -----------------------------------------------------

        if limitations:
            lines.append("## Analyst Limitations")
            lines.append("")

            for item in limitations:
                lines.append(
                    f"- {item}"
                )

            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "Generated by ClockGuard Security Operations "
            "using Azure GPT-4.1-mini."
        )

        return "\n".join(lines)

    # =========================================================
    # DETERMINISTIC FALLBACK
    # =========================================================

    def _fallback(
        self,
        incident,
        rows,
        context,
        compliance,
    ):
        """
        Complete report fallback.

        This ensures the report still contains all major
        sections even if Azure OpenAI is unavailable.
        """

        techniques = self._unique_techniques(rows)
        evidence = self._unique_evidence(rows)
        timeline = self._timeline(rows)

        incident_type = (
            incident.get("incident_type")
            or incident.get("threat_class")
            or "Unknown"
        )

        severity = (
            incident.get("severity")
            or "Review"
        )

        risk_score = incident.get(
            "risk_score"
        )

        anomaly_flag = incident.get(
            "anomaly_flag"
        )

        anomaly_score = incident.get(
            "anomaly_score"
        )

        nist_phase = incident.get(
            "nist_phase"
        )

        nist_function = incident.get(
            "nist_function"
        )

        nist_reason = incident.get(
            "nist_reason"
        )

        # -----------------------------------------------------
        # Executive summary
        # -----------------------------------------------------

        summary = (
            f"The incident is classified as "
            f"{incident_type} with severity "
            f"{severity} and a supplied risk score "
            f"of {risk_score}. "
        )

        if anomaly_flag is not None:
            summary += (
                f"Member 2 anomaly detection recorded "
                f"anomaly={anomaly_flag}"
            )

            if anomaly_score is not None:
                summary += (
                    f" with an anomaly score of "
                    f"{anomaly_score}."
                )
            else:
                summary += "."

        summary += (
            " The investigation uses the existing "
            "ClockGuard security signals and does not "
            "recalculate the supplied risk or anomaly "
            "values."
        )

        # -----------------------------------------------------
        # Risk explanation
        # -----------------------------------------------------

        risk_explanation = (
            f"The supplied risk score is {risk_score} "
            f"with severity {severity}. "
        )

        if anomaly_flag is not None:
            risk_explanation += (
                f"The Member 2 pipeline recorded "
                f"anomaly={anomaly_flag}"
            )

            if anomaly_score is not None:
                risk_explanation += (
                    f" and anomaly score "
                    f"{anomaly_score}."
                )
            else:
                risk_explanation += "."

        risk_explanation += (
            " These values are supplied by the upstream "
            "AI intelligence pipeline and are not "
            "recalculated by the investigation layer."
        )

        # -----------------------------------------------------
        # Actions
        # -----------------------------------------------------

        actions = [
            (
                "Preserve the supplied evidence and "
                "maintain the event timeline."
            ),
            (
                "Validate the observed activity against "
                "the affected host, account and surrounding "
                "security logs."
            ),
            (
                "Review the mapped MITRE ATT&CK techniques "
                "and determine whether the activity is "
                "consistent with malicious behavior."
            ),
            (
                "Investigate the scope of the incident "
                "before taking containment actions."
            ),
            (
                "If malicious activity is confirmed, "
                "follow the organization's approved "
                "containment and eradication procedures."
            ),
            (
                "Document evidence handling, decisions, "
                "approvals and investigation outcomes."
            ),
        ]

        # -----------------------------------------------------
        # Compliance
        # -----------------------------------------------------

        compliance_output = (
            compliance
            if isinstance(compliance, dict)
            else {
                "status": "Review Required",
                "review_required": True,
                "reason": (
                    "No jurisdiction-specific legal "
                    "determination is inferred from the "
                    "available incident data."
                ),
            }
        )

        report = {
            "executive_summary": summary,

            "key_findings": {
                "incident_id": incident.get(
                    "incident_id"
                ),
                "incident_type": incident_type,
                "severity": severity,
                "risk_score": risk_score,
                "anomaly_flag": anomaly_flag,
                "anomaly_score": anomaly_score,
                "evidence_count": len(evidence),
                "technique_count": len(techniques),
            },

            "evidence_assessment": evidence,

            "mitre_interpretation": techniques,

            "nist_response_state": {
                "function": nist_function,
                "phase": nist_phase,
                "confidence": "Derived",
                "reason": nist_reason,
            },

            "risk_explanation": {
                "risk_score": risk_score,
                "severity": severity,
                "anomaly_flag": anomaly_flag,
                "anomaly_score": anomaly_score,
                "explanation": risk_explanation,
            },

            "response_actions": actions,

            "compliance_summary": compliance_output,

            "timeline_notes": timeline,

            "retrieved_context": [
                {
                    "source": item.get("source"),
                    "score": item.get("score"),
                }
                for item in context or []
                if isinstance(item, dict)
            ],

            "limitations": [
                (
                    "NIST response-state labels are derived "
                    "by ClockGuard and are not CAM-LDS "
                    "ground truth."
                ),
                (
                    "No legal notification deadline is "
                    "inferred without jurisdiction and "
                    "applicable law."
                ),
                (
                    "Recommendations are analyst-support "
                    "guidance and require human validation."
                ),
            ],

            "generation_mode": "deterministic_fallback",
        }

        report["report_markdown"] = (
            self._build_markdown_report(
                incident,
                report,
            )
        )

        return report

    # =========================================================
    # AZURE OPENAI REPORT GENERATION
    # =========================================================

    def generate_report(
        self,
        incident,
        rows,
        context,
        compliance,
    ):
        """
        Generate a complete structured investigation report.
        """

        # -----------------------------------------------------
        # Azure unavailable
        # -----------------------------------------------------

        if not self.client:
            fallback = self._fallback(
                incident,
                rows,
                context,
                compliance,
            )

            fallback["llm_error"] = (
                "Azure OpenAI client was not initialized: "
                + str(self.init_error)
            )

            return fallback

        # -----------------------------------------------------
        # Prepare grounded input
        # -----------------------------------------------------

        techniques = self._unique_techniques(rows)
        evidence = self._unique_evidence(rows)
        timeline = self._timeline(rows)

        grounded_data = {
            "incident": incident,
            "mitre_techniques": techniques,
            "evidence": evidence,
            "timeline": timeline,
            "retrieved_context": context,
            "compliance": compliance,
        }

        # -----------------------------------------------------
        # Strong structured prompt
        # -----------------------------------------------------

        prompt = {
            "incident_data": grounded_data,

            "task": (
                "Generate a complete cybersecurity incident "
                "investigation report for ClockGuard."
            ),

            "strict_rules": [
                (
                    "Use ONLY the supplied incident data, "
                    "evidence and retrieved context."
                ),
                (
                    "Do not invent facts, users, hosts, "
                    "systems, attackers, attribution or "
                    "additional attack activity."
                ),
                (
                    "Do not invent legal requirements, "
                    "jurisdictions or notification deadlines."
                ),
                (
                    "Do not recalculate risk_score."
                ),
                (
                    "Do not recalculate anomaly_score."
                ),
                (
                    "Explain existing Member 2 AI signals "
                    "instead of replacing them."
                ),
                (
                    "MITRE techniques must come only from "
                    "the supplied MITRE technique records."
                ),
                (
                    "NIST response state is derived by "
                    "ClockGuard and is NOT CAM-LDS ground truth."
                ),
                (
                    "If information is missing, explicitly "
                    "say that it was not supplied."
                ),
                (
                    "Recommended actions must be practical "
                    "SOC analyst guidance, not unsupported facts."
                ),
            ],

            "required_output": {
                "executive_summary": (
                    "Detailed 1-2 paragraph summary explaining "
                    "what happened, why the incident matters, "
                    "severity, supplied risk/anomaly signals, "
                    "and the observed attack stage."
                ),

                "evidence_assessment": (
                    "Array of detailed evidence records. "
                    "Explain what each supplied evidence item "
                    "shows and why it matters."
                ),

                "mitre_interpretation": (
                    "Array containing every supplied unique "
                    "MITRE technique with id, name, tactic, "
                    "confidence and evidence-grounded explanation."
                ),

                "nist_response_state": (
                    "Object containing function, phase, "
                    "confidence and explanation. Clearly "
                    "state that the NIST state is derived."
                ),

                "risk_explanation": (
                    "Object explaining the supplied risk score, "
                    "severity, anomaly flag and anomaly score. "
                    "Do not calculate a new score."
                ),

                "response_actions": (
                    "Array of specific, evidence-grounded "
                    "SOC investigation and response actions."
                ),

                "compliance_summary": (
                    "Object describing the supplied compliance "
                    "screening. Do not invent regulations, "
                    "jurisdictions or deadlines."
                ),

                "timeline_notes": (
                    "Array of chronological notes based only "
                    "on supplied timestamps, commands and evidence."
                ),

                "limitations": (
                    "Array of important limitations and "
                    "uncertainties."
                ),
            },
        }

        # -----------------------------------------------------
        # Azure request
        # -----------------------------------------------------

        try:
            response = self.client.chat.completions.create(
                model=AZURE_OPENAI_DEPLOYMENT,
                temperature=0.1,
                response_format={
                    "type": "json_object"
                },
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are ClockGuard, an enterprise "
                            "SOC incident-response analyst. "
                            "Produce complete, professional, "
                            "evidence-grounded cybersecurity "
                            "investigation reports. "
                            "Never invent missing information."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            prompt,
                            default=str,
                        ),
                    },
                ],
            )

            content = (
                response.choices[0]
                .message
                .content
            )

            if not content:
                raise ValueError(
                    "Azure OpenAI returned an empty response."
                )

            result = json.loads(content)

            # -------------------------------------------------
            # Make sure required sections exist
            # -------------------------------------------------

            result.setdefault(
                "executive_summary",
                "No executive summary was generated.",
            )

            result.setdefault(
                "evidence_assessment",
                evidence,
            )

            result.setdefault(
                "mitre_interpretation",
                techniques,
            )

            result.setdefault(
                "nist_response_state",
                {
                    "function": incident.get(
                        "nist_function"
                    ),
                    "phase": incident.get(
                        "nist_phase"
                    ),
                    "confidence": "Derived",
                    "reason": incident.get(
                        "nist_reason"
                    ),
                },
            )

            result.setdefault(
                "risk_explanation",
                {
                    "risk_score": incident.get(
                        "risk_score"
                    ),
                    "severity": incident.get(
                        "severity"
                    ),
                    "anomaly_flag": incident.get(
                        "anomaly_flag"
                    ),
                    "anomaly_score": incident.get(
                        "anomaly_score"
                    ),
                    "explanation": (
                        "Risk values are supplied by "
                        "Member 2 and were not recalculated."
                    ),
                },
            )

            result.setdefault(
                "response_actions",
                [],
            )

            result.setdefault(
                "compliance_summary",
                compliance,
            )

            result.setdefault(
                "timeline_notes",
                timeline,
            )

            result.setdefault(
                "limitations",
                [],
            )

            result["generation_mode"] = (
                "azure_openai"
            )

            result["model"] = (
                AZURE_OPENAI_DEPLOYMENT
            )

            # -------------------------------------------------
            # Generate downloadable Markdown representation
            # -------------------------------------------------

            result["report_markdown"] = (
                self._build_markdown_report(
                    incident,
                    result,
                )
            )

            return result

        # -----------------------------------------------------
        # Azure failure
        # -----------------------------------------------------

        except Exception as exc:

            fallback = self._fallback(
                incident,
                rows,
                context,
                compliance,
            )

            fallback["llm_error"] = str(exc)

            return fallback

    # =========================================================
    # AI SOC CHAT
    # =========================================================

    def chat(
        self,
        incident,
        rows,
        question,
        context,
        compliance,
    ):
        """
        Context-aware SOC assistant.
        """

        # -----------------------------------------------------
        # Fallback mode
        # -----------------------------------------------------

        if not self.client:

            q = str(question).lower()

            if "why" in q and "risk" in q:
                return {
                    "answer": (
                        f"The supplied Member 2 risk score "
                        f"is {incident.get('risk_score')} "
                        f"with severity "
                        f"{incident.get('severity')}. "
                        f"The recorded reason is: "
                        f"{incident.get('risk_reason') or 'Not supplied.'}"
                    ),
                    "generation_mode": "fallback",
                }

            if "mitre" in q:

                techniques = self._unique_techniques(
                    rows
                )

                answer = "; ".join(
                    f"{x['id']}: {x['name']}"
                    for x in techniques
                )

                return {
                    "answer": (
                        answer
                        or "No MITRE technique data found."
                    ),
                    "generation_mode": "fallback",
                }

            if "nist" in q:

                return {
                    "answer": (
                        f"The supplied NIST response "
                        f"phase is "
                        f"{incident.get('nist_phase')}. "
                        f"It is marked as derived. "
                        f"Reason: "
                        f"{incident.get('nist_reason') or 'Not supplied.'}"
                    ),
                    "generation_mode": "fallback",
                }

            return {
                "answer": (
                    "I can explain the supplied evidence, "
                    "risk, MITRE mapping, NIST response state, "
                    "timeline, compliance screening and "
                    "recommended response actions. "
                    "I will not invent missing facts."
                ),
                "generation_mode": "fallback",
            }

        # -----------------------------------------------------
        # Azure chat
        # -----------------------------------------------------

        prompt = {
            "incident": incident,
            "evidence": rows[:20],
            "context": context,
            "compliance": compliance,
            "question": question,
            "rules": [
                (
                    "Answer only from supplied incident "
                    "data and retrieved context."
                ),
                (
                    "Do not invent facts, systems, users, "
                    "attackers or attribution."
                ),
                (
                    "Do not invent legal deadlines."
                ),
                (
                    "Do not recalculate risk or anomaly scores."
                ),
                (
                    "Clearly distinguish derived NIST "
                    "response-state information."
                ),
            ],
        }

        try:

            response = self.client.chat.completions.create(
                model=AZURE_OPENAI_DEPLOYMENT,
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are the ClockGuard AI SOC "
                            "Assistant. Give concise, "
                            "professional, evidence-grounded "
                            "answers for security analysts."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            prompt,
                            default=str,
                        ),
                    },
                ],
            )

            answer = (
                response.choices[0]
                .message
                .content
            )

            return {
                "answer": answer,
                "generation_mode": "azure_openai",
                "model": AZURE_OPENAI_DEPLOYMENT,
            }

        except Exception as exc:

            return {
                "answer": (
                    "Azure OpenAI request failed. "
                    "The supplied incident evidence remains "
                    "available for analyst review."
                ),
                "generation_mode": "fallback",
                "llm_error": str(exc),
            }
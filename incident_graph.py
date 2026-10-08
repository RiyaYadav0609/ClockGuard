"""from typing import TypedDict, Any
from langgraph.graph import StateGraph, END

class IncidentState(TypedDict, total=False):
    incident: dict
    rows: list
    context: list
    compliance: dict
    report: dict

class IncidentGraph:
    def __init__(self, data_service, rag_service, compliance_service, llm_service):
        self.data = data_service
        self.rag = rag_service
        self.compliance = compliance_service
        self.llm = llm_service
        graph = StateGraph(IncidentState)
        graph.add_node("load_incident", self.load_incident)
        graph.add_node("retrieve_context", self.retrieve_context)
        graph.add_node("compliance_check", self.compliance_check)
        graph.add_node("generate_report", self.generate_report)
        graph.set_entry_point("load_incident")
        graph.add_edge("load_incident", "retrieve_context")
        graph.add_edge("retrieve_context", "compliance_check")
        graph.add_edge("compliance_check", "generate_report")
        graph.add_edge("generate_report", END)
        self.app = graph.compile()

    def load_incident(self, state):
        rows = self.data.get_rows(state["incident_id"])
        if not rows:
            raise ValueError("Incident not found")
        return {"incident": rows[0], "rows": rows}

    def retrieve_context(self, state):
        i = state["incident"]
        q = " ".join(str(i.get(k, "")) for k in ["incident_type", "threat_class", "mitre_technique_id", "mitre_technique_name", "nist_phase", "severity"])
        return {"context": self.rag.retrieve(q, top_k=5)}

    def compliance_check(self, state):
        return {"compliance": self.compliance.evaluate(state["rows"])}

    def generate_report(self, state):
        return {"report": self.llm.generate_report(state["incident"], state["rows"], state["context"], state["compliance"])}

    def run(self, incident_id):
        result = self.app.invoke({"incident_id": incident_id})
        return result"""

from typing import TypedDict
from langgraph.graph import StateGraph, END


class IncidentState(TypedDict, total=False):
    incident_id: str
    incident: dict
    rows: list
    context: list
    compliance: dict
    report: dict


class IncidentGraph:
    def __init__(
        self,
        data_service,
        rag_service,
        compliance_service,
        llm_service,
    ):
        self.data = data_service
        self.rag = rag_service
        self.compliance = compliance_service
        self.llm = llm_service

        graph = StateGraph(IncidentState)

        # Nodes
        graph.add_node("load_incident", self.load_incident)
        graph.add_node("retrieve_context", self.retrieve_context)
        graph.add_node("compliance_check", self.compliance_check)
        graph.add_node("generate_report", self.generate_report)

        # Flow
        graph.set_entry_point("load_incident")

        graph.add_edge(
            "load_incident",
            "retrieve_context",
        )

        graph.add_edge(
            "retrieve_context",
            "compliance_check",
        )

        graph.add_edge(
            "compliance_check",
            "generate_report",
        )

        graph.add_edge(
            "generate_report",
            END,
        )

        # Compile LangGraph application
        self.app = graph.compile()

    def load_incident(self, state: IncidentState) -> dict:
        """
        Load all rows belonging to the selected incident.
        """

        incident_id = state.get("incident_id")

        if not incident_id:
            raise ValueError("incident_id is required")

        rows = self.data.get_rows(incident_id)

        if not rows:
            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        return {
            "incident_id": incident_id,
            "incident": rows[0],
            "rows": rows,
        }

    def retrieve_context(self, state: IncidentState) -> dict:
        """
        Retrieve relevant MITRE/NIST/compliance context
        from the local RAG knowledge base.
        """

        incident = state.get("incident", {})

        query_fields = [
            "incident_type",
            "threat_class",
            "mitre_technique_id",
            "mitre_technique_name",
            "nist_phase",
            "severity",
        ]

        query = " ".join(
            str(incident.get(field, ""))
            for field in query_fields
            if incident.get(field)
        )

        context = self.rag.retrieve(
            query,
            top_k=5,
        )

        return {
            "context": context
        }

    def compliance_check(self, state: IncidentState) -> dict:
        """
        Run conservative compliance screening
        using the incident evidence.
        """

        rows = state.get("rows", [])

        compliance_result = self.compliance.evaluate(
            rows
        )

        return {
            "compliance": compliance_result
        }

    def generate_report(self, state: IncidentState) -> dict:
        """
        Generate the final AI-assisted incident report
        using incident data, evidence, RAG context,
        and compliance findings.
        """

        incident = state.get("incident", {})
        rows = state.get("rows", [])
        context = state.get("context", [])
        compliance = state.get("compliance", {})

        report = self.llm.generate_report(
            incident,
            rows,
            context,
            compliance,
        )

        return {
            "report": report
        }

    def run(self, incident_id: str) -> dict:
        """
        Execute the complete LangGraph workflow.

        Flow:
        Incident
            ↓
        Load incident
            ↓
        Retrieve RAG context
            ↓
        Compliance check
            ↓
        OpenAI / fallback report generation
        """

        if not incident_id:
            raise ValueError(
                "incident_id cannot be empty"
            )

        result = self.app.invoke(
            {
                "incident_id": incident_id
            }
        )

        return result

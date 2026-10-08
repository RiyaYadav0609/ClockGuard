from pathlib import Path
import pandas as pd

REQUIRED = [
    "incident_id", "sequence_id", "attack_step", "timestamp", "command_type",
    "command", "evidence", "threat_class", "mitre_technique_id",
    "mitre_technique_name", "mitre_tactic", "mitre_confidence", "mitre_reason",
    "nist_function", "nist_phase", "nist_confidence", "nist_reason",
    "source_dataset", "anomaly_flag", "anomaly_score", "anomaly_method",
    "incident_type", "classification_reason", "extracted_evidence", "risk_score",
    "severity", "risk_reason"
]

class DataService:
    def __init__(self, csv_path: Path):
        self.csv_path = Path(csv_path)
        self.df = pd.read_csv(self.csv_path)
        missing = [c for c in REQUIRED if c not in self.df.columns]
        if missing:
            raise ValueError(f"Member 2 CSV is missing columns: {missing}")
        self.df["timestamp"] = self.df["timestamp"].astype(str)
        self.df["anomaly_flag"] = self.df["anomaly_flag"].astype(bool)
        self.df["risk_score"] = pd.to_numeric(self.df["risk_score"], errors="coerce").fillna(0)
        self.df["anomaly_score"] = pd.to_numeric(self.df["anomaly_score"], errors="coerce").fillna(0)

    def _records(self, frame):
        return frame.where(pd.notna(frame), None).to_dict(orient="records")

    def list_incidents(self, limit=100, severity=None, incident_type=None):
        d = self.df
        if severity:
            d = d[d["severity"].astype(str).str.lower() == severity.lower()]
        if incident_type:
            d = d[d["incident_type"].astype(str).str.lower() == incident_type.lower()]
        d = d.sort_values(["timestamp", "attack_step"], kind="stable")
        return self._records(d.head(limit))

    def get_incident(self, incident_id):
        d = self.df[self.df["incident_id"].astype(str) == str(incident_id)]
        if d.empty:
            return None
        d = d.sort_values(["timestamp", "attack_step"], kind="stable")
        return self._records(d)[0]

    def get_rows(self, incident_id):
        d = self.df[self.df["incident_id"].astype(str) == str(incident_id)]
        d = d.sort_values(["timestamp", "attack_step"], kind="stable")
        return self._records(d)

    def summary(self):
        s = self.df["severity"].value_counts().to_dict()
        types = self.df["incident_type"].value_counts().to_dict()
        return {
            "rows": int(len(self.df)),
            "unique_incidents": int(self.df["incident_id"].nunique()),
            "anomalies": int(self.df["anomaly_flag"].sum()),
            "critical": int(s.get("Critical", 0)),
            "high": int(s.get("High", 0)),
            "medium": int(s.get("Medium", 0)),
            "low": int(s.get("Low", 0)),
            "incident_types": types,
            "source_dataset": sorted(self.df["source_dataset"].dropna().astype(str).unique().tolist()),
        }

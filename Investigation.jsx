import { useEffect, useMemo, useState } from 'react';
import { Panel, AttackGraph } from '../components/Widgets';

export default function Investigation({
  incident,
  rows,
  api,
  setPage,
  setAnalysis,
  analysis,
}) {
  const [busy, setBusy] = useState(false);
  const [mitreData, setMitreData] = useState([]);

  // ---------------------------------------------------------
  // HOOKS
  // IMPORTANT: ALL HOOKS RUN BEFORE ANY CONDITIONAL RETURN
  // ---------------------------------------------------------

  useEffect(() => {
    setAnalysis(null);
    setMitreData([]);
  }, [incident?.incident_id, setAnalysis]);

  // ---------------------------------------------------------
  // SELECTED INCIDENT
  // The selected incident remains authoritative for:
  // risk, severity and anomaly values.
  // ---------------------------------------------------------

  const selectedIncident = incident || {};

  const safeRows = Array.isArray(rows) ? rows : [];

  // ---------------------------------------------------------
  // LOAD MITRE DATA
  // Uses the backend /api/mitre/{incident_id} endpoint.
  // This does NOT recalculate or modify any risk value.
  // ---------------------------------------------------------

  useEffect(() => {
    let cancelled = false;

    const loadMitre = async () => {
      if (!selectedIncident.incident_id || !api?.mitre) {
        return;
      }

      try {
        const result = await api.mitre(
          selectedIncident.incident_id
        );

        if (cancelled) return;

        if (Array.isArray(result)) {
          setMitreData(result);
        } else if (Array.isArray(result?.techniques)) {
          setMitreData(result.techniques);
        } else {
          setMitreData([]);
        }
      } catch (error) {
        if (!cancelled) {
          console.warn(
            'MITRE data could not be loaded:',
            error
          );
          setMitreData([]);
        }
      }
    };

    loadMitre();

    return () => {
      cancelled = true;
    };
  }, [selectedIncident.incident_id, api]);

  // ---------------------------------------------------------
  // RISK BREAKDOWN
  // VISUALIZATION ONLY
  // Does NOT recalculate authoritative backend risk.
  // ---------------------------------------------------------

  const breakdown = useMemo(() => {
    const r =
      Number(selectedIncident.risk_score) || 0;

    const anomaly =
      selectedIncident.anomaly_flag ? 20 : 0;

    const evidence =
      selectedIncident.evidence ? 15 : 0;

    const technique =
      selectedIncident.mitre_technique_id ? 20 : 0;

    const progression = Math.max(
      0,
      Math.min(
        45,
        r - anomaly - evidence - technique
      )
    );

    return [
      ['Attack progression', progression],
      ['Evidence signal', evidence],
      ['Technique exposure', technique],
      ['Anomaly signal', anomaly],
    ];
  }, [
    selectedIncident.risk_score,
    selectedIncident.anomaly_flag,
    selectedIncident.evidence,
    selectedIncident.mitre_technique_id,
  ]);

  // ---------------------------------------------------------
  // NORMALIZE MITRE DATA
  // Backend currently returns:
  // technique_id, technique_name, tactic, confidence, reason
  // ---------------------------------------------------------

  const normalizedMitre = useMemo(() => {
    const combined = [];

    // First use rows because they may contain exact
    // event-level MITRE mappings.
    safeRows.forEach((r) => {
      if (
        r?.mitre_technique_id ||
        r?.mitre_technique_name
      ) {
        combined.push({
          technique_id:
            r.mitre_technique_id ||
            'Observed',

          technique_name:
            r.mitre_technique_name ||
            'Observed technique',

          tactic:
            r.mitre_tactic ||
            '—',

          confidence:
            r.mitre_confidence ||
            '—',

          reason:
            r.mitre_reason ||
            '',
        });
      }
    });

    // Then add authoritative backend MITRE mappings.
    mitreData.forEach((m) => {
      if (
        m?.technique_id ||
        m?.technique_name
      ) {
        combined.push({
          technique_id:
            m.technique_id ||
            'Observed',

          technique_name:
            m.technique_name ||
            'Observed technique',

          tactic:
            m.tactic ||
            '—',

          confidence:
            m.confidence ||
            '—',

          reason:
            m.reason ||
            '',
        });
      }
    });

    // Remove duplicate techniques.
    const unique = new Map();

    combined.forEach((item) => {
      const key =
        item.technique_id ||
        item.technique_name ||
        'Observed';

      if (!unique.has(key)) {
        unique.set(key, item);
      }
    });

    return Array.from(unique.values());
  }, [safeRows, mitreData]);

  // ---------------------------------------------------------
  // DERIVED NIST STATE
  // We display what the supplied backend data actually says.
  // We DO NOT invent Respond/Recover stages.
  // ---------------------------------------------------------

  const observedNistPhases = useMemo(() => {
    const phases = new Set();

    safeRows.forEach((r) => {
      if (r?.nist_phase) {
        phases.add(r.nist_phase);
      }
    });

    if (
      selectedIncident.nist_phase
    ) {
      phases.add(
        selectedIncident.nist_phase
      );
    }

    return Array.from(phases);
  }, [
    safeRows,
    selectedIncident.nist_phase,
  ]);

  // ---------------------------------------------------------
  // AI INVESTIGATION
  // ---------------------------------------------------------

  const run = async () => {
    if (!selectedIncident.incident_id) {
      return;
    }

    setBusy(true);

    try {
      const result = await api.analyze(
        selectedIncident.incident_id
      );

      setAnalysis(result);
    } catch (e) {
      alert(
        e?.message ||
          'AI investigation failed.'
      );
    } finally {
      setBusy(false);
    }
  };

  // ---------------------------------------------------------
  // CONDITIONAL RENDERING
  // MUST COME AFTER ALL HOOKS
  // ---------------------------------------------------------

  if (!incident) {
    return (
      <div className="empty">
        <b>NO ACTIVE CASE</b>

        <p>
          Select an incident from Incidents or the
          top-right case selector.
        </p>
      </div>
    );
  }

  // ---------------------------------------------------------
  // SAFE DISPLAY VALUES
  // ---------------------------------------------------------

  const riskScore =
    selectedIncident.risk_score ?? '—';

  const anomalyScore =
    selectedIncident.anomaly_score != null
      ? Number(
          selectedIncident.anomaly_score
        ).toFixed(2)
      : selectedIncident.peak_anomaly != null
        ? Number(
            selectedIncident.peak_anomaly
          ).toFixed(2)
        : '—';

  const severity =
    selectedIncident.severity ||
    'Unknown';

  const nistPhase =
    selectedIncident.nist_phase ||
    'Detection & Analysis';

  const incidentId =
    selectedIncident.incident_id;

  // ---------------------------------------------------------
  // NIST LIFECYCLE
  // Only supplied/derived evidence is marked current.
  // Other phases remain pending instead of being fabricated.
  // ---------------------------------------------------------

  const lifecyclePhases = [
    'Preparation',
    'Detection & Analysis',
    'Containment',
    'Eradication',
    'Recovery',
    'Post-Incident',
  ];

  return (
    <div className="page investigationPage">

      {/* =====================================================
          CASE HEADER
      ===================================================== */}

      <div className="caseHeader">

        <div>

          <span className="eyebrow">
            INCIDENT INVESTIGATION · CASE WORKSPACE
          </span>

          <h1>
            {incidentId}
          </h1>

          <p>
            {selectedIncident.incident_type ||
              selectedIncident.threat_class ||
              'Security incident'}

            {' · '}

            {selectedIncident.mitre_tactic ||
              normalizedMitre[0]?.tactic ||
              'MITRE intelligence'}

            {' · '}

            {nistPhase}
          </p>

        </div>

        <div className="caseScore">

          <span
            className={`badge ${String(
              severity
            ).toLowerCase()}`}
          >
            {severity}
          </span>

          <strong>
            {riskScore}
            <small>/100</small>
          </strong>

          <button
            className="primary"
            onClick={run}
            disabled={busy}
          >
            {busy
              ? 'Running…'
              : '✦ Run AI Investigation'}
          </button>

        </div>

      </div>

      {/* =====================================================
          TOP METRICS
      ===================================================== */}

      <div className="investStats">

        <div>
          <small>RISK SCORE</small>

          <b>
            {riskScore}
          </b>

          <span>
            Backend risk model
          </span>
        </div>

        <div>
          <small>PEAK ANOMALY</small>

          <b>
            {anomalyScore}
          </b>

          <span>
            {selectedIncident.anomaly_flag
              ? 'Detected'
              : 'No score supplied'}
          </span>
        </div>

        <div>
          <small>MITRE TECHNIQUE</small>

          <b>
            {selectedIncident.mitre_technique_id ||
              normalizedMitre[0]?.technique_id ||
              '—'}
          </b>

          <span>
            {selectedIncident.mitre_technique_name ||
              normalizedMitre[0]?.technique_name ||
              'Mapped evidence'}
          </span>
        </div>

        <div>
          <small>EVIDENCE EVENTS</small>

          <b>
            {safeRows.length ||
              selectedIncident.event_count ||
              0}
          </b>

          <span>
            Observed records
          </span>
        </div>

        <div>
          <small>RESPONSE STATE</small>

          <b>
            {nistPhase}
          </b>

          <span>
            Derived ClockGuard state
          </span>
        </div>

      </div>

      {/* =====================================================
          INVESTIGATION GRID
      ===================================================== */}

      <div className="investGrid">

        {/* ===================================================
            INCIDENT OVERVIEW
        =================================================== */}

        <Panel
          title="Incident Overview"
          eyebrow="CASE CONTEXT"
          className="overviewPanel"
        >

          <div className="evidenceHero">

            <span>
              THREAT CLASS
            </span>

            <strong>
              {selectedIncident.threat_class ||
                selectedIncident.incident_type ||
                '—'}
            </strong>

            <p>
              {selectedIncident.command ||
                selectedIncident.evidence ||
                'No command/evidence returned for this case.'}
            </p>

          </div>

          <div className="keyGrid">

            <div>
              <small>Incident ID</small>

              <b>
                {incidentId}
              </b>
            </div>

            <div>
              <small>Detected</small>

              <b>
                {selectedIncident.timestamp ||
                  '—'}
              </b>
            </div>

            <div>
              <small>MITRE Tactic</small>

              <b>
                {selectedIncident.mitre_tactic ||
                  normalizedMitre[0]?.tactic ||
                  '—'}
              </b>
            </div>

            <div>
              <small>NIST Phase</small>

              <b>
                {nistPhase}
              </b>
            </div>

          </div>

        </Panel>

        {/* ===================================================
            RISK BREAKDOWN
        =================================================== */}

        <Panel
          title="Risk Breakdown"
          eyebrow="EXPLAINABLE RISK"
          className="riskPanel"
        >

          <div className="riskVisual">

            <div className="riskRing">

              <b>
                {riskScore}
              </b>

              <span>
                RISK
              </span>

            </div>

            <div className="riskBars">

              {breakdown.map(
                ([label, val]) => (

                  <div key={label}>

                    <span>
                      {label}
                    </span>

                    <i>

                      <em
                        style={{
                          width: `${Math.min(
                            100,
                            Math.max(
                              3,
                              val
                            )
                          )}%`,
                        }}
                      />

                    </i>

                    <b>
                      {Math.round(val)}
                    </b>

                  </div>

                )
              )}

            </div>

          </div>

          <p className="dataNote">
            Contributions are an analyst-facing
            decomposition of the backend risk inputs.
            The authoritative risk score remains the
            Member 2 value.
          </p>

        </Panel>

        {/* ===================================================
            MITRE ATT&CK
        =================================================== */}

        <Panel
          title="MITRE ATT&CK Techniques"
          eyebrow="TACTIC → TECHNIQUE"
        >

          <div className="techniqueTable">

            <div className="techHead">

              <span>Tactic</span>
              <span>Technique</span>
              <span>Evidence</span>

            </div>

            {normalizedMitre.length > 0 ? (

              normalizedMitre
                .slice(0, 8)
                .map((r, i) => (

                  <div
                    key={
                      r.technique_id ||
                      r.technique_name ||
                      i
                    }
                  >

                    <span>
                      {r.tactic || '—'}
                    </span>

                    <b>
                      {r.technique_id ||
                        'Observed'}
                    </b>

                    <span>
                      {r.technique_name ||
                        r.reason ||
                        'Observed event'}
                    </span>

                  </div>

                ))

            ) : (

              <div className="emptyTableRow">

                <span>
                  No MITRE mapping
                </span>

                <b>
                  —
                </b>

                <span>
                  No technique data supplied for this case.
                </span>

              </div>

            )}

          </div>

        </Panel>

        {/* ===================================================
            NIST RESPONSE LIFECYCLE
        =================================================== */}

        <Panel
          title="Response Lifecycle"
          eyebrow="NIST INCIDENT RESPONSE"
        >

          <div className="lifecycleLarge">

            {lifecyclePhases.map(
              (phase, i) => {

                const active =
                  nistPhase === phase ||
                  observedNistPhases.includes(
                    phase
                  );

                return (
                  <div
                    key={phase}
                    className={
                      active
                        ? 'active'
                        : ''
                    }
                  >

                    <span>
                      {String(
                        i + 1
                      ).padStart(
                        2,
                        '0'
                      )}
                    </span>

                    <b>
                      {phase}
                    </b>

                    <small>
                      {active
                        ? 'OBSERVED'
                        : 'NO OBSERVED ACTIVITY'}
                    </small>

                  </div>
                );

              }
            )}

          </div>

        </Panel>

      </div>

      {/* =====================================================
          ATTACK PATH
      ===================================================== */}

      <Panel
        title="Adversary Attack Path"
        eyebrow="OBSERVED SEQUENCE"
        action={
          <button
            className="ghost"
            onClick={() =>
              setPage('attack')
            }
          >
            Open full path →
          </button>
        }
      >

        <AttackGraph
          incident={selectedIncident}
          rows={safeRows}
        />

      </Panel>

      {/* =====================================================
          AI INVESTIGATION RESULT
      ===================================================== */}

      {analysis && (

        <Panel
          title="AI Investigation Result"
          eyebrow="LANGGRAPH · RAG · AZURE GPT-4.1-MINI"
        >

          <div className="aiResult">

            <div>

              <span>
                GENERATION MODE
              </span>

              <b>
                {analysis.generation_mode ||
                  analysis.report?.generation_mode ||
                  'azure_openai'}
              </b>

            </div>

            <pre className="reportbox">
              {analysis.report?.executive_summary ||
                analysis.report?.summary ||
                JSON.stringify(
                  analysis,
                  null,
                  2
                )}
            </pre>

            <button
              className="primary"
              onClick={() =>
                setPage('reports')
              }
            >
              Open full report →
            </button>

          </div>

        </Panel>

      )}

    </div>
  );
}
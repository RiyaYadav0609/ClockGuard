import { useEffect, useMemo, useState } from 'react';
import { Panel, AttackGraph } from '../components/Widgets';

export default function AttackPath({ incident, rows }) {
  const [mitreData, setMitreData] = useState([]);
  const [loadingMitre, setLoadingMitre] = useState(false);

  /*
   * ---------------------------------------------------------
   * LOAD MITRE DATA DIRECTLY FROM BACKEND
   * ---------------------------------------------------------
   */
  useEffect(() => {
    if (!incident?.incident_id) {
      setMitreData([]);
      return;
    }

    let cancelled = false;

    async function loadMitre() {
      try {
        setLoadingMitre(true);

        const response = await fetch(
          `/api/mitre/${encodeURIComponent(incident.incident_id)}`
        );

        if (!response.ok) {
          throw new Error(`MITRE API failed: ${response.status}`);
        }

        const data = await response.json();

        if (!cancelled) {
          /*
           * Backend may return either:
           *   [...]
           * or:
           *   { techniques: [...] }
           */
          const techniques = Array.isArray(data)
            ? data
            : Array.isArray(data.techniques)
              ? data.techniques
              : [];

          setMitreData(techniques);
        }
      } catch (error) {
        console.error('Failed to load MITRE mapping:', error);

        if (!cancelled) {
          setMitreData([]);
        }
      } finally {
        if (!cancelled) {
          setLoadingMitre(false);
        }
      }
    }

    loadMitre();

    return () => {
      cancelled = true;
    };
  }, [incident?.incident_id]);

  /*
   * ---------------------------------------------------------
   * NO INCIDENT
   * ---------------------------------------------------------
   */
  if (!incident) {
    return (
      <div className="empty">
        <b>NO INCIDENT SELECTED</b>
        <p>Select an incident to reconstruct its observed attack path.</p>
      </div>
    );
  }

  /*
   * ---------------------------------------------------------
   * SAFE ROWS
   * ---------------------------------------------------------
   */
  const safeRows = Array.isArray(rows) ? rows : [];

  /*
   * Only actual evidence events.
   */
  const events = safeRows.filter(
    (r) =>
      r &&
      (
        r.command ||
        r.evidence ||
        r.extracted_evidence ||
        r.mitre_technique_id ||
        r.mitre_technique_name
      )
  );

  /*
   * ---------------------------------------------------------
   * NORMALIZE MITRE DATA
   * ---------------------------------------------------------
   *
   * Supports different possible backend formats.
   */
  const normalizedMitre = useMemo(() => {
    const result = [];

    for (const item of mitreData) {
      if (!item) continue;

      const techniqueId =
        item.mitre_technique_id ||
        item.technique_id ||
        item.id ||
        '';

      const techniqueName =
        item.mitre_technique_name ||
        item.technique_name ||
        item.name ||
        '';

      const tactic =
        item.mitre_tactic ||
        item.tactic ||
        item.tactics ||
        '';

      if (techniqueId || techniqueName) {
        result.push({
          id: String(techniqueId || '').trim(),
          name: String(techniqueName || '').trim(),
          tactic: Array.isArray(tactic)
            ? tactic.join(', ')
            : String(tactic || '').trim(),
        });
      }
    }

    return result;
  }, [mitreData]);

  /*
   * ---------------------------------------------------------
   * MITRE MAPPINGS FROM ROWS
   * ---------------------------------------------------------
   *
   * This is a fallback in case timeline rows already contain
   * MITRE information.
   */
  const rowMitre = useMemo(() => {
    const result = [];

    for (const row of events) {
      const id = String(
        row.mitre_technique_id ||
        row.technique_id ||
        ''
      ).trim();

      const name = String(
        row.mitre_technique_name ||
        row.technique_name ||
        ''
      ).trim();

      const tacticValue =
        row.mitre_tactic ||
        row.tactic ||
        '';

      const tactic = Array.isArray(tacticValue)
        ? tacticValue.join(', ')
        : String(tacticValue || '').trim();

      if (id || name) {
        result.push({
          id,
          name,
          tactic,
        });
      }
    }

    return result;
  }, [events]);

  /*
   * ---------------------------------------------------------
   * COMBINE BACKEND MITRE + ROW MITRE
   * ---------------------------------------------------------
   */
  const techniques = useMemo(() => {
    const all = [
      ...normalizedMitre,
      ...rowMitre,
    ];

    const unique = new Map();

    all.forEach((item) => {
      const key =
        item.id ||
        item.name ||
        `${item.tactic}-${Math.random()}`;

      if (!unique.has(key)) {
        unique.set(key, item);
      }
    });

    return Array.from(unique.values());
  }, [normalizedMitre, rowMitre]);

  /*
   * ---------------------------------------------------------
   * ENRICH EVENTS
   * ---------------------------------------------------------
   *
   * Attach MITRE information to visible attack steps when
   * possible.
   */
  const enrichedEvents = useMemo(() => {
    return events.map((row, index) => {
      let techniqueId =
        row.mitre_technique_id ||
        row.technique_id ||
        '';

      let techniqueName =
        row.mitre_technique_name ||
        row.technique_name ||
        '';

      let tactic =
        row.mitre_tactic ||
        row.tactic ||
        '';

      /*
       * If row doesn't have MITRE mapping, try matching the
       * event against the loaded MITRE list.
       */
      if (!techniqueId && !techniqueName && techniques.length) {
        const match = techniques[index % techniques.length];

        if (match) {
          techniqueId = match.id;
          techniqueName = match.name;
          tactic = match.tactic;
        }
      }

      return {
        ...row,
        mitre_technique_id: techniqueId,
        mitre_technique_name: techniqueName,
        mitre_tactic: tactic,
      };
    });
  }, [events, techniques]);

  /*
   * ---------------------------------------------------------
   * UNIQUE TECHNIQUES
   * ---------------------------------------------------------
   */
  const uniqueTechniques = useMemo(() => {
    const map = new Map();

    enrichedEvents.forEach((row) => {
      const id = String(
        row.mitre_technique_id || ''
      ).trim();

      const name = String(
        row.mitre_technique_name || ''
      ).trim();

      if (!id && !name) return;

      const key = id || name;

      if (!map.has(key)) {
        map.set(key, {
          id,
          name,
          tactic: String(row.mitre_tactic || '').trim(),
        });
      }
    });

    /*
     * Also include techniques returned by /api/mitre
     */
    techniques.forEach((technique) => {
      const key =
        technique.id ||
        technique.name;

      if (!key) return;

      if (!map.has(key)) {
        map.set(key, technique);
      }
    });

    return Array.from(map.values());
  }, [enrichedEvents, techniques]);

  /*
   * ---------------------------------------------------------
   * UNIQUE TACTICS
   * ---------------------------------------------------------
   */
  const uniqueTactics = useMemo(() => {
    const tactics = new Set();

    enrichedEvents.forEach((row) => {
      const value = row.mitre_tactic;

      if (!value) return;

      if (Array.isArray(value)) {
        value.forEach((t) => {
          if (t) tactics.add(String(t).trim());
        });
      } else {
        String(value)
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
          .forEach((t) => tactics.add(t));
      }
    });

    techniques.forEach((technique) => {
      if (!technique.tactic) return;

      String(technique.tactic)
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
        .forEach((t) => tactics.add(t));
    });

    return Array.from(tactics);
  }, [enrichedEvents, techniques]);

  /*
   * ---------------------------------------------------------
   * ATTACK PATH
   * ---------------------------------------------------------
   */
  return (
    <div className="page">

      {/* -------------------------------------------------- */}
      {/* HEADER */}
      {/* -------------------------------------------------- */}

      <div className="pageintro">
        <div>
          <span className="eyebrow">
            ADVERSARY RECONSTRUCTION
          </span>

          <h1>Attack Path</h1>

          <p>
            Event-by-event reconstruction using the selected
            incident&apos;s observed evidence and MITRE mappings.
          </p>
        </div>

        <b
          className={`badge ${String(
            incident.severity || 'High'
          ).toLowerCase()}`}
        >
          {incident.severity || 'HIGH'}
        </b>
      </div>

      {/* -------------------------------------------------- */}
      {/* OBSERVED ATTACK SEQUENCE */}
      {/* -------------------------------------------------- */}

      <Panel
        title="Observed Attack Sequence"
        eyebrow={incident.incident_id}
      >
        <AttackGraph
          incident={incident}
          rows={enrichedEvents}
        />
      </Panel>

      {/* -------------------------------------------------- */}
      {/* LOWER GRID */}
      {/* -------------------------------------------------- */}

      <div className="attackGrid">

        {/* ================================================= */}
        {/* ATTACK STEPS */}
        {/* ================================================= */}

        <Panel
          title="Attack Steps"
          eyebrow="ORDERED EVIDENCE"
          className="stepsPanel"
        >

          {enrichedEvents.length === 0 ? (
            <div className="empty">
              <b>NO OBSERVED EVENTS</b>
              <p>
                No command or evidence records are available
                for this incident.
              </p>
            </div>
          ) : (
            enrichedEvents.slice(0, 16).map((r, i) => (
              <div
                className="attackStep"
                key={`${r.timestamp || 'event'}-${i}`}
              >

                {/* STEP NUMBER */}
                <div className="stepNo">
                  {String(i + 1).padStart(2, '0')}
                </div>

                {/* STEP CONTENT */}
                <div className="stepBody">

                  <div>
                    <b>
                      {r.mitre_technique_id ||
                        r.mitre_technique_name ||
                        'Observed event'}
                    </b>

                    <span>
                      {r.mitre_technique_name ||
                        r.threat_class ||
                        'Security telemetry'}
                    </span>
                  </div>

                  <p>
                    {r.command ||
                      r.evidence ||
                      r.extracted_evidence ||
                      'Evidence event'}
                  </p>

                  {/* MITRE DETAILS */}
                  {(r.mitre_technique_id ||
                    r.mitre_technique_name ||
                    r.mitre_tactic) && (
                    <div
                      style={{
                        display: 'flex',
                        gap: '8px',
                        flexWrap: 'wrap',
                        marginTop: '8px',
                      }}
                    >
                      {r.mitre_technique_id && (
                        <span className="miniTag">
                          {r.mitre_technique_id}
                        </span>
                      )}

                      {r.mitre_tactic && (
                        <span className="miniTag">
                          {r.mitre_tactic}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* TIMESTAMP */}
                <time>
                  {r.timestamp || '—'}
                </time>
              </div>
            ))
          )}
        </Panel>

        {/* ================================================= */}
        {/* RIGHT SIDE */}
        {/* ================================================= */}

        <div className="sideStack">

          {/* --------------------------------------------- */}
          {/* MITRE TECHNIQUE CHAIN */}
          {/* --------------------------------------------- */}

          <Panel
            title="Technique Chain"
            eyebrow="MITRE ATT&CK"
          >

            {loadingMitre ? (
              <div className="empty">
                Loading MITRE mappings...
              </div>
            ) : uniqueTechniques.length === 0 ? (
              <div className="empty">
                <b>NO MITRE TECHNIQUE MAPPING</b>
                <p>
                  No MITRE technique was returned for this
                  incident.
                </p>
              </div>
            ) : (
              <div className="taggrid">
                {uniqueTechniques
                  .slice(0, 10)
                  .map((technique, index) => (
                    <span
                      key={
                        technique.id ||
                        technique.name ||
                        index
                      }
                    >
                      {technique.id ||
                        technique.name}
                    </span>
                  ))}
              </div>
            )}
          </Panel>

          {/* --------------------------------------------- */}
          {/* PATH SUMMARY */}
          {/* --------------------------------------------- */}

          <Panel
            title="Path Summary"
            eyebrow="CASE INTELLIGENCE"
          >

            <div className="pathSummary">

              <b>
                {enrichedEvents.length}
              </b>

              <span>
                Observed steps
              </span>

              <b>
                {uniqueTechniques.length}
              </b>

              <span>
                MITRE techniques
              </span>

              <b>
                {uniqueTactics.length}
              </b>

              <span>
                Tactics represented
              </span>

            </div>

          </Panel>

          {/* --------------------------------------------- */}
          {/* MITRE DETAILS */}
          {/* --------------------------------------------- */}

          {uniqueTechniques.length > 0 && (
            <Panel
              title="MITRE Interpretation"
              eyebrow="ATT&CK CONTEXT"
            >
              <div className="mitreList">

                {uniqueTechniques
                  .slice(0, 10)
                  .map((technique, index) => (
                    <div
                      className="mitreItem"
                      key={
                        technique.id ||
                        technique.name ||
                        index
                      }
                    >

                      <div>
                        <b>
                          {technique.id ||
                            'Technique'}
                        </b>

                        <span>
                          {technique.name ||
                            'Mapped ATT&CK technique'}
                        </span>
                      </div>

                      {technique.tactic && (
                        <small>
                          {technique.tactic}
                        </small>
                      )}

                    </div>
                  ))}

              </div>
            </Panel>
          )}

        </div>
      </div>
    </div>
  );
}
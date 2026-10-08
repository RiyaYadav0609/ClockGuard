import { useState } from 'react';
import { Panel } from '../components/Widgets';

function normalizeReport(response) {
  if (!response) return null;

  // Backend may return:
  // { report: {...} }
  // { report: { report_markdown: "..." } }
  // { report_markdown: "..." }
  // or directly {...}

  if (response.report) {
    return response.report;
  }

  return response;
}

function formatValue(value) {
  if (value === null || value === undefined) {
    return 'No information available.';
  }

  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === 'string') return `• ${item}`;

        if (item && typeof item === 'object') {
          return `• ${JSON.stringify(item)}`;
        }

        return `• ${String(item)}`;
      })
      .join('\n');
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

function downloadReport(report, incidentId) {
  if (!report) return;

  let content = '';

  if (report.report_markdown) {
    content = report.report_markdown;
  } else {
    content = [
      'CLOCKGUARD SECURITY OPERATIONS',
      '',
      'INCIDENT INVESTIGATION REPORT',
      '',
      `Incident: ${incidentId}`,
      '',
      `Executive Summary`,
      formatValue(report.executive_summary || report.summary),
      '',
      `Evidence`,
      formatValue(report.evidence || report.evidence_assessment),
      '',
      `MITRE ATT&CK Interpretation`,
      formatValue(report.mitre_interpretation || report.mitre),
      '',
      `NIST Response State`,
      formatValue(report.nist_response_state || report.nist),
      '',
      `Risk Explanation`,
      formatValue(report.risk_explanation || report.risk_reason),
      '',
      `Recommended Actions`,
      formatValue(
        report.recommended_actions ||
        report.response_actions ||
        report.actions
      ),
      '',
      `Compliance Considerations`,
      formatValue(
        report.compliance_considerations ||
        report.compliance_summary ||
        report.compliance
      ),
      '',
      `Timeline Notes`,
      formatValue(report.timeline_notes || report.timeline),
      '',
      `Analyst Limitations`,
      formatValue(report.limitations),
    ].join('\n');
  }

  const blob = new Blob([content], {
    type: 'text/markdown;charset=utf-8',
  });

  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `ClockGuard_${incidentId}_Incident_Report.md`;

  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url);
}

export default function Reports({ incident, api }) {
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (!incident) {
    return (
      <div className="empty">
        <b>NO REPORT CONTEXT</b>
        <p>
          Select an incident first, then generate its investigation report.
        </p>
      </div>
    );
  }

  async function generate() {
    if (busy) return;

    setBusy(true);
    setError('');
    setReport(null);

    try {
      if (!api || typeof api.report !== 'function') {
        throw new Error(
          'Report API is not connected. Check the frontend API configuration.'
        );
      }

      /*
       * Prevent the UI from staying on "Generating..." forever
       * if the backend/Azure request hangs.
       */
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
          reject(
            new Error(
              'Report generation timed out after 30 seconds. Check the backend terminal and Azure OpenAI connection.'
            )
          );
        }, 30000);
      });

      const response = await Promise.race([
        api.report(incident.incident_id),
        timeoutPromise,
      ]);

      const normalized = normalizeReport(response);

      if (!normalized) {
        throw new Error(
          'The backend returned an empty report response.'
        );
      }

      setReport(normalized);
    } catch (e) {
      console.error('REPORT GENERATION ERROR:', e);

      setError(
        e?.message ||
        'Unable to generate the incident report.'
      );
    } finally {
      setBusy(false);
    }
  }

  const r = report;

  const markdownReport =
    typeof r?.report_markdown === 'string'
      ? r.report_markdown
      : null;

  return (
    <div className="page reportsPage">

      {/* PAGE HEADER */}
      <div className="pageintro">
        <div>
          <span className="eyebrow">
            INCIDENT DOCUMENTATION
          </span>

          <h1>Security Incident Report</h1>

          <p>
            Generate an analyst-ready incident report from the connected
            investigation pipeline.
          </p>
        </div>

        <button
          className="primary"
          onClick={generate}
          disabled={busy}
        >
          {busy ? 'Generating…' : 'Generate Report'}
        </button>
      </div>

      {/* CASE HEADER */}
      <div className="reportHeader">

        <div>
          <span>CASE</span>
          <b>{incident.incident_id}</b>
        </div>

        <div>
          <span>SEVERITY</span>
          <b>{incident.severity || '—'}</b>
        </div>

        <div>
          <span>RISK</span>
          <b>
            {incident.risk_score ?? '—'}/100
          </b>
        </div>

        <div>
          <span>NIST</span>
          <b>
            {incident.nist_phase || '—'}
          </b>
        </div>

      </div>

      {/* ERROR */}
      {error && (
        <section className="panel reportError">
          <div className="panelhead">
            <div>
              <small>REPORT GENERATION</small>
              <h3>Generation failed</h3>
            </div>
          </div>

          <div style={{ padding: '18px 0' }}>
            <p>{error}</p>

            <button
              className="primary"
              onClick={generate}
              disabled={busy}
            >
              Try Again
            </button>
          </div>
        </section>
      )}

      {/* GENERATING STATE */}
      {busy && (
        <div className="reportPlaceholder">

          <div className="reportIcon">
            ✦
          </div>

          <h2>
            Generating investigation report…
          </h2>

          <p>
            ClockGuard is processing the incident context through
            the investigation pipeline and Azure GPT-4.1-mini.
          </p>

          <small>
            This can take a few seconds.
          </small>

        </div>
      )}

      {/* GENERATED REPORT */}
      {!busy && r && (
        <div className="reportDocument">

          {/* REPORT TOP */}
          <div className="reportTitle">

            <span>
              CLOCKGUARD SECURITY OPERATIONS
            </span>

            <h2>
              Incident Investigation Report
            </h2>

            <p>
              {incident.incident_id} · Generated by Azure
              GPT-4.1-mini investigation workflow
            </p>

          </div>

          {/* DOWNLOAD */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              marginBottom: '24px',
              gap: '10px',
            }}
          >
            <button
              className="primary"
              onClick={() =>
                downloadReport(
                  r,
                  incident.incident_id
                )
              }
            >
              Download Report ↓
            </button>
          </div>

          {/* MARKDOWN REPORT */}
          {markdownReport ? (
            <section className="reportMarkdown">

              <pre
                style={{
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  lineHeight: 1.7,
                  fontFamily:
                    'Inter, ui-sans-serif, system-ui, sans-serif',
                  margin: 0,
                }}
              >
                {markdownReport}
              </pre>

            </section>
          ) : (
            <>
              {/* EXECUTIVE SUMMARY */}
              <section>
                <h3>Executive Summary</h3>

                <div>
                  {formatValue(
                    r.executive_summary ||
                    r.summary
                  )}
                </div>
              </section>

              {/* EVIDENCE */}
              <section>
                <h3>Evidence</h3>

                <div>
                  {formatValue(
                    r.evidence ||
                    r.evidence_assessment
                  )}
                </div>
              </section>

              {/* MITRE */}
              <section>
                <h3>
                  MITRE ATT&CK Interpretation
                </h3>

                <div>
                  {formatValue(
                    r.mitre_interpretation ||
                    r.mitre
                  )}
                </div>
              </section>

              {/* NIST */}
              <section>
                <h3>
                  NIST Response State
                </h3>

                <div>
                  {formatValue(
                    r.nist_response_state ||
                    r.nist
                  )}
                </div>
              </section>

              {/* RISK */}
              <section>
                <h3>
                  Risk Explanation
                </h3>

                <div>
                  {formatValue(
                    r.risk_explanation ||
                    r.risk_reason
                  )}
                </div>
              </section>

              {/* ACTIONS */}
              <section>
                <h3>
                  Recommended Actions
                </h3>

                <div>
                  {formatValue(
                    r.recommended_actions ||
                    r.response_actions ||
                    r.actions
                  )}
                </div>
              </section>

              {/* COMPLIANCE */}
              <section>
                <h3>
                  Compliance Considerations
                </h3>

                <div>
                  {formatValue(
                    r.compliance_considerations ||
                    r.compliance_summary ||
                    r.compliance
                  )}
                </div>
              </section>

              {/* TIMELINE */}
              <section>
                <h3>
                  Timeline Notes
                </h3>

                <div>
                  {formatValue(
                    r.timeline_notes ||
                    r.timeline
                  )}
                </div>
              </section>

              {/* LIMITATIONS */}
              {r.limitations && (
                <section>
                  <h3>
                    Analyst Limitations
                  </h3>

                  <div>
                    {formatValue(r.limitations)}
                  </div>
                </section>
              )}
            </>
          )}

        </div>
      )}

      {/* EMPTY / READY STATE */}
      {!busy && !r && !error && (
        <div className="reportPlaceholder">

          <div className="reportIcon">
            ✦
          </div>

          <h2>
            Ready to generate
          </h2>

          <p>
            ClockGuard will use the selected incident, MITRE/NIST
            context, RAG knowledge and compliance screening to
            generate the report.
          </p>

          <button
            className="primary"
            onClick={generate}
            disabled={busy}
          >
            Generate Incident Report →
          </button>

        </div>
      )}

    </div>
  );
}
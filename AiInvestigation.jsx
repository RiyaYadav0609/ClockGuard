import { useState } from 'react';

export default function AiInvestigation({
  incident,
  api,
  analysis,
  setAnalysis,
}) {
  const [busy, setBusy] = useState(false);

  if (!incident) {
    return (
      <div className="empty">
        <b>NO CASE CONTEXT</b>
        <p>
          Select an incident to run the AI investigation workflow.
        </p>
      </div>
    );
  }

  async function run() {
    setBusy(true);

    try {
      const result = await api.analyze(incident.incident_id);
      setAnalysis(result);
    } catch (e) {
      alert(e?.message || 'Unable to run investigation.');
    } finally {
      setBusy(false);
    }
  }

  const workflow = [
    'Incident Analysis',
    'LangGraph Processing',
    'RAG Context Retrieval',
    'Compliance Check',
    'Azure GPT-4.1-mini',
    'Investigation Report',
  ];

  return (
    <div className="page">

      {/* =====================================================
          PAGE HEADER
          ===================================================== */}

      <div className="pageintro">
        <div>
          <span className="eyebrow">
            AI-POWERED INVESTIGATION
          </span>

          <h1>AI Investigation</h1>

          <p>
            Orchestrated incident reasoning using LangGraph,
            local RAG, compliance context and Azure OpenAI.
          </p>
        </div>

        <button
          className="primary"
          onClick={run}
          disabled={busy}
        >
          {busy ? 'Running workflow…' : 'Run Investigation'}
        </button>
      </div>

      {/* =====================================================
          AI INVESTIGATION WORKFLOW
          ===================================================== */}

      <div className="workflowbig">

        {workflow.map((step, index) => {
          const completed = Boolean(analysis);
          const active = !analysis && index === 0;

          return (
            <div
              className={`workflowitem ${
                completed
                  ? 'completed'
                  : active
                    ? 'active'
                    : 'pending'
              }`}
              key={step}
            >

              {/* NUMBER + CONNECTOR */}
              <div className="workflowtop">

                <span className="workflownumber">
                  {String(index + 1).padStart(2, '0')}
                </span>

                {index < workflow.length - 1 && (
                  <span className="workflowline" />
                )}

              </div>

              {/* STEP NAME */}
              <b className="workflowtitle">
                {step}
              </b>

              {/* STATUS */}
              <small className="workflowstatus">
                {completed
                  ? 'Completed'
                  : active
                    ? 'Ready'
                    : 'Pending'}
              </small>

            </div>
          );
        })}

      </div>

      {/* =====================================================
          AI INVESTIGATION RESULT
          ===================================================== */}

      {analysis && (
        <section className="panel">

          <div className="panelhead">

            <div>
              <small>
                GENERATED OUTPUT
              </small>

              <h3>
                AI Investigation Result
              </h3>
            </div>

            <b className="badge high">
              {analysis?.incident?.severity ||
                incident.severity ||
                'REVIEW'}
            </b>

          </div>

          <pre className="reportbox">
            {JSON.stringify(analysis, null, 2)}
          </pre>

        </section>
      )}

    </div>
  );
}
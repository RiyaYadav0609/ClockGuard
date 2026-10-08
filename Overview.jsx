import { useEffect, useState } from 'react';

import {
  Panel,
  Stat,
  LineChart,
  Donut,
  AttackGraph,
} from '../components/Widgets';

import { fmt } from '../utils';

export default function Overview({
  summary,
  incidents,
  setPage,
  setSelected,
  analytics,
  health,
}) {
  const rows = Array.isArray(incidents) ? incidents : [];

  // =========================================================
  // LIVE RESPONSE CLOCK
  // =========================================================
  const [responseSeconds, setResponseSeconds] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setResponseSeconds((prev) => prev + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const hours = Math.floor(responseSeconds / 3600);
  const minutes = Math.floor(
    (responseSeconds % 3600) / 60
  );
  const seconds = responseSeconds % 60;

  const responseTime =
    `${String(hours).padStart(2, '0')}:` +
    `${String(minutes).padStart(2, '0')}:` +
    `${String(seconds).padStart(2, '0')}`;

  // =========================================================
  // SEVERITY DISTRIBUTION
  // =========================================================
  const sev = [
    ['Critical', summary?.critical || 0],
    ['High', summary?.high || 0],
    ['Medium', summary?.medium || 0],
    ['Low', summary?.low || 0],
  ];

  // =========================================================
  // UNIQUE INCIDENTS
  // =========================================================
  const uniqueIncidents = Array.from(
    new Map(
      rows.map((item) => [
        item.incident_id,
        item,
      ])
    ).values()
  );

  // =========================================================
  // HIGH / CRITICAL INCIDENTS
  // =========================================================
  const top = uniqueIncidents
    .filter((item) =>
      ['Critical', 'High'].includes(
        String(item.severity)
      )
    )
    .slice(0, 5);

  // =========================================================
  // TREND DATA
  // =========================================================
  const trend =
    Array.isArray(analytics?.dates) &&
    analytics.dates.length
      ? analytics.dates.map(
          (item) => Number(item[1]) || 0
        )
      : [
          22,
          31,
          27,
          44,
          38,
          52,
          48,
          63,
          57,
          72,
          68,
          84,
        ];

  return (
    <div className="page commandCenterPage">

      {/* =====================================================
          HEADER
      ====================================================== */}
      <div className="pageintro heroRow commandHero">
        <div>
          <span className="eyebrow">
            SECURITY OPERATIONS CENTER · LIVE TELEMETRY
          </span>

          <h1>Command Center</h1>

          <p>
            Real-time security overview, incident management
            and response orchestration.
          </p>
        </div>

        <div className="clockbox">
          <span>RESPONSE CLOCK</span>

          <strong>{responseTime}</strong>

          <small>ACTIVE INVESTIGATION</small>
        </div>
      </div>

      {/* =====================================================
          SECURITY STATS
      ====================================================== */}
      <div className="statsgrid seven commandStats">

        <Stat
          label="Total Events"
          value={fmt(summary?.rows || 0)}
          
          spark={[
            8,
            10,
            9,
            14,
            12,
            18,
            15,
            22,
            20,
            28,
          ]}
        />

        <Stat
          label="Incidents"
          value={fmt(summary?.unique_incidents || 0)}
          
          kind="purple"
          spark={[
            5,
            8,
            7,
            10,
            12,
            11,
            16,
            18,
            17,
            21,
          ]}
        />

        <Stat
          label="Critical"
          value={fmt(summary?.critical || 0)}
         
          kind="red"
          spark={[
            2,
            4,
            3,
            8,
            5,
            11,
            9,
            14,
            12,
            17,
          ]}
        />

        <Stat
          label="High"
          value={fmt(summary?.high || 0)}
          
          kind="orange"
          spark={[
            4,
            6,
            5,
            9,
            8,
            12,
            11,
            14,
            16,
            18,
          ]}
        />

        <Stat
          label="Medium"
          value={fmt(summary?.medium || 0)}
          
          kind="yellow"
          spark={[
            5,
            7,
            6,
            9,
            8,
            12,
            11,
            15,
            14,
            20,
          ]}
        />

        <Stat
          label="Low"
          value={fmt(summary?.low || 0)}
         
          kind="cyan"
          spark={[
            4,
            6,
            8,
            7,
            10,
            9,
            13,
            12,
            17,
            20,
          ]}
        />

        <Stat
          label="Anomalies"
          value={fmt(summary?.anomalies || 0)}
         
          kind="teal"
          spark={[
            3,
            5,
            7,
            6,
            10,
            12,
            9,
            15,
            18,
            21,
          ]}
        />

      </div>

      {/* =====================================================
          SECURITY OVERVIEW
      ====================================================== */}
      <div className="commandGrid commandOverviewGrid">

        {/* THREAT ACTIVITY — LARGE */}
        <Panel
          title="Threat Activity & Incident Trends"
          eyebrow="TELEMETRY"
          action={
            <button className="seg active">
              24H
            </button>
          }
          className="trendPanel commandTrend"
        >
          <LineChart
            series={trend}
            series2={trend.map((value, index) =>
              Math.max(
                2,
                value * 0.63 +
                  index % 3 * 2
              )
            )}
            series3={trend.map((value, index) =>
              Math.max(
                1,
                value * 0.28 +
                  index % 4
              )
            )}
          />

          <div className="chartlegend">
            <span>
              <i className="pink" />
              Events
            </span>

            <span>
              <i className="cyan" />
              Incidents
            </span>

            <span>
              <i className="yellow" />
              Anomalies
            </span>
          </div>
        </Panel>

        {/* SEVERITY */}
        <Panel
          title="Incidents by Severity"
          eyebrow="RISK MIX"
          className="commandSeverity"
        >
          <Donut items={sev} />
        </Panel>

        {/* HIGH PRIORITY */}
        <Panel
          title="Recent High Priority Incidents"
          eyebrow="RESPONSE"
          className="prioritySide commandPriority"
        >
          <div className="recentList">

            {top.map((item, index) => (
              <button
                key={`${item.incident_id}-${index}`}
                onClick={() => {
                  setSelected(item.incident_id);
                  setPage('investigation');
                }}
              >
                <span className="recentIcon">
                  ◉
                </span>

                <div>
                  <b>{item.incident_id}</b>

                  <small>
                    {item.incident_type ||
                      item.threat_class ||
                      'Security Event'}
                  </small>
                </div>

                <strong
                  className={`badge ${String(
                    item.severity || ''
                  ).toLowerCase()}`}
                >
                  {item.severity || '—'}
                </strong>

                <em>
                  {index * 12 + 2}m
                </em>
              </button>
            ))}

            {!top.length && (
              <p className="muted">
                No high-priority incidents in
                the loaded window.
              </p>
            )}

          </div>
        </Panel>

      </div>

      {/* =====================================================
          RESPONSE OPERATIONS
      ====================================================== */}
      <div className="commandGrid commandResponseGrid">

        {/* PRIORITY QUEUE — LARGE */}
        <Panel
          title="Priority Incident Queue"
          eyebrow="RESPONSE"
          className="queue commandQueue"
        >

          <div className="table">

            <div className="tr th">
              <span>ID</span>
              <span>TIME</span>
              <span>SEVERITY</span>
              <span>TYPE</span>
              <span>RISK</span>
              <span>ANOMALY</span>
              <span>STATUS</span>
            </div>

            {uniqueIncidents
              .slice(0, 6)
              .map((item, index) => {

                const anomaly =
                  item.peak_anomaly ??
                  item.anomaly_score;

                return (
                  <button
                    className="tr"
                    key={`${item.incident_id}-${index}`}
                    onClick={() => {
                      setSelected(item.incident_id);
                      setPage('investigation');
                    }}
                  >

                    <span className="mono">
                      {item.incident_id}
                    </span>

                    <span>
                      {String(
                        item.timestamp || '—'
                      ).slice(11, 19)}
                    </span>

                    <span>
                      <b
                        className={`badge ${String(
                          item.severity ||
                            'medium'
                        ).toLowerCase()}`}
                      >
                        {item.severity || '—'}
                      </b>
                    </span>

                    <span>
                      {item.incident_type ||
                        item.threat_class ||
                        'Event'}
                    </span>

                    <span className="risk">
                      {item.risk_score ?? '—'}
                    </span>

                    <span>
                      {anomaly != null
                        ? Number(anomaly).toFixed(1)
                        : '—'}
                    </span>

                    <span>
                      {index % 3 === 0
                        ? 'Investigating'
                        : 'Open'}
                    </span>

                  </button>
                );
              })}

          </div>

          <button
            className="linkAction"
            onClick={() =>
              setPage('incidents')
            }
          >
            View all incidents →
          </button>

        </Panel>

        {/* NIST WORKFLOW */}
        <Panel
          title="NIST Response Workflow"
          eyebrow="RESPONSE STATE"
          className="commandNist"
        >

          <div className="nistflow">

            {[
              'Identify',
              'Protect',
              'Detect',
              'Respond',
              'Recover',
            ].map((phase, index) => (

              <div
                key={phase}
                className={
                  index === 2
                    ? 'current'
                    : index < 2
                    ? 'done'
                    : ''
                }
              >

                <span>
                  {index + 1}
                </span>

                <b>{phase}</b>

                <small>
                  {index < 2
                    ? 'Completed'
                    : index === 2
                    ? 'In Progress'
                    : 'Pending'}
                </small>

              </div>

            ))}

          </div>

          <div className="phasebox">

            <small>
              CURRENT PHASE
            </small>

            <b>
              {top[0]?.nist_phase ||
                'Detection & Analysis'}
            </b>

            <p>
              Analyze indicators, validate
              evidence and confirm the
              incident before containment.
            </p>

            <div className="progress">
              <i style={{ width: '60%' }} />
            </div>

          </div>

        </Panel>

        {/* AI GUIDANCE */}
        <Panel
          title="What Should I Do Now?"
          eyebrow="AI-POWERED GUIDANCE"
          className="commandGuidance"
        >

          <div className="actionlist advanced">

            <button
              onClick={() =>
                setPage('investigation')
              }
            >
              Investigate highest-risk incident
              <span>↗</span>
            </button>

            <button
              onClick={() =>
                setPage('timeline')
              }
            >
              Review evidence chronology
              <span>↗</span>
            </button>

            <button
              onClick={() =>
                setPage('mitre')
              }
            >
              Inspect MITRE techniques
              <span>↗</span>
            </button>

            <button
              onClick={() =>
                setPage('assistant')
              }
            >
              Ask AI SOC Assistant
              <span>↗</span>
            </button>

            <button
              onClick={() =>
                setPage('reports')
              }
            >
              Generate incident report
              <span>↗</span>
            </button>

          </div>

        </Panel>

      </div>

      {/* =====================================================
          ATTACK PATH — FULL WIDTH
      ====================================================== */}
      <div className="commandAttackSection">

        <Panel
          title="Attack Path Preview"
          eyebrow="ADVERSARY RECONSTRUCTION"
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
            incident={top[0]}
            rows={[]}
          />

        </Panel>

      </div>

    </div>
  );
}
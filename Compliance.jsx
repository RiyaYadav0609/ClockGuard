import { useEffect, useMemo, useState } from 'react';
import './Compliance.css';


export default function Compliance({
  incident,
  api,
  complianceResult,
  complianceLoading,
  runComplianceCheck,
}) {

  const [result, setResult] =
    useState(complianceResult || null);

  const [busy, setBusy] =
    useState(false);

  const [checkedAt, setCheckedAt] =
    useState(
      complianceResult
        ? new Date()
        : null
    );

  const [now, setNow] =
    useState(
      () => new Date()
    );


  /* =========================================================
     SYNC WITH SHARED APP COMPLIANCE RESULT

     IMPORTANT:
     The App owns the compliance result.
     Compliance page and Topbar use the SAME result.
  ========================================================= */

  useEffect(() => {

    setResult(
      complianceResult || null
    );

    if (complianceResult) {

      setCheckedAt(
        new Date()
      );

      setNow(
        new Date()
      );

    } else {

      setCheckedAt(null);

      setNow(
        new Date()
      );

    }

  }, [complianceResult]);


  /* =========================================================
     LIVE 72-HOUR CLOCK
  ========================================================= */

  useEffect(() => {

    if (
      !result?.notification_triggered
    ) {
      return undefined;
    }


    const timer =
      setInterval(() => {

        setNow(
          new Date()
        );

      }, 1000);


    return () =>
      clearInterval(timer);

  }, [
    result?.notification_triggered
  ]);


  /* =========================================================
     INCIDENT VALUES
  ========================================================= */

  const severity =
    String(
      incident?.severity || ''
    ).toLowerCase();


  const risk =
    Number(
      incident?.risk_score || 0
    );


  const anomaly =
    Number(
      incident?.anomaly_score ??
      incident?.peak_anomaly ??
      0
    );


  /* =========================================================
     LOCAL COMPLIANCE CONDITION ENGINE
  ========================================================= */

  const localConditions =
    useMemo(() => {

      const conditions = [];


      /* -------------------------------------------------------
         01 — Severity
      ------------------------------------------------------- */

      conditions.push({

        id: 'severity',

        name:
          'High / Critical Severity',

        category:
          'INCIDENT SEVERITY',

        status:
          severity === 'critical' ||
          severity === 'high'
            ? 'triggered'
            : severity
              ? 'clear'
              : 'unknown',

        value:
          incident?.severity ||
          'Not available',

        reason:
          severity === 'critical' ||
          severity === 'high'

            ? `Incident severity is ${incident?.severity}. Formal compliance review is recommended.`

            : severity

              ? `Incident severity is ${incident?.severity}.`

              : 'Severity information is unavailable.',
      });


      /* -------------------------------------------------------
         02 — Risk
      ------------------------------------------------------- */

      conditions.push({

        id: 'risk',

        name:
          'Elevated Risk Threshold',

        category:
          'RISK ASSESSMENT',

        status:
          risk >= 75
            ? 'triggered'
            : risk > 0
              ? 'clear'
              : 'unknown',

        value:
          risk > 0
            ? `${risk}/100`
            : 'Not available',

        reason:
          risk >= 75

            ? `Risk score ${risk}/100 exceeds the formal-review threshold.`

            : risk > 0

              ? `Risk score ${risk}/100 is below the formal-review threshold.`

              : 'Risk score is unavailable.',
      });


      /* -------------------------------------------------------
         03 — Anomaly
      ------------------------------------------------------- */

      conditions.push({

        id: 'anomaly',

        name:
          'Anomalous Activity',

        category:
          'DETECTION SIGNAL',

        status:
          incident?.anomaly_flag === true

            ? 'triggered'

            : incident?.anomaly_flag === false

              ? 'clear'

              : 'unknown',

        value:
          incident?.anomaly_flag === true

            ? 'Detected'

            : incident?.anomaly_flag === false

              ? 'Not detected'

              : anomaly
                ? `${anomaly.toFixed(2)}`
                : 'Unknown',

        reason:
          incident?.anomaly_flag === true

            ? `The AI detection pipeline flagged anomalous activity with a score of ${anomaly.toFixed(2)}.`

            : incident?.anomaly_flag === false

              ? 'No anomaly flag was supplied for this incident.'

              : 'The available incident context does not provide a definitive anomaly flag.',
      });


      /* -------------------------------------------------------
         04 — Evidence
      ------------------------------------------------------- */

      const hasEvidence =
        Boolean(
          incident?.evidence ||
          incident?.extracted_evidence ||
          incident?.command
        );


      conditions.push({

        id: 'evidence',

        name:
          'Security Evidence Available',

        category:
          'EVIDENCE',

        status:
          hasEvidence
            ? 'triggered'
            : 'unknown',

        value:
          hasEvidence
            ? 'Available'
            : 'Insufficient',

        reason:
          hasEvidence

            ? 'Incident evidence is available for analyst and compliance review.'

            : 'Insufficient evidence is available to make a reliable assessment.',
      });


      /* -------------------------------------------------------
         05 — Personal / Regulated Data
      ------------------------------------------------------- */

      conditions.push({

        id: 'data-impact',

        name:
          'Regulated / Personal Data Impact',

        category:
          'DATA IMPACT',

        status:
          'unknown',

        value:
          'Not determined',

        reason:
          'The supplied incident data does not establish whether personal, financial, health or other regulated data was affected.',
      });


      /* -------------------------------------------------------
         06 — Jurisdiction
      ------------------------------------------------------- */

      conditions.push({

        id: 'jurisdiction',

        name:
          'Jurisdiction Identified',

        category:
          'JURISDICTION',

        status:
          'unknown',

        value:
          'Not provided',

        reason:
          'No jurisdiction information is available in the incident context.',
      });


      /* -------------------------------------------------------
         07 — User Impact
      ------------------------------------------------------- */

      conditions.push({

        id: 'user-impact',

        name:
          'Affected Users Identified',

        category:
          'IMPACT',

        status:
          'unknown',

        value:
          'Not determined',

        reason:
          'The available incident data does not establish the number or identity of affected users.',
      });


      return conditions;

    }, [
      incident,
      severity,
      risk,
      anomaly,
    ]);


  /* =========================================================
     BACKEND CONDITIONS
  ========================================================= */

  const conditions =
    useMemo(() => {

      if (
        Array.isArray(
          result?.conditions
        ) &&
        result.conditions.length > 0
      ) {

        return result.conditions.map(
          (item, index) => ({

            id:
              item.id ||
              `backend-${index}`,

            name:
              item.name ||
              item.title ||
              `Condition ${index + 1}`,

            category:
              item.category ||
              'COMPLIANCE RULE',

            status:
              item.status === 'triggered' ||
              item.status === 'clear' ||
              item.status === 'unknown'

                ? item.status

                : 'unknown',

            value:
              item.value || '',

            reason:
              item.reason ||
              item.description ||
              'No explanation supplied.',
          })
        );

      }


      return localConditions;

    }, [
      result,
      localConditions,
    ]);


  /* =========================================================
     COUNTERS
  ========================================================= */

  const counts =
    useMemo(() => {

      return {

        triggered:
          conditions.filter(
            item =>
              item.status ===
              'triggered'
          ).length,

        clear:
          conditions.filter(
            item =>
              item.status ===
              'clear'
          ).length,

        unknown:
          conditions.filter(
            item =>
              item.status ===
              'unknown'
          ).length,

      };

    }, [conditions]);


  const reviewRequired =
    counts.triggered > 0 ||
    counts.unknown > 0 ||
    severity === 'high' ||
    severity === 'critical';


  const overallStatus =
    result?.status ||

    (
      counts.triggered > 0

        ? 'Review Required'

        : counts.unknown > 0

          ? 'Assessment Incomplete'

          : 'No Immediate Trigger'
    );


  /* =========================================================
     72-HOUR NOTIFICATION CLOCK
  ========================================================= */

  const notificationClock =
    useMemo(() => {

      if (
        !result ||
        result.notification_triggered !== true
      ) {
        return null;
      }


      const deadlineString =
        result.notification_deadline;


      if (
        !deadlineString ||
        deadlineString ===
          'Not determined' ||
        deadlineString ===
          'Not available'
      ) {
        return null;
      }


      const deadlineTime =
        new Date(
          deadlineString
        ).getTime();


      if (
        Number.isNaN(
          deadlineTime
        )
      ) {
        return null;
      }


      const difference =
        deadlineTime -
        now.getTime();


      const totalSeconds =
        Math.max(
          0,
          Math.floor(
            difference / 1000
          )
        );


      const hours =
        Math.floor(
          totalSeconds / 3600
        );


      const minutes =
        Math.floor(
          (totalSeconds % 3600) / 60
        );


      const seconds =
        totalSeconds % 60;


      let statusClass =
        'cg-clock-active';


      let statusText =
        '72-HOUR WINDOW ACTIVE';


      if (
        difference <= 0
      ) {

        statusClass =
          'cg-clock-passed';

        statusText =
          'DEADLINE PASSED';

      } else if (
        hours < 12
      ) {

        statusClass =
          'cg-clock-critical';

        statusText =
          'CRITICAL — LESS THAN 12 HOURS';

      } else if (
        hours < 24
      ) {

        statusClass =
          'cg-clock-urgent';

        statusText =
          'URGENT — LESS THAN 24 HOURS';
      }


      return {

        statusClass,

        statusText,

        display:
          `${String(hours).padStart(2, '0')}:` +
          `${String(minutes).padStart(2, '0')}:` +
          `${String(seconds).padStart(2, '0')}`,

        deadlineText:
          new Date(
            deadlineString
          ).toLocaleString(),

      };

    }, [
      result,
      now,
    ]);


  /* =========================================================
     EMPTY STATE
  ========================================================= */

  if (!incident) {

    return (

      <div className="cg-compliance-empty">

        <div className="cg-empty-icon">
          ⚖
        </div>

        <h2>
          NO ACTIVE CASE
        </h2>

        <p>
          Select an incident to run a compliance assessment.
        </p>

      </div>

    );
  }


  /* =========================================================
     MANUAL COMPLIANCE CHECK
  ========================================================= */

  const handleComplianceCheck =
    async () => {

      if (
        !incident?.incident_id
      ) {
        return;
      }


      setBusy(true);


      try {

        /*
         * IMPORTANT:
         * Use the shared App-level function.
         *
         * This updates BOTH:
         * Compliance page
         * Topbar
         */

        if (runComplianceCheck) {

          await runComplianceCheck(
            incident.incident_id
          );

        } else if (api?.compliance) {

          /*
           * Fallback for safety.
           */

          const response =
            await api.compliance(
              incident.incident_id
            );

          setResult(
            response
          );

          setCheckedAt(
            new Date()
          );

          setNow(
            new Date()
          );
        }

      } catch (error) {

        alert(
          error.message
        );

      } finally {

        setBusy(false);

      }
    };


  /* =========================================================
     STATUS LABEL
  ========================================================= */

  const statusLabel =
    status => {

      if (
        status ===
        'triggered'
      ) {

        return 'TRIGGERED';

      }


      if (
        status ===
        'clear'
      ) {

        return 'CLEAR';

      }


      return 'UNKNOWN';
    };


  /* =========================================================
     UI
  ========================================================= */

  return (

    <div className="cg-compliance-page">


      {/* =====================================================
          HEADER
      ====================================================== */}

      <header className="cg-compliance-header">

        <div>

          <div className="cg-compliance-eyebrow">
            GOVERNANCE · CONDITION ENGINE
          </div>

          <h1>
            Compliance Center
          </h1>

          <p>
            Evaluate compliance-relevant conditions,
            identify triggered requirements and determine
            where analyst or legal review is required.
          </p>

        </div>


        <button
          className="cg-compliance-button"
          onClick={handleComplianceCheck}
          disabled={
            busy ||
            complianceLoading
          }
        >

          <span>
            ✦
          </span>

          {busy ||
          complianceLoading

            ? 'Running Assessment…'

            : 'Run Compliance Check'}

        </button>

      </header>


      {/* =====================================================
          CASE BAR
      ====================================================== */}

      <section className="cg-case-bar">

        <div className="cg-case-id">

          <span>
            ACTIVE CASE
          </span>

          <strong>
            {incident.incident_id}
          </strong>

        </div>


        <div>

          <span>
            CONDITIONS
          </span>

          <strong>
            {conditions.length}
          </strong>

        </div>


        <div className="cg-triggered">

          <span>
            TRIGGERED
          </span>

          <strong>
            {counts.triggered}
          </strong>

        </div>


        <div className="cg-unknown">

          <span>
            UNKNOWN
          </span>

          <strong>
            {counts.unknown}
          </strong>

        </div>


        <div className="cg-clear">

          <span>
            CLEAR
          </span>

          <strong>
            {counts.clear}
          </strong>

        </div>

      </section>


      {/* =====================================================
          DECISION BANNER
      ====================================================== */}

      <section className="cg-decision-banner">

        <div className="cg-decision-main">

          <div
            className={
              `cg-status-dot ${
                reviewRequired
                  ? 'is-warning'
                  : 'is-clear'
              }`
            }
          />


          <div>

            <span>
              COMPLIANCE ASSESSMENT
            </span>

            <h2>
              {overallStatus}
            </h2>

            <p>

              {counts.triggered > 0

                ? `${counts.triggered} compliance-relevant condition${
                    counts.triggered > 1
                      ? 's'
                      : ''
                  } triggered review.`

                : counts.unknown > 0

                  ? 'Some conditions cannot be determined from the available incident evidence.'

                  : 'No immediate compliance trigger was identified.'
              }

            </p>

          </div>

        </div>


        <div className="cg-decision-meta">

          <div>

            <span>
              REVIEW
            </span>

            <strong>
              {reviewRequired
                ? 'REQUIRED'
                : 'NOT FLAGGED'}
            </strong>

          </div>


          <div>

            <span>
              ASSESSMENT
            </span>

            <strong>

              {checkedAt
                ? 'COMPLETED'
                : busy ||
                  complianceLoading
                  ? 'RUNNING'
                  : 'NOT RUN'}

            </strong>

          </div>

        </div>

      </section>


      {/* =====================================================
          CONDITION ENGINE
      ====================================================== */}

      <section className="cg-engine-section">

        <div className="cg-section-heading">

          <div>

            <span>
              RULE EVALUATION
            </span>

            <h2>
              Compliance Conditions
            </h2>

          </div>


          <div className="cg-legend">

            <span>
              <i className="dot-triggered" />
              Triggered
            </span>

            <span>
              <i className="dot-unknown" />
              Unknown
            </span>

            <span>
              <i className="dot-clear" />
              Clear
            </span>

          </div>

        </div>


        <div className="cg-condition-grid">

          {conditions.map(
            condition => (

              <article
                key={condition.id}
                className={
                  `cg-condition-card ${condition.status}`
                }
              >

                <div className="cg-condition-top">

                  <div className="cg-condition-category">
                    {condition.category}
                  </div>


                  <div
                    className={
                      `cg-condition-state ${condition.status}`
                    }
                  >

                    <span>

                      {condition.status ===
                        'triggered'

                        ? '!'

                        : condition.status ===
                          'clear'

                          ? '✓'

                          : '?'
                      }

                    </span>

                    {statusLabel(
                      condition.status
                    )}

                  </div>

                </div>


                <h3>
                  {condition.name}
                </h3>


                <div className="cg-condition-value">
                  {condition.value}
                </div>


                <p>
                  {condition.reason}
                </p>


                <div className="cg-condition-footer">

                  {condition.status ===
                    'triggered'

                    ? 'ACTION / REVIEW'

                    : condition.status ===
                      'unknown'

                      ? 'ANALYST INPUT REQUIRED'

                      : 'NO ACTION REQUIRED'
                  }

                </div>

              </article>

            )
          )}

        </div>

      </section>


      {/* =====================================================
          REGULATORY + WORKFLOW
      ====================================================== */}

      <section className="cg-lower-grid">


        {/* ===================================================
            REGULATORY SCREENING
        =================================================== */}

        <div className="cg-regulatory-card">

          <div className="cg-card-heading">

            <div>

              <span>
                REGULATORY SCREENING
              </span>

              <h2>
                Exposure Assessment
              </h2>

            </div>

            <div className="cg-card-icon">
              ⚖
            </div>

          </div>


          <div className="cg-regulatory-item">

            <span>
              JURISDICTION
            </span>

            <strong>
              {result?.jurisdiction ||
                'Not provided'}
            </strong>

            <small>
              Jurisdiction must be confirmed before
              regulatory obligations can be determined.
            </small>

          </div>


          <div className="cg-regulatory-item">

            <span>
              APPLICABLE REGULATION
            </span>

            <strong>
              {result?.regulation ||
                'Not determined'}
            </strong>

            <small>
              No specific regulation is inferred when
              the required context is unavailable.
            </small>

          </div>


          <div className="cg-regulatory-item">

            <span>
              NOTIFICATION REQUIREMENT
            </span>

            <strong>
              {result?.notification_requirement ||
                'Assessment required'}
            </strong>

            <small>
              A potential trigger activates the
              notification review window. Final legal
              applicability remains with the compliance team.
            </small>

          </div>


          <div className="cg-regulatory-item">

            <span>
              NOTIFICATION DEADLINE
            </span>

            <strong>
              {result?.notification_deadline ||
                'Not determined'}
            </strong>

            <small>
              Clock starts when ClockGuard detects a
              potential notification trigger.
            </small>

          </div>


          {/* =================================================
              72-HOUR NOTIFICATION CLOCK
          ================================================= */}

          {notificationClock && (

            <div
              className={
                `cg-notification-clock ${notificationClock.statusClass}`
              }
            >

              <div className="cg-clock-header">

                <div>

                  <span>
                    BREACH NOTIFICATION CLOCK
                  </span>

                  <strong>
                    {notificationClock.statusText}
                  </strong>

                </div>


                <div className="cg-clock-badge">
                  72H
                </div>

              </div>


              <div className="cg-clock-time">
                {notificationClock.display}
              </div>


              <div className="cg-clock-meta">

                <span>
                  DEADLINE
                </span>

                <strong>
                  {notificationClock.deadlineText}
                </strong>

              </div>


              <div className="cg-clock-basis">

                <span>
                  TRIGGER
                </span>

                <strong>
                  Potential notification trigger detected
                </strong>

              </div>


              <div className="cg-clock-note">

                ClockGuard has activated the
                72-hour notification review window.
                The final legal decision remains with
                the appropriate compliance/legal team.

              </div>

            </div>

          )}

        </div>


        {/* ===================================================
            REVIEW WORKFLOW
        =================================================== */}

        <div className="cg-workflow-card">

          <div className="cg-card-heading">

            <div>

              <span>
                REVIEW WORKFLOW
              </span>

              <h2>
                Required Actions
              </h2>

            </div>

            <div className="cg-card-icon">
              ↗
            </div>

          </div>


          <WorkflowStep
            number="01"
            title="Assess affected data"
            description="Determine whether personal, financial, health or other regulated data was affected."
          />


          <WorkflowStep
            number="02"
            title="Confirm jurisdiction"
            description="Identify the geographic and legal jurisdiction relevant to the incident."
          />


          <WorkflowStep
            number="03"
            title="Determine applicable obligations"
            description="Map applicable regulations, contracts and internal policies."
          />


          <WorkflowStep
            number="04"
            title="Assess notification"
            description="Determine whether regulatory, customer or internal notification is required."
          />


          <WorkflowStep
            number="05"
            title="Record final decision"
            description="Document the final security, legal and compliance decision."
          />

        </div>

      </section>


      {/* =====================================================
          DECISION CONTEXT
      ====================================================== */}

      <section className="cg-context-card">

        <div className="cg-card-heading">

          <div>

            <span>
              DECISION TRACE
            </span>

            <h2>
              Why This Case Requires Review
            </h2>

          </div>

          <div className="cg-card-icon">
            !
          </div>

        </div>


        <div className="cg-context-grid">

          {conditions
            .filter(
              item =>
                item.status !== 'clear'
            )
            .map(
              (condition, index) => (

                <div
                  className="cg-context-item"
                  key={condition.id}
                >

                  <div className="cg-context-number">

                    {String(
                      index + 1
                    ).padStart(2, '0')}

                  </div>


                  <div>

                    <strong>
                      {condition.name}
                    </strong>

                    <p>
                      {condition.reason}
                    </p>

                  </div>

                </div>

              )
            )}

        </div>


        <div className="cg-legal-note">

          <strong>
            Operational screening notice
          </strong>

          <p>
            ClockGuard identifies potential notification
            triggers from available incident evidence.
            When a potential trigger is detected, the
            prototype activates a 72-hour review window.
            The final legal determination remains with
            the appropriate security, privacy and legal
            teams.
          </p>

        </div>

      </section>

    </div>
  );
}


/* ============================================================
   WORKFLOW STEP
============================================================ */

function WorkflowStep({
  number,
  title,
  description,
}) {

  return (

    <div className="cg-workflow-step">

      <div className="cg-workflow-number">
        {number}
      </div>


      <div className="cg-workflow-content">

        <strong>
          {title}
        </strong>

        <p>
          {description}
        </p>

      </div>

    </div>
  );
}
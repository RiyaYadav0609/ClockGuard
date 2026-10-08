import { useEffect, useMemo, useState } from 'react';

import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';

import Overview from './pages/Overview';
import Analytics from './pages/Analytics';
import Incidents from './pages/Incidents';
import Investigation from './pages/Investigation';
import AttackPath from './pages/AttackPath';
import Timeline from './pages/Timeline';
import Mitre from './pages/Mitre';
import AiInvestigation from './pages/AiInvestigation';
import Compliance from './pages/Compliance';
import Assistant from './pages/Assistant';
import Settings from './pages/Settings';
import Threat from './pages/Threat';
import Auth from './pages/Auth';
import Reports from './pages/Reports';
import Nist from './pages/Nist';
import Knowledge from './pages/Knowledge';

import { api, normalizeList } from './services/api';
import { deriveAnalytics, uniqueByIncident } from './utils';


const titles = {
  overview: 'Command Center',
  threat: 'Threat Landscape',
  incidents: 'Incidents',
  investigation: 'Investigation',
  attack: 'Attack Path',
  timeline: 'Response Timeline',
  analytics: 'Threat Analytics',
  mitre: 'MITRE ATT&CK',
  ai: 'AI Investigation',
  assistant: 'AI SOC Assistant',
  compliance: 'Compliance',
  reports: 'Reports',
  nist: 'NIST Incident Response',
  knowledge: 'Knowledge Base',
  settings: 'Settings',
};


export default function App() {

  // =========================================================
  // AUTHENTICATION
  // =========================================================

  const [entered, setEntered] = useState(
    () => localStorage.getItem('clockguard_auth') === '1'
  );


  // =========================================================
  // NAVIGATION
  // =========================================================

  const [page, setPage] = useState('overview');


  // =========================================================
  // MAIN DATA
  // =========================================================

  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);

  const [selected, setSelected] = useState('');
  const [incident, setIncident] = useState(null);
  const [rows, setRows] = useState([]);

  const [analysis, setAnalysis] = useState(null);


  // =========================================================
  // SHARED COMPLIANCE RESULT
  //
  // This is now the SINGLE source of truth for:
  // - Compliance page
  // - Topbar notification
  // =========================================================

  const [complianceResult, setComplianceResult] =
    useState(null);

  const [complianceLoading, setComplianceLoading] =
    useState(false);


  // =========================================================
  // UI STATE
  // =========================================================

  const [health, setHealth] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');


  // =========================================================
  // LOAD DASHBOARD DATA
  // =========================================================

  async function load() {

    setLoading(true);
    setErr('');

    try {

      const [h, s, ins] = await Promise.all([
        api.health(),
        api.summary(),

        api.incidents({
          limit: 1000,
        }),
      ]);


      const raw = normalizeList(ins);

      setHealth(h?.status === 'ok');

      setSummary(s);

      setIncidents(
        uniqueByIncident(raw)
      );

    } catch (e) {

      setHealth(false);

      setErr(
        `Backend not connected: ${e.message}`
      );

    } finally {

      setLoading(false);

    }
  }


  // =========================================================
  // LOAD SELECTED INCIDENT
  // =========================================================

  async function loadIncident(id) {

    setAnalysis(null);

    // No incident selected
    if (!id) {

      setIncident(null);
      setRows([]);

      // IMPORTANT:
      // Remove old compliance timer/result.
      setComplianceResult(null);

      return;
    }


    // Clear old compliance result immediately
    setComplianceResult(null);
    setComplianceLoading(true);


    try {

      const [d, t, compliance] =
        await Promise.all([

          api.incident(id),

          api.timeline(id),

          api.compliance(id),

        ]);


      // Incident details
      setIncident(
        d?.incident || d
      );


      // Timeline/evidence rows
      setRows(
        normalizeList(t)
      );


      // =====================================================
      // SHARED COMPLIANCE RESULT
      //
      // This exact object is passed to BOTH:
      // Compliance.jsx
      // Topbar.jsx
      // =====================================================

      setComplianceResult(compliance);

    } catch (e) {

      setErr(
        `Incident load failed: ${e.message}`
      );

      setComplianceResult(null);

    } finally {

      setComplianceLoading(false);

    }
  }


  // =========================================================
  // MANUAL / REFRESHED COMPLIANCE CHECK
  //
  // Compliance.jsx can call this.
  // The result automatically updates Topbar too.
  // =========================================================

  async function runComplianceCheck(id) {

    const incidentId =
      id || incident?.incident_id || selected;

    if (!incidentId) {
      return null;
    }

    setComplianceLoading(true);

    try {

      const response =
        await api.compliance(incidentId);

      setComplianceResult(response);

      return response;

    } catch (e) {

      setErr(
        `Compliance check failed: ${e.message}`
      );

      throw e;

    } finally {

      setComplianceLoading(false);

    }
  }


  // =========================================================
  // LOAD INITIAL DATA AFTER LOGIN
  // =========================================================

  useEffect(() => {

    if (entered) {
      load();
    }

  }, [entered]);


  // =========================================================
  // LOAD INCIDENT WHEN SELECTED
  // =========================================================

  useEffect(() => {

    if (entered) {

      loadIncident(selected);

    }

  }, [selected, entered]);


  // =========================================================
  // ANALYTICS
  // =========================================================

  const analytics = useMemo(
    () =>
      deriveAnalytics(
        incidents,
        summary || {}
      ),
    [incidents, summary]
  );


  // =========================================================
  // LOGOUT
  // =========================================================

  const logout = () => {

    localStorage.removeItem(
      'clockguard_auth'
    );

    setEntered(false);

  };


  // =========================================================
  // AUTH SCREEN
  // =========================================================

  if (!entered) {

    return (
      <Auth
        onEnter={() =>
          setEntered(true)
        }
      />
    );

  }


  // =========================================================
  // COMMON PROPS FOR ALL PAGES
  // =========================================================

  const props = {

    summary,
    analytics,
    incidents,

    setPage,
    setSelected,

    incident,
    rows,

    analysis,
    setAnalysis,

    api,

    health,
    loading,

    // Shared compliance data
    complianceResult,
    complianceLoading,
    runComplianceCheck,

  };


  // =========================================================
  // APPLICATION
  // =========================================================

  return (

    <div className="app">

      {/* =====================================================
          SIDEBAR
      ====================================================== */}

      <Sidebar
        page={page}
        setPage={setPage}
        health={health}
      />


      {/* =====================================================
          MAIN CONTENT
      ====================================================== */}

      <main className="main">

        {/* ===================================================
            TOPBAR
        ==================================================== */}

        <Topbar
          title={titles[page]}
          incidents={incidents}
          selected={selected}
          setSelected={setSelected}
          onRefresh={load}
          loading={loading}
          complianceResult={complianceResult}
          complianceLoading={complianceLoading}
        />


        {/* ===================================================
            ERROR BAR
        ==================================================== */}

        {err && (

          <div className="errorbar">

            {err}

            <button
              onClick={() =>
                setErr('')
              }
            >
              ×
            </button>

          </div>

        )}


        {/* ===================================================
            PAGES
        ==================================================== */}

        {page === 'overview' && (
          <Overview {...props} />
        )}

        {page === 'threat' && (
          <Threat {...props} />
        )}

        {page === 'analytics' && (
          <Analytics {...props} />
        )}

        {page === 'incidents' && (
          <Incidents {...props} />
        )}

        {page === 'investigation' && (
          <Investigation {...props} />
        )}

        {page === 'attack' && (
          <AttackPath {...props} />
        )}

        {page === 'timeline' && (
          <Timeline {...props} />
        )}

        {page === 'mitre' && (
          <Mitre {...props} />
        )}

        {page === 'ai' && (
          <AiInvestigation {...props} />
        )}

        {page === 'compliance' && (
          <Compliance {...props} />
        )}

        {page === 'assistant' && (
          <Assistant {...props} />
        )}

        {page === 'reports' && (
          <Reports {...props} />
        )}

        {page === 'nist' && (
          <Nist {...props} />
        )}

        {page === 'knowledge' && (
          <Knowledge {...props} />
        )}

        {page === 'settings' && (
          <Settings {...props} />
        )}


        {/* ===================================================
            LOGOUT
        ==================================================== */}

        <button
          className="logoutFloat"
          onClick={logout}
        >
          Sign out
        </button>

      </main>

    </div>
  );
}
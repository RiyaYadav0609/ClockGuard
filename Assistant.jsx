import { useState } from 'react';

export default function Assistant({ incident, api }) {
  const [q, setQ] = useState('');
  const [msgs, setMsgs] = useState([]);
  const [busy, setBusy] = useState(false);

  const prompts = [
    'Why is this incident high risk?',
    'What MITRE techniques were detected?',
    'What should I do now?',
    'Explain the evidence',
    'Explain the NIST phase',
  ];

  // ---------------------------------------------------------
  // Safely convert any backend response into displayable text
  // ---------------------------------------------------------
  const normalizeResponse = (response) => {
    if (response == null) {
      return 'The AI assistant returned an empty response.';
    }

    if (typeof response === 'string') {
      return response;
    }

    if (typeof response === 'number' || typeof response === 'boolean') {
      return String(response);
    }

    if (typeof response === 'object') {
      // Most likely Azure/backend response
      if (typeof response.answer === 'string') {
        return response.answer;
      }

      if (typeof response.response === 'string') {
        return response.response;
      }

      if (typeof response.message === 'string') {
        return response.message;
      }

      // If answer itself is an object
      if (response.answer && typeof response.answer === 'object') {
        try {
          return JSON.stringify(response.answer, null, 2);
        } catch {
          return 'The assistant returned an unreadable response.';
        }
      }

      try {
        return JSON.stringify(response, null, 2);
      } catch {
        return 'The assistant returned an unreadable response.';
      }
    }

    return String(response);
  };

  // ---------------------------------------------------------
  // Send question
  // ---------------------------------------------------------
  async function send(text = q) {
    const question = String(text || '').trim();

    if (!question || !incident || busy) {
      return;
    }

    setQ('');

    setMsgs((messages) => [
      ...messages,
      {
        role: 'user',
        text: question,
      },
    ]);

    setBusy(true);

    try {
      if (!api || typeof api.chat !== 'function') {
        throw new Error('AI Assistant API is not available.');
      }

      if (!incident?.incident_id) {
        throw new Error('No incident is selected.');
      }

      // Call existing backend API
      const result = await api.chat(
        incident.incident_id,
        question
      );

      const answer = normalizeResponse(result);

      setMsgs((messages) => [
        ...messages,
        {
          role: 'assistant',
          text: answer,
        },
      ]);
    } catch (error) {
      console.error('ClockGuard AI Assistant error:', error);

      setMsgs((messages) => [
        ...messages,
        {
          role: 'assistant',
          text:
            error?.message
              ? `Assistant error: ${error.message}`
              : 'Assistant error: Unable to process the request.',
        },
      ]);
    } finally {
      setBusy(false);
    }
  }

  // ---------------------------------------------------------
  // UI
  // ---------------------------------------------------------
  return (
    <div className="page">

      {/* PAGE HEADER */}
      <div className="pageintro">
        <div>
          <span className="eyebrow">
            INVESTIGATOR COPILOT
          </span>

          <h1>AI SOC Assistant</h1>

          <p>
            Context-aware questions grounded in the selected
            ClockGuard incident.
          </p>
        </div>
      </div>

      {/* ASSISTANT */}
      <section className="assistant panel">

        {/* ASSISTANT HEADER */}
        <div className="assistanthead">
          <div>
            <b>CLOCKGUARD AI</b>

            <span>
              Context: {incident?.incident_id || 'None'}
            </span>
          </div>

          <span className="live">
            ● {busy ? 'ANALYZING' : 'READY'}
          </span>
        </div>

        {/* QUICK QUESTIONS */}
        <div className="promptrow">
          {prompts.map((prompt) => (
            <button
              key={prompt}
              type="button"
              onClick={() => send(prompt)}
              disabled={!incident || busy}
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* MESSAGES */}
        <div className="messages">

          {!msgs.length && (
            <div className="welcome">
              <strong>
                Ask anything about this incident.
              </strong>

              <span>
                Risk, evidence, MITRE ATT&CK, NIST,
                response actions or investigation summary.
              </span>
            </div>
          )}

          {msgs.map((message, index) => (
            <div
              className={`message ${message.role}`}
              key={`${message.role}-${index}`}
            >
              <b>
                {message.role === 'user' ? 'YOU' : 'CG'}
              </b>

              <p>
                {String(message.text ?? '')}
              </p>
            </div>
          ))}

          {busy && (
            <div className="message assistant">
              <b>CG</b>

              <p>
                Analyzing incident context…
              </p>
            </div>
          )}

        </div>

        {/* QUESTION INPUT */}
        <form
          onSubmit={(event) => {
            event.preventDefault();

            if (!busy && incident) {
              send();
            }
          }}
        >

          <input
            value={q}
            onChange={(event) => setQ(event.target.value)}
            placeholder={
              incident
                ? 'Ask about this incident…'
                : 'Select an incident first…'
            }
            disabled={!incident || busy}
          />

          <button
            type="submit"
            className="primary"
            disabled={!incident || busy || !q.trim()}
          >
            {busy ? 'Analyzing…' : 'Send'}
          </button>

        </form>

      </section>

    </div>
  );
}
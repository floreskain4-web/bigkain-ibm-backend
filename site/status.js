(() => {
  'use strict';

  const API_BASE = 'https://bigkain-ibm-backend.vercel.app';
  const page = document;
  const HEALTH_PATH = '/health';
  const DASHBOARD_VERSION = page.querySelector('meta[name="dashboard-version"]')?.content || 'source';
  const ETF_PATH = `/v1/btc/market/etf-flow?dashboard_build=${encodeURIComponent(DASHBOARD_VERSION)}`;
  const REQUEST_TIMEOUT_MS = 8000;
  const POLL_INTERVAL_MS = 60000;
  const refreshButton = page.getElementById('refresh-button');
  let refreshing = false;

  const formatMillions = (value) => {
    const sign = value < 0 ? '−' : '+';
    const formatted = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(Math.abs(value));
    return `${sign}$${formatted}M`;
  };

  const formatDate = (value) => {
    const date = new Date(`${value}T00:00:00Z`);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(date);
  };

  function setText(id, value) {
    const element = page.getElementById(id);
    if (element) element.textContent = value;
    return element;
  }

  function updateCard(name, state, value, detail) {
    const card = page.querySelector(`[data-check="${name}"]`);
    if (!card) return;
    card.dataset.state = state;
    const valueNode = card.querySelector('[data-value]');
    const detailNode = card.querySelector('[data-detail]');
    if (valueNode) valueNode.textContent = value;
    if (detailNode) detailNode.textContent = detail;
  }

  async function getJson(path) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await window.fetch(`${API_BASE}${path}`, {
        method: 'GET',
        mode: 'cors',
        cache: 'no-store',
        credentials: 'omit',
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Status endpoint returned ${response.status}`);
      return await response.json();
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function setOverall(state, label, summary) {
    const badge = page.getElementById('overall-badge');
    if (badge) {
      badge.dataset.state = state;
      const text = badge.querySelector('[data-overall-label]');
      if (text) text.textContent = label;
    }
    setText('status-summary', summary);
  }

  function updateHealth(health) {
    const healthOk = health?.ok === true && health?.service === 'bigkain-backend';
    if (!healthOk) {
      updateCard('backend', 'offline', 'Unavailable', 'The public health endpoint did not return a valid service response.');
      updateCard('network', 'offline', 'Unknown', 'Network mode is unavailable until the health check succeeds.');
      updateCard('key-boundary', 'offline', 'Unknown', 'Key-material status is unavailable until the health check succeeds.');
      updateCard('ownership', 'offline', 'Unknown', 'Proof state is unavailable until the health check succeeds.');
      return false;
    }

    updateCard('backend', 'online', 'Operational', 'The live /health request succeeded.');
    const isMainnet = health.network === 'bitcoin-mainnet';
    updateCard(
      'network',
      isMainnet ? 'online' : 'warning',
      isMainnet ? 'Bitcoin mainnet' : 'Unexpected network',
      isMainnet ? 'The API reports Bitcoin mainnet.' : `The API reports: ${String(health.network || 'unknown')}.`,
    );

    const noKeyMaterial = health.private_keys_received === false;
    updateCard(
      'key-boundary',
      noKeyMaterial ? 'online' : 'warning',
      noKeyMaterial ? 'None reported' : 'Review required',
      noKeyMaterial ? 'The API reports that it has received no private keys.' : 'The API did not confirm its public key-material boundary.',
    );

    const proof = typeof health.ownership_proof === 'string' ? health.ownership_proof : 'UNKNOWN';
    const proofKnown = proof === 'PROVEN' || proof === 'UNPROVEN';
    updateCard(
      'ownership',
      proof === 'PROVEN' ? 'online' : proofKnown ? 'neutral' : 'warning',
      proof,
      proof === 'PROVEN' ? 'A public ownership proof is recorded.' : proof === 'UNPROVEN' ? 'No public ownership proof is recorded.' : 'The API returned an unfamiliar proof state.',
    );
    return true;
  }

  function renderFlowUnavailable() {
    setText('daily-flow', '—');
    setText('daily-flow-date', 'Data unavailable');
    setText('five-session-flow', '—');
    setText('session-breadth', '—');
    setText('flow-as-of', 'As of —');
    setText('market-detail', 'The read-only ETF flow feed is unavailable or returned invalid data. The service-health check is reported separately.');
    const signal = page.getElementById('flow-signal');
    if (signal) {
      signal.className = 'signal-badge signal-loading';
      signal.textContent = 'Unavailable';
    }
    const chart = page.getElementById('flow-chart');
    if (chart) {
      const empty = page.createElement('p');
      empty.className = 'chart-empty';
      empty.textContent = 'Flow sessions are temporarily unavailable.';
      chart.replaceChildren(empty);
    }
    updateCard('etf', 'offline', 'Unavailable', 'The read-only ETF endpoint did not return validated market data.');
    return false;
  }

  function renderFlow(data) {
    const validSignal = ['GREEN', 'YELLOW', 'RED'].includes(data?.signal);
    const valid = data?.source === 'Farside Investors' &&
      /^\d{4}-\d{2}-\d{2}$/.test(data?.asOfDate || '') &&
      Number.isFinite(data?.dailyNetFlowUsdM) &&
      Number.isFinite(data?.fiveSessionNetFlowUsdM) &&
      Number.isInteger(data?.positiveSessions) && Number.isInteger(data?.negativeSessions) &&
      validSignal && Array.isArray(data?.sessions) && data.sessions.length > 0 &&
      data.sessions.every((item) => /^\d{4}-\d{2}-\d{2}$/.test(item?.date || '') && Number.isFinite(item?.netFlowUsdM));
    if (!valid) return renderFlowUnavailable();

    const latest = data.sessions[data.sessions.length - 1];
    const daily = setText('daily-flow', formatMillions(data.dailyNetFlowUsdM));
    if (daily) daily.className = data.dailyNetFlowUsdM < 0 ? 'negative' : 'positive';
    setText('daily-flow-date', `As of ${formatDate(latest.date)}`);
    const five = setText('five-session-flow', formatMillions(data.fiveSessionNetFlowUsdM));
    if (five) five.className = data.fiveSessionNetFlowUsdM < 0 ? 'negative' : 'positive';
    setText('session-breadth', `${data.positiveSessions} / ${data.negativeSessions}`);
    setText('flow-as-of', `Source data as of ${formatDate(data.asOfDate)}`);

    const signal = page.getElementById('flow-signal');
    if (signal) {
      signal.className = `signal-badge signal-${data.signal.toLowerCase()}`;
      signal.textContent = data.signal;
    }
    setText('market-detail', 'The signal reflects the latest five reported sessions only. It is market context, not an investment recommendation or service-health indicator.');
    updateCard('etf', 'online', 'Available', `Source data through ${formatDate(data.asOfDate)}; read-only market feed.`);

    const chart = page.getElementById('flow-chart');
    if (!chart) return true;
    const sessions = data.sessions.slice(-5);
    const largest = Math.max(1, ...sessions.map((item) => Math.abs(item.netFlowUsdM)));
    const rows = sessions.map((item) => {
      const row = page.createElement('div');
      row.className = 'flow-row';
      row.setAttribute('role', 'listitem');

      const date = page.createElement('span');
      date.className = 'flow-date';
      date.textContent = formatDate(item.date);

      const track = page.createElement('span');
      track.className = 'flow-track';
      track.setAttribute('aria-hidden', 'true');
      const bar = page.createElement('span');
      bar.className = `flow-bar ${item.netFlowUsdM < 0 ? 'negative' : 'positive'}`;
      bar.style.width = `${Math.max(2, (Math.abs(item.netFlowUsdM) / largest) * 48)}%`;
      track.append(bar);

      const amount = page.createElement('span');
      amount.className = 'flow-amount';
      amount.textContent = formatMillions(item.netFlowUsdM);

      row.append(date, track, amount);
      return row;
    });
    chart.replaceChildren(...rows);
    return true;
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    if (refreshButton) {
      refreshButton.disabled = true;
      refreshButton.setAttribute('aria-busy', 'true');
    }

    try {
      const [healthResult, flowResult] = await Promise.allSettled([
        getJson(HEALTH_PATH),
        getJson(ETF_PATH),
      ]);
      const healthOk = healthResult.status === 'fulfilled' && updateHealth(healthResult.value);
      if (healthResult.status === 'rejected') {
        updateHealth(null);
      }
      const flowOk = flowResult.status === 'fulfilled' && renderFlow(flowResult.value);
      if (flowResult.status === 'rejected') {
        renderFlowUnavailable();
      }

      if (healthOk && flowOk) {
        setOverall('online', 'All systems nominal', 'The API and read-only market-data feed both responded.');
      } else if (healthOk || flowOk) {
        setOverall('partial', 'Partial availability', 'At least one public endpoint responded; review each card for detail.');
      } else {
        setOverall('offline', 'Attention required', 'The public checks could not be completed. The page will retry automatically.');
      }

      const checked = new Date();
      const checkedTime = page.getElementById('checked-time');
      if (checkedTime) {
        checkedTime.dateTime = checked.toISOString();
        checkedTime.textContent = checked.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' });
      }
    } catch {
      updateHealth(null);
      renderFlowUnavailable();
      setOverall('offline', 'Attention required', 'The public checks could not be completed. The page will retry automatically.');
    } finally {
      refreshing = false;
      if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.removeAttribute('aria-busy');
      }
    }
  }

  if (refreshButton) refreshButton.addEventListener('click', refresh);
  refresh();
  window.setInterval(refresh, POLL_INTERVAL_MS);
})();

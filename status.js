(() => {
  'use strict';

  const root = document.getElementById('bk-live-status');
  if (!root) return;

  const API_BASE = 'https://bigkain-ibm-backend.vercel.app';
  const REQUEST_TIMEOUT_MS = 8000;
  const POLL_INTERVAL_MS = 60000;
  let refreshing = false;

  function updateCard(name, state, value, detail) {
    const card = root.querySelector(`[data-check="${name}"]`);
    if (!card) return;
    const light = card.querySelector('[data-light]');
    const valueNode = card.querySelector('[data-value]');
    const detailNode = card.querySelector('[data-detail]');
    if (light) light.dataset.state = state;
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
      if (!response.ok) throw new Error('Status endpoint unavailable');
      return await response.json();
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function setHealthUnavailable() {
    updateCard('backend', 'offline', 'Unavailable', 'The health endpoint did not return a valid response.');
    updateCard('network', 'offline', 'Unknown', 'Network status is unavailable until the health check succeeds.');
    updateCard('key-boundary', 'offline', 'Unknown', 'Key-material status is unavailable until the health check succeeds.');
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const [healthResult, etfResult] = await Promise.allSettled([
        getJson('/health'),
        getJson('/v1/btc/market/etf-flow'),
      ]);

      const healthOk = healthResult.status === 'fulfilled' &&
        healthResult.value?.ok === true &&
        healthResult.value?.service === 'bigkain-backend';

      if (healthOk) {
        const health = healthResult.value;
        updateCard('backend', 'online', 'Online', 'The live /health check succeeded.');
        const mainnet = health.network === 'bitcoin-mainnet';
        updateCard(
          'network',
          mainnet ? 'online' : 'warning',
          mainnet ? 'Bitcoin mainnet' : 'Unexpected network',
          mainnet ? 'Reported by the backend health endpoint.' : `Backend reports: ${String(health.network || 'unknown')}.`,
        );
        const noKeyMaterial = health.private_keys_received === false;
        updateCard(
          'key-boundary',
          noKeyMaterial ? 'online' : 'warning',
          noKeyMaterial ? 'None reported' : 'Review required',
          'Live private_keys_received value from /health; signing and broadcasting are not performed by this page.',
        );
      } else {
        setHealthUnavailable();
      }

      const etf = etfResult.status === 'fulfilled' ? etfResult.value : null;
      const etfOk = etf && etf.source === 'Farside Investors' &&
        /^\d{4}-\d{2}-\d{2}$/.test(etf.asOfDate || '') &&
        ['GREEN', 'YELLOW', 'RED'].includes(etf.signal) &&
        Number.isFinite(etf.fiveSessionNetFlowUsdM);
      if (etfOk) {
        const flow = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1, signDisplay: 'always' })
          .format(etf.fiveSessionNetFlowUsdM);
        updateCard(
          'etf',
          'online',
          'Available',
          `As of ${etf.asOfDate}; five-session flow ${flow} USD millions; market signal ${etf.signal}.`,
        );
      } else {
        updateCard('etf', 'offline', 'Unavailable', 'The read-only ETF flow endpoint did not return valid data.');
      }

      const summary = root.querySelector('[data-status-summary]');
      const checkedAt = root.querySelector('[data-checked-time]');
      const now = new Date();
      if (summary) summary.textContent = healthOk ? 'Live backend checks updated.' : 'Backend health check failed; review the status details.';
      if (checkedAt) checkedAt.textContent = `Last checked: ${now.toLocaleTimeString()}`;
    } catch {
      setHealthUnavailable();
      updateCard('etf', 'offline', 'Unavailable', 'The read-only ETF flow endpoint did not return valid data.');
      const summary = root.querySelector('[data-status-summary]');
      const checkedAt = root.querySelector('[data-checked-time]');
      if (summary) summary.textContent = 'Live checks could not be completed; retrying automatically.';
      if (checkedAt) checkedAt.textContent = `Last checked: ${new Date().toLocaleTimeString()}`;
    } finally {
      refreshing = false;
    }
  }

  refresh();
  window.setInterval(refresh, POLL_INTERVAL_MS);
})();

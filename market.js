import { Router } from 'express';

export const FARSIDE_BTC_ALL_DATA_URL = 'https://farside.co.uk/bitcoin-etf-flow-all-data/';
export const ETF_FLOW_PATH = '/v1/btc/market/etf-flow';
const REQUIRED_SESSIONS = 5;
const MONTHS = new Map([
  ['jan', '01'], ['feb', '02'], ['mar', '03'], ['apr', '04'],
  ['may', '05'], ['jun', '06'], ['jul', '07'], ['aug', '08'],
  ['sep', '09'], ['oct', '10'], ['nov', '11'], ['dec', '12'],
]);

function decodeHtmlEntities(value) {
  const named = {
    amp: '&', apos: "'", gt: '>', lt: '<', nbsp: ' ', quot: '"',
    minus: '−', ndash: '–', mdash: '—',
  };
  return value.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (match, entity) => {
    if (entity[0] === '#') {
      const hex = entity[1]?.toLowerCase() === 'x';
      const codePoint = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
      try {
        return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : match;
      } catch {
        return match;
      }
    }
    return named[entity.toLowerCase()] ?? match;
  });
}

function cellText(html) {
  return decodeHtmlEntities(
    html
      .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<br\s*\/?>/gi, ' ')
      .replace(/<[^>]*>/g, ' '),
  )
    .replace(/[\u00a0\t\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseDate(value) {
  const match = value.match(/^(\d{1,2})\s+([a-z]{3})\s+(\d{4})$/i);
  if (!match) return null;
  const month = MONTHS.get(match[2].toLowerCase());
  if (!month) return null;
  return `${match[3]}-${month}-${match[1].padStart(2, '0')}`;
}

function parseFlowValue(value) {
  const text = value.trim().replace(/[\u2212\u2012\u2013\u2014]/g, '-');
  if (!text || /^[-]+$/.test(text) || /^(?:n\/a|na)$/i.test(text)) return null;

  const accountingNegative = /^\(.*\)$/.test(text);
  const normalized = text.replace(/[(),$\s]/g, '');
  if (!/^[+-]?\d+(?:\.\d+)?$/.test(normalized)) return null;
  const parsed = Number(normalized);
  if (!Number.isFinite(parsed)) return null;
  const signed = accountingNegative ? -Math.abs(parsed) : parsed;
  return Math.round((signed + Math.sign(signed) * Number.EPSILON) * 10) / 10;
}

/**
 * Parse Farside's all-data HTML table into chronological reporting sessions.
 * The published Total column is used as net flow; rows with no reported fund
 * values (for example, a market holiday or a not-yet-updated row) are skipped.
 */
export function parseFarsideSessions(html) {
  if (typeof html !== 'string') throw new TypeError('Farside response must be HTML text');
  const byDate = new Map();
  const rows = html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi);

  for (const [, rowHtml] of rows) {
    const cells = [...rowHtml.matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)]
      .map(([, rawCell]) => cellText(rawCell));
    if (cells.length < 3) continue;

    const date = parseDate(cells[0]);
    if (!date) continue;

    const fundFlows = cells.slice(1, -1).map(parseFlowValue);
    const netFlowUsdM = parseFlowValue(cells.at(-1));
    if (netFlowUsdM == null || fundFlows.every((flow) => flow == null)) continue;

    byDate.set(date, { date, netFlowUsdM });
  }

  return [...byDate.values()].sort((a, b) => a.date.localeCompare(b.date));
}

export function calculateFlowSignal(fiveSessionNetFlowUsdM, positiveSessions, negativeSessions) {
  if (fiveSessionNetFlowUsdM > 0 && positiveSessions > negativeSessions) return 'GREEN';
  if (fiveSessionNetFlowUsdM < 0 && negativeSessions > positiveSessions) return 'RED';
  return 'YELLOW';
}

export function summarizeEtfFlows(sessions, fetchedAt = new Date().toISOString()) {
  const chronological = [...sessions]
    .filter((session) => session && /^\d{4}-\d{2}-\d{2}$/.test(session.date) && Number.isFinite(session.netFlowUsdM))
    .sort((a, b) => a.date.localeCompare(b.date));
  if (chronological.length < REQUIRED_SESSIONS) {
    throw new Error(`at least ${REQUIRED_SESSIONS} reported ETF sessions are required`);
  }

  const window = chronological.slice(-REQUIRED_SESSIONS);
  const latest = window.at(-1);
  const fiveSessionNetFlowUsdM = Math.round(
    (window.reduce((sum, session) => sum + session.netFlowUsdM, 0) + Number.EPSILON) * 10,
  ) / 10;
  const positiveSessions = window.filter((session) => session.netFlowUsdM > 0).length;
  const negativeSessions = window.filter((session) => session.netFlowUsdM < 0).length;

  return {
    source: 'Farside Investors',
    sourceUrl: FARSIDE_BTC_ALL_DATA_URL,
    asOfDate: latest.date,
    fetchedAt,
    currency: 'USD',
    unit: 'millions',
    dailyNetFlowUsdM: latest.netFlowUsdM,
    fiveSessionNetFlowUsdM,
    positiveSessions,
    negativeSessions,
    signal: calculateFlowSignal(fiveSessionNetFlowUsdM, positiveSessions, negativeSessions),
    sessions: window.map(({ date, netFlowUsdM }) => ({ date, netFlowUsdM })),
    signalRule: 'GREEN when five-session net flow and session breadth are positive; RED when both are negative; otherwise YELLOW.',
  };
}

export function createEtfFlowRouter({ fetchImpl = (url, options) => globalThis.fetch(url, options) } = {}) {
  const router = Router();

  router.get(ETF_FLOW_PATH, async (_req, res) => {
    try {
      const upstream = await fetchImpl(FARSIDE_BTC_ALL_DATA_URL, {
        method: 'GET',
        headers: {
          Accept: 'text/html,application/xhtml+xml',
          'User-Agent': 'BigKain read-only ETF flow endpoint',
        },
        signal: AbortSignal.timeout(10_000),
      });
      if (!upstream?.ok) throw new Error('Farside upstream unavailable');

      const sessions = parseFarsideSessions(await upstream.text());
      const response = summarizeEtfFlows(sessions);
      res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
      return res.json(response);
    } catch {
      return res.status(502).json({ error: 'Farside ETF flow data is temporarily unavailable' });
    }
  });

  return router;
}

'use strict';

/*
 * The base URL stays a constant: an override could send the bearer token to
 * another host.
 */

const { URLSearchParams } = require('url');
const auth = require('./auth');
const { httpsRequest } = require('./http-client');

const API_BASE = 'https://gmailpostmastertools.googleapis.com/v2';

const STANDARD_METRICS = [
  'FEEDBACK_LOOP_ID',
  'FEEDBACK_LOOP_SPAM_RATE',
  'SPAM_RATE',
  'AUTH_SUCCESS_RATE',
  'TLS_ENCRYPTION_MESSAGE_COUNT',
  'TLS_ENCRYPTION_RATE',
  'DELIVERY_ERROR_COUNT',
  'DELIVERY_ERROR_RATE',
];

// Metrics Google rejects without a filter, from the API's discovery document.
const REQUIRED_FILTERS = {
  AUTH_SUCCESS_RATE: {
    pattern: /auth_type\s*=\s*"(spf|dkim|dmarc)"/,
    example: 'auth_type = "dkim" (spf, dkim or dmarc)',
  },
  TLS_ENCRYPTION_MESSAGE_COUNT: {
    pattern: /traffic_direction\s*=\s*"(inbound|outbound)"/,
    example: 'traffic_direction = "inbound" (inbound or outbound)',
  },
  TLS_ENCRYPTION_RATE: {
    pattern: /traffic_direction\s*=\s*"(inbound|outbound)"/,
    example: 'traffic_direction = "inbound" (inbound or outbound)',
  },
  FEEDBACK_LOOP_SPAM_RATE: {
    pattern: /feedback_loop_id\s*=\s*"[^"]+"/,
    example: 'feedback_loop_id = "<id from FEEDBACK_LOOP_ID>"',
  },
};

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const LABEL = '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?';
const HOST_RE = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})+$`);
const DAY_MS = 86400000;

const MAX_PAGE_SIZE = 200;
const MAX_STATS_PAGES = 25;
const MAX_METRIC_NAME_LENGTH = 100;

function request(method, url, token, bodyObj) {
  const payload = bodyObj ? Buffer.from(JSON.stringify(bodyObj)) : null;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'User-Agent': 'gmail-postmaster-mcp',
  };
  if (payload) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = payload.length;
  }
  return httpsRequest({ method, url, headers, body: payload });
}

async function call(method, pathSuffix, bodyObj) {
  const url = API_BASE + pathSuffix;
  const token = await auth.getAccessToken();
  const first = await request(method, url, token, bodyObj);
  if (first.status !== 401) return first;

  // The access token can be revoked before its expiry time, so try one
  // refresh before asking the person to sign in again.
  const freshToken = await auth.getAccessToken({ forceRefresh: true });
  const second = await request(method, url, freshToken, bodyObj);
  if (second.status !== 401) return second;

  const e = new Error('Google rejected the access token (401). Run "gpt_authenticate" to sign in again.');
  e.code = 'NEED_AUTH';
  throw e;
}

function validateDomain(domain) {
  const isValid = typeof domain === 'string' && HOST_RE.test(domain);
  if (!isValid) {
    throw new Error(`Invalid domain "${domain}". Use a fully-qualified domain name, e.g. mail.example.com.`);
  }
  return domain.toLowerCase();
}

function parseDate(s, label) {
  const match = typeof s === 'string' ? DATE_RE.exec(s) : null;
  if (!match) throw new Error(`Invalid ${label} "${s}". Expected yyyy-MM-dd.`);
  const [year, month, day] = match.slice(1).map(Number);
  // Date.UTC rolls February 31 into March, so a round trip finds fake dates.
  const asTime = Date.UTC(year, month - 1, day);
  const isRealDate = new Date(asTime).toISOString().slice(0, 10) === s;
  if (!isRealDate) throw new Error(`Invalid ${label} "${s}". That date does not exist.`);
  return { year, month, day, time: asTime };
}

function toApiDate({ year, month, day }) {
  return { year, month, day };
}

function isoDate(time) {
  return new Date(time).toISOString().slice(0, 10);
}

function validatePageSize(pageSize) {
  const isValid = Number.isInteger(pageSize) && pageSize >= 1 && pageSize <= MAX_PAGE_SIZE;
  if (!isValid) throw new Error(`pageSize must be a whole number from 1 to ${MAX_PAGE_SIZE}.`);
}

function buildMetricDefinitions(metrics) {
  let input = metrics;
  const isMissing = input === undefined || input === null || (Array.isArray(input) && input.length === 0);
  if (isMissing) input = ['SPAM_RATE'];
  if (!Array.isArray(input)) input = [input];

  const seenNames = new Set();
  return input.map((metric, i) => {
    const isString = typeof metric === 'string';
    const isObject = metric !== null && typeof metric === 'object' && !Array.isArray(metric);
    if (!isString && !isObject) {
      throw new Error(`Metric ${i + 1} must be a metric name or an object with standardMetric.`);
    }

    const rawName = isString ? metric : metric.standardMetric;
    const standardMetric = String(rawName || '').toUpperCase();
    if (!STANDARD_METRICS.includes(standardMetric)) {
      throw new Error(`Unknown metric "${standardMetric}". Supported: ${STANDARD_METRICS.join(', ')}.`);
    }

    const filter = isObject && metric.filter !== undefined ? metric.filter : '';
    if (typeof filter !== 'string') throw new Error(`The filter for ${standardMetric} must be a string.`);

    const requirement = REQUIRED_FILTERS[standardMetric];
    const failsRequirement = requirement && !requirement.pattern.test(filter);
    if (failsRequirement) {
      throw new Error(`${standardMetric} needs a filter like: ${requirement.example}.`);
    }

    const name = isObject && metric.name ? metric.name : `${standardMetric}_${i}`;
    const hasValidName = typeof name === 'string' && name.length <= MAX_METRIC_NAME_LENGTH;
    if (!hasValidName) throw new Error(`Metric name must be a string of at most ${MAX_METRIC_NAME_LENGTH} characters.`);
    if (seenNames.has(name)) throw new Error(`Metric name "${name}" is used twice. Each needs its own name.`);
    seenNames.add(name);

    const definition = { name, baseMetric: { standardMetric } };
    if (filter) definition.filter = filter;
    return definition;
  });
}

// --- public methods ---

async function listDomains({ pageSize, pageToken } = {}) {
  const qs = new URLSearchParams();
  if (pageSize !== undefined) {
    validatePageSize(pageSize);
    qs.set('pageSize', String(pageSize));
  }
  if (pageToken) qs.set('pageToken', pageToken);
  const q = qs.toString();
  return call('GET', `/domains${q ? '?' + q : ''}`);
}

async function getDomain({ domain }) {
  const name = validateDomain(domain);
  return call('GET', `/domains/${encodeURIComponent(name)}`);
}

async function getComplianceStatus({ domain }) {
  const name = validateDomain(domain);
  return call('GET', `/domains/${encodeURIComponent(name)}/complianceStatus`);
}

async function queryDomainStats({ domain, start_date, end_date, granularity, metrics, pageToken } = {}) {
  const name = validateDomain(domain);

  // Yesterday by default: today's data is usually incomplete.
  const end = parseDate(end_date || isoDate(Date.now() - DAY_MS), 'end_date');
  // Counted from the end date, so an end date alone still gives a valid range.
  const start = parseDate(start_date || isoDate(end.time - 6 * DAY_MS), 'start_date');
  if (start.time > end.time) {
    throw new Error(`start_date ${isoDate(start.time)} is after end_date ${isoDate(end.time)}.`);
  }

  const gran = String(granularity || 'DAILY').toUpperCase();
  if (!['DAILY', 'OVERALL'].includes(gran)) throw new Error('granularity must be DAILY or OVERALL.');

  const baseBody = {
    metricDefinitions: buildMetricDefinitions(metrics),
    aggregationGranularity: gran,
    pageSize: MAX_PAGE_SIZE,
    timeQuery: { dateRanges: { dateRanges: [{ start: toApiDate(start), end: toApiDate(end) }] } },
  };
  const path = `/domains/${encodeURIComponent(name)}/domainStats:query`;

  // Google returns 10 rows when pageSize is unset and may return fewer than
  // asked, so read every page. Stopping early would hide days without saying so.
  const rows = [];
  let nextToken = pageToken || '';
  for (let page = 0; page < MAX_STATS_PAGES; page++) {
    const body = nextToken ? { ...baseBody, pageToken: nextToken } : baseBody;
    const resp = await call('POST', path, body);
    const isSuccess = resp.status >= 200 && resp.status < 300;
    if (!isSuccess) return resp;

    let parsed;
    try {
      parsed = JSON.parse(resp.body);
    } catch (_) {
      throw new Error(`Google returned a response that is not JSON (HTTP ${resp.status}).`);
    }
    rows.push(...(parsed.domainStats || []));

    const followingToken = parsed.nextPageToken || '';
    const isRepeatedToken = Boolean(followingToken) && followingToken === nextToken;
    if (isRepeatedToken) throw new Error('Google returned the same page token twice. Stopped to avoid a loop.');
    nextToken = followingToken;

    if (!nextToken) {
      return { status: resp.status, headers: resp.headers, body: JSON.stringify({ domainStats: rows }) };
    }
  }

  return {
    status: 200,
    headers: {},
    body: JSON.stringify({
      domainStats: rows,
      nextPageToken: nextToken,
      note: `Stopped after ${MAX_STATS_PAGES} pages. Call again with this nextPageToken as pageToken for the rest.`,
    }),
  };
}

module.exports = {
  API_BASE,
  STANDARD_METRICS,
  listDomains,
  getDomain,
  getComplianceStatus,
  queryDomainStats,
};

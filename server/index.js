#!/usr/bin/env node
'use strict';

/*
 * Gmail Postmaster Tools MCP server (stdio transport).
 *
 * Dependency-free MCP over newline-delimited JSON-RPC 2.0. Exposes the Gmail
 * Postmaster Tools API v2 behind a bring-your-own Google OAuth (auth-code +
 * PKCE, 127.0.0.1 loopback) sign-in.
 */

const readline = require('readline');
const auth = require('./auth');
const gpt = require('./gpt');

const SERVER_NAME = 'gmail-postmaster-tools';
const { version: SERVER_VERSION } = require('./package.json');
const PROTOCOL_VERSION = '2025-06-18';
const SUPPORTED_PROTOCOL_VERSIONS = [PROTOCOL_VERSION, '2025-03-26', '2024-11-05'];
const SHUTDOWN_WAIT_MS = 5000;
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };

const TOOLS = [
  {
    name: 'gpt_authenticate',
    description:
      'Sign in to Gmail Postmaster Tools. Opens your browser for a Google account login (OAuth 2.0 authorization-code + PKCE over a 127.0.0.1 loopback) using the Google OAuth client you configured, and caches the tokens. Run this once before fetching data.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'gpt_auth_status',
    description: 'Check whether you are signed in to Gmail Postmaster Tools and when the access token expires.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'gpt_sign_out',
    description: 'Sign out: revoke the Google access and delete the cached tokens.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_domains',
    requiredScope: auth.SCOPE_DOMAIN,
    annotations: READ_ONLY,
    description: 'List the domains registered in your Gmail Postmaster Tools account, with verification state and your permission level. Calls GET /v2/domains.',
    inputSchema: {
      type: 'object',
      properties: {
        pageSize: { type: 'integer', description: 'Optional max number of domains per page (default 10, max 200).' },
        pageToken: { type: 'string', description: 'Optional page token from a previous call.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'get_domain',
    requiredScope: auth.SCOPE_DOMAIN,
    annotations: READ_ONLY,
    description: 'Get metadata for a single registered domain (verification state, permission, timestamps). Calls GET /v2/domains/{domain}.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Fully-qualified domain name, e.g. mail.example.com.' },
      },
      required: ['domain'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_compliance_status',
    requiredScope: auth.SCOPE_TRAFFIC,
    annotations: READ_ONLY,
    description: 'Get the sender compliance status for a domain — verdicts for SPF, DKIM, DMARC, alignment, message formatting, DNS records, encryption, user-reported spam rate, and one-click / honored unsubscribe. Calls GET /v2/domains/{domain}/complianceStatus.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Fully-qualified domain name, e.g. example.com.' },
      },
      required: ['domain'],
      additionalProperties: false,
    },
  },
  {
    name: 'query_domain_stats',
    requiredScope: auth.SCOPE_TRAFFIC,
    annotations: READ_ONLY,
    description:
      'Query Gmail traffic metrics for a domain over a date range, reading every page of results. Metrics: SPAM_RATE; AUTH_SUCCESS_RATE (filter required: auth_type = "spf", "dkim" or "dmarc"); TLS_ENCRYPTION_RATE and TLS_ENCRYPTION_MESSAGE_COUNT (filter required: traffic_direction = "inbound" or "outbound"); DELIVERY_ERROR_RATE and DELIVERY_ERROR_COUNT (optional filter: error_type = "reject" or "temp_fail"); FEEDBACK_LOOP_ID; FEEDBACK_LOOP_SPAM_RATE (filter required: feedback_loop_id = "<id>"). Defaults to SPAM_RATE, daily, for the 7 days ending yesterday. Google returns only dates that have data. Calls POST /v2/domains/{domain}/domainStats:query.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Fully-qualified domain name, e.g. example.com.' },
        start_date: { type: 'string', description: 'Start date yyyy-MM-dd (inclusive). Defaults to 6 days before end_date.' },
        end_date: { type: 'string', description: 'End date yyyy-MM-dd (inclusive). Defaults to yesterday.' },
        granularity: { type: 'string', enum: ['DAILY', 'OVERALL'], description: 'DAILY (per-day) or OVERALL (totals for the period). Default DAILY.' },
        pageToken: { type: 'string', description: 'Only needed if a previous result returned nextPageToken because it stopped early.' },
        metrics: {
          type: 'array',
          description: 'Metrics to fetch. Each item is either a standard metric name (string) or an object { standardMetric, filter, name }. Defaults to ["SPAM_RATE"].',
          items: {
            anyOf: [
              { type: 'string' },
              {
                type: 'object',
                properties: {
                  standardMetric: { type: 'string' },
                  filter: { type: 'string' },
                  name: { type: 'string' },
                },
                required: ['standardMetric'],
                additionalProperties: false,
              },
            ],
          },
        },
      },
      required: ['domain'],
      additionalProperties: false,
    },
  },
];

function availableTools() {
  return TOOLS.filter((tool) => !tool.requiredScope || auth.hasScope(tool.requiredScope));
}

function publicTool({ requiredScope, ...tool }) {
  return tool;
}

function formatResponse(resp, label) {
  const isSuccess = resp.status >= 200 && resp.status < 300;
  if (isSuccess) {
    let parsed;
    try { parsed = JSON.parse(resp.body); } catch (_) { parsed = null; }
    const payload = parsed !== null ? JSON.stringify(parsed, null, 2) : (resp.body || '(empty body)');
    const isEmptyStats = parsed !== null && Array.isArray(parsed.domainStats) && parsed.domainStats.length === 0;
    const note = isEmptyStats ? '\n\nNo data for this range. Google returns only dates that have data.' : '';
    return { text: `${label}: HTTP ${resp.status}\n\n${payload}${note}`, isError: false };
  }
  const body = resp.body || '(empty body)';
  const hints = {
    400: 'Bad Request.',
    403: 'access denied. Common reasons in the body: SERVICE_DISABLED (turn on the Postmaster Tools API in this Google Cloud project), PERMISSION_DENIED (this Google account has no access to the domain), ACCESS_TOKEN_SCOPE_INSUFFICIENT (run gpt_authenticate again).',
    404: 'Not Found. The domain is not registered by this Google account, or there is no data.',
  };
  const hint = hints[resp.status] ? ` — ${hints[resp.status]}` : '';
  return { text: `${label}: HTTP ${resp.status}${hint}\n${body}`.trim(), isError: true };
}

function fmtTime(ms) { try { return new Date(ms).toISOString(); } catch (_) { return String(ms); } }

function validateArguments(tool, args) {
  const isObject = args !== null && typeof args === 'object' && !Array.isArray(args);
  if (!isObject) throw new Error('Tool arguments must be an object.');
  const allowed = Object.keys(tool.inputSchema.properties);
  const unknown = Object.keys(args).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(`Unknown argument: ${unknown.join(', ')}. Allowed: ${allowed.join(', ') || '(none)'}.`);
  }
}

async function callTool(name, args) {
  switch (name) {
    case 'gpt_authenticate': {
      if (!auth.hasCreds()) return auth.SETUP_HELP;
      await auth.interactiveLogin();
      return 'Connected to Gmail Postmaster Tools. You can now query your domains and stats.';
    }
    case 'gpt_auth_status': {
      if (!auth.hasCreds()) return auth.SETUP_HELP;
      const silent = await auth.getAccessTokenSilent();
      if (!silent.ok) return auth.describeSignInProblem(silent);
      const refreshNote = silent.has_refresh_token ? 'auto-refresh enabled' : 'no refresh token, so sign in again when it expires';
      return `Signed in. Access token valid until ${fmtTime(silent.expires_at)} (${refreshNote}). Permissions: ${auth.SCOPE}`;
    }
    case 'gpt_sign_out': {
      const result = await auth.signOut();
      if (!result.hadTokens) return 'No cached tokens to remove.';
      if (result.revoked) return 'Signed out — Google access revoked and cached tokens deleted.';
      const reason = result.revokeError ? ` (${result.revokeError})` : '';
      return {
        text: `Cached tokens deleted, but Google did not confirm the revoke${reason}. Remove access at https://myaccount.google.com/permissions if needed.`,
        isError: true,
      };
    }
    case 'list_domains':
      return formatResponse(await gpt.listDomains(args), 'Registered domains');
    case 'get_domain':
      return formatResponse(await gpt.getDomain(args), `Domain ${args.domain}`);
    case 'get_compliance_status':
      return formatResponse(await gpt.getComplianceStatus(args), `Compliance status for ${args.domain}`);
    case 'query_domain_stats':
      return formatResponse(await gpt.queryDomainStats(args), `Domain stats for ${args.domain}`);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// --- JSON-RPC plumbing ---

function send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }
function sendResult(id, result) { send({ jsonrpc: '2.0', id, result }); }
function sendError(id, code, message) { send({ jsonrpc: '2.0', id, error: { code, message } }); }

async function handleToolCall(id, params) {
  const toolName = params && params.name;
  const tool = availableTools().find((candidate) => candidate.name === toolName);
  if (!tool) {
    sendError(id, -32602, `Unknown tool: ${toolName}`);
    return;
  }
  const args = (params && params.arguments) || {};
  try {
    validateArguments(tool, args);
    const output = await callTool(toolName, args);
    const { text, isError } = typeof output === 'string' ? { text: output, isError: false } : output;
    sendResult(id, { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) });
  } catch (e) {
    sendResult(id, { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true });
  }
}

async function handleMessage(msg) {
  const isValid = msg !== null && typeof msg === 'object' && msg.jsonrpc === '2.0' && typeof msg.method === 'string';
  if (!isValid) {
    const invalidId = msg && msg.id !== undefined ? msg.id : null;
    sendError(invalidId, -32600, 'Invalid request.');
    return;
  }
  const { id, method, params } = msg;
  // A message with no id is a notification, which must never get a response.
  const isRequest = id !== undefined && id !== null;
  if (!isRequest) return;
  try {
    switch (method) {
      case 'initialize': {
        const asked = params && params.protocolVersion;
        const isSupported = SUPPORTED_PROTOCOL_VERSIONS.includes(asked);
        sendResult(id, {
          protocolVersion: isSupported ? asked : PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        });
        return;
      }
      case 'ping':
        sendResult(id, {});
        return;
      case 'tools/list':
        sendResult(id, { tools: availableTools().map(publicTool) });
        return;
      case 'tools/call':
        await handleToolCall(id, params);
        return;
      default:
        sendError(id, -32601, `Method not found: ${method}`);
    }
  } catch (e) {
    sendError(id, -32603, `Internal error: ${e.message}`);
  }
}

const pending = new Set();
function track(promise) {
  pending.add(promise);
  promise.finally(() => pending.delete(promise));
}

process.stdout.on('error', (e) => {
  if (e.code === 'EPIPE') process.exit(0);
});

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const t = line.trim();
  if (!t) return;
  let msg;
  try {
    msg = JSON.parse(t);
  } catch (_) {
    sendError(null, -32700, 'Parse error.');
    return;
  }
  const messages = Array.isArray(msg) ? msg : [msg];
  messages.forEach((one) => track(handleMessage(one)));
});
rl.on('close', () => {
  // A client may close its input and still read answers already asked for, but
  // an open sign-in must not keep a finished process alive.
  const timeout = new Promise((resolve) => setTimeout(resolve, SHUTDOWN_WAIT_MS));
  Promise.race([Promise.allSettled([...pending]), timeout]).then(() => process.exit(0));
});

process.stderr.write(`[Gmail Postmaster MCP] ${SERVER_NAME} v${SERVER_VERSION} ready (creds ${auth.hasCreds() ? 'configured' : 'MISSING'}, permissions: ${auth.SCOPE}).\n`);

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'server', 'index.js');
const PRELOAD = path.join(__dirname, 'preload-mock-https.js');
const TRAFFIC = 'https://www.googleapis.com/auth/postmaster.traffic.readonly';
const DOMAIN = 'https://www.googleapis.com/auth/postmaster.domain';
const CLIENT_SECRET = 'test-client-secret-value';
const ACCESS_TOKEN = 'test-access-token-value';
const REFRESH_TOKEN = 'test-refresh-token-value';
const TEST_TIMEOUT_MS = 20000;

function startMock() {
  const mock = { requests: [], routes: {} };
  mock.server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks).toString();
      const pathname = req.url.split('?')[0];
      const record = { method: req.method, url: req.url, pathname, headers: req.headers, raw };
      mock.requests.push(record);
      const route = mock.routes[pathname] || mock.routes['*'];
      if (route) {
        await route(req, res, record);
        return;
      }
      res.writeHead(500);
      res.end('{}');
    });
  });
  return new Promise((resolve) => mock.server.listen(0, '127.0.0.1', () => {
    mock.port = mock.server.address().port;
    resolve(mock);
  }));
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function startServer(mock, env = {}) {
  const tokenDir = env.GPT_TOKEN_DIR || path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-test-')), 'tokens');
  const emptyBin = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-bin-'));
  const child = spawn(process.execPath, [SERVER], {
    env: {
      // An empty PATH means no real browser opens, and the launch failure
      // itself is under test.
      PATH: emptyBin,
      HOME: path.dirname(tokenDir),
      NODE_OPTIONS: `--require ${PRELOAD}`,
      GPT_TEST_MOCK_PORT: String(mock.port),
      GPT_CLIENT_ID: 'test-client-id',
      GPT_CLIENT_SECRET: CLIENT_SECRET,
      GPT_TOKEN_DIR: tokenDir,
      ...env,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const srv = { child, tokenDir, stderr: '', exited: null, waiting: new Map(), untagged: [], nextId: 1 };
  srv.exit = new Promise((resolve) => child.on('exit', (code, signal) => {
    srv.exited = { code, signal };
    resolve(srv.exited);
  }));
  child.stderr.on('data', (d) => { srv.stderr += d; });

  let buffer = '';
  child.stdout.on('data', (d) => {
    buffer += d;
    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const msg = JSON.parse(buffer.slice(0, idx));
      buffer = buffer.slice(idx + 1);
      const waiter = srv.waiting.get(msg.id);
      if (waiter) {
        srv.waiting.delete(msg.id);
        waiter(msg);
      } else {
        srv.untagged.push(msg);
      }
    }
  });

  srv.rpc = (method, params) => {
    const id = srv.nextId++;
    const answer = new Promise((resolve) => srv.waiting.set(id, resolve));
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    return answer;
  };
  srv.tool = (name, args = {}) => srv.rpc('tools/call', { name, arguments: args });
  srv.stop = () => {
    if (!srv.exited) child.kill('SIGKILL');
    return srv.exit;
  };
  return srv;
}

function seedTokens(srv, overrides = {}) {
  fs.mkdirSync(srv.tokenDir, { recursive: true });
  fs.writeFileSync(path.join(srv.tokenDir, 'tokens.json'), JSON.stringify({
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    expires_at: Date.now() + 3600000,
    scope: TRAFFIC,
    requested_scope: TRAFFIC,
    ...overrides,
  }));
}

async function waitFor(check, label) {
  for (let i = 0; i < 200; i++) {
    const value = check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function loginUrl(srv) {
  const match = await waitFor(() => /https:\/\/accounts\.google\.com\/\S+/.exec(srv.stderr), 'sign-in URL');
  return new URL(match[0]);
}

function text(answer) {
  return answer.result.content[0].text;
}

function withServer(name, env, body) {
  test(name, { timeout: TEST_TIMEOUT_MS }, async () => {
    const mock = await startMock();
    const srv = startServer(mock, env);
    try {
      await body(srv, mock);
    } finally {
      await srv.stop();
      await new Promise((resolve) => {
        mock.server.close(resolve);
        mock.server.closeAllConnections();
      });
    }
  });
}

function statsRequests(mock) {
  return mock.requests.filter((r) => r.pathname.endsWith('domainStats:query'));
}

// --- protocol ---

withServer('initialize returns a supported protocol version', {}, async (srv) => {
  const known = await srv.rpc('initialize', { protocolVersion: '2025-03-26' });
  assert.equal(known.result.protocolVersion, '2025-03-26');
  const unknown = await srv.rpc('initialize', { protocolVersion: '1999-01-01' });
  assert.equal(unknown.result.protocolVersion, '2025-06-18');
});

withServer('bad JSON gets a parse error and the server keeps working', {}, async (srv) => {
  srv.child.stdin.write('{not json\n');
  const parseError = await waitFor(() => srv.untagged.find((m) => m.error), 'parse error');
  assert.equal(parseError.error.code, -32700);
  assert.ok((await srv.rpc('ping')).result);
});

withServer('an unknown tool is a protocol error', {}, async (srv) => {
  const answer = await srv.tool('nope');
  assert.equal(answer.error.code, -32602);
});

withServer('a notification gets no response', {}, async (srv) => {
  srv.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'tools/list' }) + '\n');
  assert.ok((await srv.rpc('ping')).result);
  assert.deepEqual(srv.untagged, []);
});

withServer('an answer in progress is still sent after input closes', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res) => setTimeout(() => json(res, 200, { domainStats: [] }), 150);
  const answer = srv.tool('query_domain_stats', { domain: 'example.com' });
  srv.child.stdin.end();
  assert.equal((await answer).result.isError, undefined);
  assert.equal((await srv.exit).code, 0);
});

withServer('unknown arguments are rejected', {}, async (srv, mock) => {
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com', extra: 1 });
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /Unknown argument: extra/);
  assert.equal(mock.requests.length, 0);
});

test('version matches in server and manifest', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'server', 'package.json'), 'utf8'));
  assert.equal(pkg.version, manifest.version);
});

// --- scopes and endpoints ---

withServer('default permissions are traffic read-only, and domain tools are hidden', {}, async (srv) => {
  const names = (await srv.rpc('tools/list')).result.tools.map((t) => t.name);
  assert.ok(names.includes('get_compliance_status'));
  assert.ok(names.includes('query_domain_stats'));
  assert.ok(!names.includes('list_domains'));
  assert.ok(!names.includes('get_domain'));
  srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  assert.equal(url.searchParams.get('scope'), TRAFFIC);
});

withServer('domain tools appear only when GPT_SCOPE asks for them', { GPT_SCOPE: `${TRAFFIC} ${DOMAIN}` }, async (srv) => {
  const tools = (await srv.rpc('tools/list')).result.tools;
  const names = tools.map((t) => t.name);
  assert.ok(names.includes('list_domains'));
  assert.ok(tools.every((t) => t.requiredScope === undefined));
});

for (const scope of ['https://www.googleapis.com/auth/postmaster', 'https://www.googleapis.com/auth/postmaster.user']) {
  test(`refuses to start with scope ${scope}`, { timeout: TEST_TIMEOUT_MS }, async () => {
    const mock = await startMock();
    const srv = startServer(mock, { GPT_SCOPE: scope });
    const { code } = await srv.exit;
    mock.server.close();
    assert.notEqual(code, 0);
    assert.match(srv.stderr, /does not allow/);
  });
}

withServer('environment settings cannot send tokens to another host', {
  GPT_API_BASE: 'https://evil.example/v2',
  GPT_TOKEN_URL: 'https://evil.example/token',
}, async (srv, mock) => {
  seedTokens(srv, { expires_at: 0 });
  mock.routes['/token'] = (req, res) => json(res, 200, { access_token: ACCESS_TOKEN, expires_in: 3600 });
  mock.routes['*'] = (req, res) => json(res, 200, {});
  await srv.tool('get_compliance_status', { domain: 'example.com' });
  const hosts = new Set(mock.requests.map((r) => r.headers['x-original-host']));
  assert.deepEqual([...hosts].sort(), ['gmailpostmastertools.googleapis.com', 'oauth2.googleapis.com']);
});

// --- sign-in ---

withServer('sign-in works end to end, with private files and no secrets in logs', {}, async (srv, mock) => {
  mock.routes['/token'] = (req, res) => json(res, 200, {
    access_token: ACCESS_TOKEN, refresh_token: REFRESH_TOKEN, expires_in: 3600, scope: TRAFFIC,
  });
  const answer = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);

  const page = await fetch(`${url.searchParams.get('redirect_uri')}/?code=the-code&state=${url.searchParams.get('state')}`);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('cache-control'), 'no-store');
  assert.match(text(await answer), /Connected/);

  const exchange = new URLSearchParams(mock.requests.find((r) => r.pathname === '/token').raw);
  const challenge = crypto.createHash('sha256').update(exchange.get('code_verifier')).digest('base64url');
  assert.equal(challenge, url.searchParams.get('code_challenge'));
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');

  const tokenFile = path.join(srv.tokenDir, 'tokens.json');
  assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600);
  assert.equal(fs.statSync(srv.tokenDir).mode & 0o777, 0o700);
  assert.deepEqual(fs.readdirSync(srv.tokenDir), ['tokens.json']);

  const status = text(await srv.tool('gpt_auth_status'));
  assert.match(status, /Signed in/);
  for (const secret of [CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN]) {
    assert.ok(!srv.stderr.includes(secret), 'secret in stderr');
    assert.ok(!status.includes(secret), 'secret in tool output');
  }
});

withServer('a request with the wrong state does not end the sign-in', {}, async (srv, mock) => {
  mock.routes['/token'] = (req, res) => json(res, 200, { access_token: ACCESS_TOKEN, expires_in: 3600, scope: TRAFFIC });
  const answer = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  const base = url.searchParams.get('redirect_uri');

  assert.equal((await fetch(`${base}/?code=attacker&state=wrong`)).status, 400);
  assert.equal((await fetch(`${base}/?error=access_denied`)).status, 400);
  assert.equal(mock.requests.length, 0, 'bad requests must not reach Google');

  await fetch(`${base}/?code=real&state=${url.searchParams.get('state')}`);
  assert.match(text(await answer), /Connected/);
});

withServer('the callback page escapes what it shows', {}, async (srv) => {
  const answer = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  const attack = encodeURIComponent('<script>alert(1)</script>');
  const page = await fetch(`${url.searchParams.get('redirect_uri')}/?error=${attack}&state=${url.searchParams.get('state')}`);
  const html = await page.text();
  assert.ok(!html.includes('<script>'));
  assert.match(html, /&lt;script&gt;/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal((await answer).result.isError, true);
});

withServer('a malformed request to the callback does not crash the server', {}, async (srv) => {
  srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  const { port } = new URL(url.searchParams.get('redirect_uri'));
  await new Promise((resolve, reject) => {
    const socket = net.connect(Number(port), '127.0.0.1', () => socket.write('GET // HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
    socket.on('data', () => {});
    socket.on('close', resolve);
    socket.on('error', reject);
  });
  assert.ok((await srv.rpc('ping')).result);
  assert.equal(srv.exited, null);
});

withServer('a missing browser command does not crash the server', {}, async (srv) => {
  srv.tool('gpt_authenticate');
  await loginUrl(srv);
  await new Promise((r) => setTimeout(r, 200));
  assert.ok((await srv.rpc('ping')).result);
  assert.equal(srv.exited, null);
});

withServer('a repeat sign-in call joins the one already open', {}, async (srv, mock) => {
  mock.routes['/token'] = (req, res) => json(res, 200, { access_token: ACCESS_TOKEN, expires_in: 3600, scope: TRAFFIC });
  const first = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  const second = srv.tool('gpt_authenticate');
  await srv.rpc('ping');
  assert.equal(srv.stderr.match(/accounts\.google\.com/g).length, 1);
  await fetch(`${url.searchParams.get('redirect_uri')}/?code=c&state=${url.searchParams.get('state')}`);
  assert.match(text(await first), /Connected/);
  assert.match(text(await second), /Connected/);
});

withServer('sign-in fails when the permission box was unticked', {}, async (srv, mock) => {
  mock.routes['/token'] = (req, res) => json(res, 200, { access_token: ACCESS_TOKEN, expires_in: 3600, scope: 'openid' });
  const answer = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  await fetch(`${url.searchParams.get('redirect_uri')}/?code=c&state=${url.searchParams.get('state')}`);
  const result = await answer;
  assert.equal(result.result.isError, true);
  assert.match(text(result), /did not grant/);
  assert.ok(!fs.existsSync(path.join(srv.tokenDir, 'tokens.json')));
});

withServer('a token response without a token fails', {}, async (srv, mock) => {
  mock.routes['/token'] = (req, res) => json(res, 200, { scope: TRAFFIC });
  const answer = srv.tool('gpt_authenticate');
  const url = await loginUrl(srv);
  await fetch(`${url.searchParams.get('redirect_uri')}/?code=c&state=${url.searchParams.get('state')}`);
  assert.equal((await answer).result.isError, true);
  assert.ok(!fs.existsSync(path.join(srv.tokenDir, 'tokens.json')));
});

// --- tokens ---

withServer('a token saved with other permissions is not reused', {}, async (srv, mock) => {
  seedTokens(srv, { requested_scope: `${DOMAIN} ${TRAFFIC}` });
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /different permissions/);
  assert.equal(mock.requests.length, 0);
});

withServer('a 401 tries one refresh, then retries the request', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['/token'] = (req, res) => json(res, 200, { access_token: 'new-token', expires_in: 3600 });
  mock.routes['*'] = (req, res) => {
    const isNew = req.headers.authorization === 'Bearer new-token';
    json(res, isNew ? 200 : 401, {});
  };
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.equal(answer.result.isError, undefined);
  assert.equal(mock.requests.filter((r) => r.pathname === '/token').length, 1);
});

withServer('a failed refresh says why', {}, async (srv, mock) => {
  seedTokens(srv, { expires_at: 0 });
  mock.routes['/token'] = (req, res) => json(res, 400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /invalid_grant/);
  assert.match(text(answer), /gpt_authenticate/);
});

withServer('a token endpoint that never answers times out', { GPT_REQUEST_TIMEOUT_MS: '200' }, async (srv, mock) => {
  seedTokens(srv, { expires_at: 0 });
  mock.routes['/token'] = () => {};
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /timed out/);
});

withServer('sign-out revokes at Google and deletes the file', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['/revoke'] = (req, res) => json(res, 200, {});
  assert.match(text(await srv.tool('gpt_sign_out')), /revoked/);
  const revoke = mock.requests.find((r) => r.pathname === '/revoke');
  assert.equal(new URLSearchParams(revoke.raw).get('token'), REFRESH_TOKEN);
  assert.ok(!fs.existsSync(path.join(srv.tokenDir, 'tokens.json')));
});

withServer('sign-out reports a failed revoke', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['/revoke'] = (req, res) => json(res, 503, {});
  const answer = await srv.tool('gpt_sign_out');
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /did not confirm/);
  assert.ok(!fs.existsSync(path.join(srv.tokenDir, 'tokens.json')));
});

// --- API calls ---

withServer('all pages of stats are returned, at the largest page size', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res, record) => {
    const { pageToken } = JSON.parse(record.raw);
    const pages = {
      undefined: { domainStats: [{ metric: 'a', date: 1 }], nextPageToken: 'p2' },
      p2: { domainStats: [{ metric: 'a', date: 2 }], nextPageToken: 'p3' },
      p3: { domainStats: [{ metric: 'a', date: 3 }] },
    };
    json(res, 200, pages[pageToken]);
  };
  const answer = await srv.tool('query_domain_stats', { domain: 'example.com', start_date: '2026-10-01', end_date: '2026-10-31' });
  const rows = JSON.parse(text(answer).split('\n\n')[1]).domainStats;
  assert.deepEqual(rows.map((r) => r.date), [1, 2, 3]);

  const body = JSON.parse(statsRequests(mock)[0].raw);
  assert.equal(body.pageSize, 200);
  assert.equal(statsRequests(mock)[0].pathname, '/v2/domains/example.com/domainStats:query');
  assert.deepEqual(body.timeQuery.dateRanges.dateRanges[0], {
    start: { year: 2026, month: 10, day: 1 },
    end: { year: 2026, month: 10, day: 31 },
  });
  assert.deepEqual(body.metricDefinitions, [{ name: 'SPAM_RATE_0', baseMetric: { standardMetric: 'SPAM_RATE' } }]);
  assert.equal(body.aggregationGranularity, 'DAILY');
});

withServer('a page token loop stops instead of running forever', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res) => json(res, 200, { domainStats: [], nextPageToken: 'same' });
  const answer = await srv.tool('query_domain_stats', { domain: 'example.com' });
  assert.equal(answer.result.isError, true);
  assert.equal(statsRequests(mock).length, 2);
});

withServer('dates that do not exist or are out of order never reach Google', {}, async (srv, mock) => {
  seedTokens(srv);
  const fake = await srv.tool('query_domain_stats', { domain: 'example.com', start_date: '2026-02-31', end_date: '2026-03-01' });
  assert.match(text(fake), /does not exist/);
  const reversed = await srv.tool('query_domain_stats', { domain: 'example.com', start_date: '2026-03-02', end_date: '2026-03-01' });
  assert.match(text(reversed), /is after/);
  assert.equal(mock.requests.length, 0);
});

withServer('an end date alone gives the 7 days ending on it', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res) => json(res, 200, {});
  await srv.tool('query_domain_stats', { domain: 'example.com', end_date: '2026-01-03' });
  const range = JSON.parse(statsRequests(mock)[0].raw).timeQuery.dateRanges.dateRanges[0];
  assert.deepEqual(range.start, { year: 2025, month: 12, day: 28 });
  assert.deepEqual(range.end, { year: 2026, month: 1, day: 3 });
});

withServer('metrics needing a filter are checked before calling Google', {}, async (srv, mock) => {
  seedTokens(srv);
  const missing = await srv.tool('query_domain_stats', { domain: 'example.com', metrics: ['AUTH_SUCCESS_RATE'] });
  assert.match(text(missing), /needs a filter/);
  assert.equal(mock.requests.length, 0);

  mock.routes['*'] = (req, res) => json(res, 200, { domainStats: [] });
  const filter = 'auth_type = "dkim"';
  await srv.tool('query_domain_stats', { domain: 'example.com', metrics: [{ standardMetric: 'AUTH_SUCCESS_RATE', filter }] });
  assert.equal(JSON.parse(statsRequests(mock)[0].raw).metricDefinitions[0].filter, filter);
});

withServer('bad metric entries give a clear error', {}, async (srv) => {
  seedTokens(srv);
  for (const metrics of [[null], [7], ['NOPE'], [{ standardMetric: 'SPAM_RATE', filter: 5 }]]) {
    const answer = await srv.tool('query_domain_stats', { domain: 'example.com', metrics });
    assert.equal(answer.result.isError, true);
    assert.doesNotMatch(text(answer), /Cannot read/);
  }
});

withServer('bad domains never reach Google', {}, async (srv, mock) => {
  seedTokens(srv);
  for (const domain of ['../../v2/domains', 'a b.com', ['example.com'], 'localhost', '-bad.example.com', 'example.com/x']) {
    const answer = await srv.tool('get_compliance_status', { domain });
    assert.equal(answer.result.isError, true);
    assert.match(text(answer), /Invalid domain/);
  }
  assert.equal(mock.requests.length, 0);
});

for (const status of [400, 403, 404, 500]) {
  withServer(`HTTP ${status} from Google is marked as an error`, {}, async (srv, mock) => {
    seedTokens(srv);
    mock.routes['*'] = (req, res) => json(res, status, { error: { message: 'nope' } });
    const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
    assert.equal(answer.result.isError, true);
    assert.match(text(answer), new RegExp(`HTTP ${status}`));
  });
}

withServer('empty results explain themselves', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res) => json(res, 200, {});
  const answer = await srv.tool('query_domain_stats', { domain: 'example.com' });
  assert.equal(answer.result.isError, undefined);
  assert.match(text(answer), /only dates that have data/);
});

withServer('characters split across network chunks stay intact', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = async (req, res) => {
    const payload = Buffer.from(JSON.stringify({ name: 'é€' }));
    res.writeHead(200);
    const cut = payload.indexOf(0xc3) + 1;
    res.write(payload.subarray(0, cut));
    await new Promise((r) => setTimeout(r, 30));
    res.end(payload.subarray(cut));
  };
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.match(text(answer), /é€/);
});

withServer('an oversized response is refused', {}, async (srv, mock) => {
  seedTokens(srv);
  mock.routes['*'] = (req, res) => {
    res.writeHead(200);
    res.write(Buffer.alloc(11 * 1024 * 1024, 0x61));
    res.end();
  };
  const answer = await srv.tool('get_compliance_status', { domain: 'example.com' });
  assert.equal(answer.result.isError, true);
  assert.match(text(answer), /larger than/);
});

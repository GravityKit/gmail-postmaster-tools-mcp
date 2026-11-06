'use strict';

// Calls Google's real endpoints with made-up credentials, so it needs no
// account and reads no data. Run with: npm run test:live
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const SERVER = path.join(__dirname, '..', 'server', 'index.js');
const TRAFFIC = 'https://www.googleapis.com/auth/postmaster.traffic.readonly';
const DISCOVERY = 'https://gmailpostmastertools.googleapis.com/$discovery/rest?version=v2';
const TIMEOUT_MS = 60000;

function callServerTool(tokens, name, args) {
  const tokenDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpt-live-'));
  fs.writeFileSync(path.join(tokenDir, 'tokens.json'), JSON.stringify({ scope: TRAFFIC, requested_scope: TRAFFIC, ...tokens }));
  const child = spawn(process.execPath, [SERVER], {
    env: {
      PATH: process.env.PATH,
      GPT_CLIENT_ID: 'made-up-client.apps.googleusercontent.com',
      GPT_CLIENT_SECRET: 'made-up-secret',
      GPT_TOKEN_DIR: tokenDir,
    },
    stdio: ['pipe', 'pipe', 'inherit'],
  });
  return new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('error', reject);
    child.on('exit', () => resolve({ answer: JSON.parse(out.trim().split('\n').pop()), tokenDir }));
    child.stdin.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) + '\n');
  });
}

test('the code matches Google\'s published API definition', { timeout: TIMEOUT_MS }, async () => {
  const discovery = await (await fetch(DISCOVERY)).json();
  const { STANDARD_METRICS } = require('../server/gpt');

  const published = discovery.schemas.BaseMetric.properties.standardMetric.enum
    .filter((value) => value !== 'STANDARD_METRIC_UNSPECIFIED');
  assert.deepEqual([...STANDARD_METRICS].sort(), [...published].sort());

  const { domains } = discovery.resources;
  const statsMethod = domains.resources.domainStats.methods.query;
  assert.equal(statsMethod.httpMethod, 'POST');
  assert.equal(statsMethod.path, 'v2/{+parent}/domainStats:query');
  assert.ok(statsMethod.scopes.includes(TRAFFIC));
  assert.ok(domains.methods.getComplianceStatus.scopes.includes(TRAFFIC));

  const request = discovery.schemas.QueryDomainStatsRequest.properties;
  for (const field of ['metricDefinitions', 'aggregationGranularity', 'pageSize', 'pageToken', 'timeQuery']) {
    assert.ok(request[field], `${field} is in the published request`);
  }
});

test('Google rejects a made-up access token and the server reports it', { timeout: TIMEOUT_MS }, async () => {
  const { answer } = await callServerTool(
    { access_token: 'made-up-token', expires_at: Date.now() + 3600000 },
    'get_compliance_status',
    { domain: 'gravitykit.com' }
  );
  assert.equal(answer.result.isError, true);
  assert.match(answer.result.content[0].text, /gpt_authenticate/);
});

test('Google rejects a made-up client and the server says why', { timeout: TIMEOUT_MS }, async () => {
  const { answer } = await callServerTool(
    { access_token: 'x', refresh_token: 'made-up-refresh', expires_at: 0 },
    'get_compliance_status',
    { domain: 'gravitykit.com' }
  );
  assert.equal(answer.result.isError, true);
  assert.match(answer.result.content[0].text, /invalid_client/);
  assert.doesNotMatch(answer.result.content[0].text, /made-up-secret|made-up-refresh/);
});

test('sign-out reports when Google refuses to revoke, and still deletes the file', { timeout: TIMEOUT_MS }, async () => {
  const { answer, tokenDir } = await callServerTool(
    { access_token: 'x', refresh_token: 'made-up-refresh', expires_at: 0 },
    'gpt_sign_out',
    {}
  );
  assert.equal(answer.result.isError, true);
  assert.match(answer.result.content[0].text, /did not confirm/);
  assert.ok(!fs.existsSync(path.join(tokenDir, 'tokens.json')));
});

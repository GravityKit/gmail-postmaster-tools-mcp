'use strict';

/*
 * Google requires a client secret even for desktop apps; PKCE alone is rejected.
 * The endpoints stay constants: an environment override could send the client
 * secret and refresh token to another host.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { URL, URLSearchParams } = require('url');
const { httpsRequest, positiveIntEnv } = require('./http-client');

const CLIENT_ID = (process.env.GPT_CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.GPT_CLIENT_SECRET || '').trim();

const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';

const SCOPE_TRAFFIC = 'https://www.googleapis.com/auth/postmaster.traffic.readonly';
// Google describes this scope as "View and manage": it also allows creating,
// verifying and deleting domains. It stays off unless GPT_SCOPE asks for it.
const SCOPE_DOMAIN = 'https://www.googleapis.com/auth/postmaster.domain';
const ALLOWED_SCOPES = [SCOPE_TRAFFIC, SCOPE_DOMAIN];

function resolveScopes(raw) {
  // An MCP host may pass an unset optional setting as its literal placeholder.
  const isUnresolvedPlaceholder = /^\$\{user_config\.[^}]*\}$/.test(raw || '');
  const requested = (isUnresolvedPlaceholder || !raw ? SCOPE_TRAFFIC : raw).split(/\s+/).filter(Boolean);
  const rejected = requested.filter((scope) => !ALLOWED_SCOPES.includes(scope));
  if (rejected.length > 0 || requested.length === 0) {
    throw new Error(
      `GPT_SCOPE contains a scope this server does not allow: ${rejected.join(' ') || '(empty)'}. ` +
      `Allowed: ${ALLOWED_SCOPES.join(' ')}`
    );
  }
  return [...new Set(requested)].sort();
}

const SCOPES = resolveScopes(process.env.GPT_SCOPE);
const SCOPE = SCOPES.join(' ');

const DEFAULT_TOKEN_DIR = path.join(os.homedir(), '.gmail-postmaster-mcp');
const TOKEN_DIR = (process.env.GPT_TOKEN_DIR || '').trim() || DEFAULT_TOKEN_DIR;
const TOKEN_PATH = path.join(TOKEN_DIR, 'tokens.json');

const LOGIN_TIMEOUT_MS = positiveIntEnv('GPT_LOGIN_TIMEOUT_MS', 180000);
const TOKEN_ERROR_MAX_CHARS = 300;

const SETUP_HELP =
  'Google OAuth credentials are not configured. Create an OAuth client of type ' +
  '"Desktop app" in Google Cloud Console (APIs & Services > Credentials), enable ' +
  'the "Gmail Postmaster Tools API", then set the Client ID and Client Secret in ' +
  'this extension\'s configuration. See the README for step-by-step instructions.';

function requireCreds() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    const e = new Error(SETUP_HELP);
    e.code = 'NO_CREDS';
    throw e;
  }
}

function hasScope(scope) {
  return SCOPES.includes(scope);
}

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function loadCache() {
  try {
    const parsed = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
    const isObject = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed);
    return isObject ? parsed : null;
  } catch (_) {
    return null;
  }
}

function saveCache(obj) {
  const created = fs.mkdirSync(TOKEN_DIR, { recursive: true, mode: 0o700 });
  // Leave the permissions of a folder the user chose and already had alone.
  const ownsDir = Boolean(created) || TOKEN_DIR === DEFAULT_TOKEN_DIR;
  if (ownsDir) {
    try { fs.chmodSync(TOKEN_DIR, 0o700); } catch (_) { /* best effort, e.g. on Windows */ }
  }

  // Write then rename, so the file is never briefly readable and a crash
  // cannot leave half a token file. Rename also replaces a planted symlink.
  const tmpPath = `${TOKEN_PATH}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(obj, null, 2), { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmpPath, TOKEN_PATH);
  } catch (e) {
    try { fs.unlinkSync(tmpPath); } catch (_) { /* nothing to clean up */ }
    throw e;
  }
}

function clearCache() {
  try {
    fs.unlinkSync(TOKEN_PATH);
    return true;
  } catch (e) {
    if (e.code === 'ENOENT') return false;
    throw e;
  }
}

async function postForm(urlStr, form) {
  const body = new URLSearchParams(form).toString();
  const resp = await httpsRequest({
    method: 'POST',
    url: urlStr,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
      Accept: 'application/json',
    },
    body,
  });

  let json = {};
  try { json = JSON.parse(resp.body) || {}; } catch (_) { /* reported by status below */ }

  const isSuccess = resp.status >= 200 && resp.status < 300;
  if (isSuccess) return json;

  // Only Google's two error fields: never echo an arbitrary response body.
  const detail = `${json.error || ''} ${json.error_description || ''}`.trim().slice(0, TOKEN_ERROR_MAX_CHARS);
  const e = new Error(`Token endpoint HTTP ${resp.status}${detail ? `: ${detail}` : ''}`);
  e.oauthError = json.error;
  throw e;
}

function storeTokenResponse(tok, prev) {
  const hasAccessToken = typeof tok.access_token === 'string' && tok.access_token.length > 0;
  if (!hasAccessToken) {
    throw new Error('Google\'s token response did not include an access token.');
  }
  const expiresInSeconds = Number(tok.expires_in);
  const hasExpiry = Number.isFinite(expiresInSeconds) && expiresInSeconds > 0;
  const now = Date.now();
  const rec = {
    access_token: tok.access_token,
    expires_at: now + ((hasExpiry ? expiresInSeconds : 3600) * 1000),
    // Google only returns refresh_token on the first consent; keep the old one otherwise.
    refresh_token: tok.refresh_token || (prev && prev.refresh_token) || null,
    scope: tok.scope || SCOPE,
    requested_scope: SCOPE,
    obtained_at: now,
  };
  saveCache(rec);
  return rec;
}

function htmlPage(title, message) {
  const safeTitle = escapeHtml(title);
  return `<!doctype html><html><head><meta charset="utf-8"><title>${safeTitle}</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f5f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border-radius:10px;box-shadow:0 2px 16px rgba(0,0,0,.12);padding:36px 44px;max-width:460px;text-align:center}
h1{font-size:20px;margin:0 0 12px;color:#1a73e8}p{font-size:14px;color:#333;line-height:1.5;margin:0}</style></head>
<body><div class="card"><h1>${safeTitle}</h1><p>${escapeHtml(message)}</p></div></body></html>`;
}

function openBrowser(url) {
  let command = 'xdg-open';
  let args = [url];
  if (process.platform === 'darwin') {
    command = 'open';
  } else if (process.platform === 'win32') {
    // Avoid `cmd /c start` — it truncates URLs at `&`.
    command = 'rundll32';
    args = ['url.dll,FileProtocolHandler', url];
  }
  try {
    const child = spawn(command, args, { stdio: 'ignore', detached: true });
    // A missing command arrives as an 'error' event, not a throw. Unhandled, it
    // would end the whole server. The URL is printed to stderr as the fallback.
    child.on('error', () => {});
    child.unref();
  } catch (_) { /* URL is printed to stderr as a fallback */ }
}

function runInteractiveLogin() {
  requireCreds();
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(32));

  return new Promise((resolve, reject) => {
    let redirectUri;
    let settled = false;
    let exchanging = false;
    const server = http.createServer();

    const done = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        server.close();
        if (server.closeIdleConnections) server.closeIdleConnections();
      } catch (_) { /* already closed */ }
      fn();
    };

    const timer = setTimeout(() => {
      done(() => reject(new Error(`Sign-in timed out after ${Math.round(LOGIN_TIMEOUT_MS / 1000)}s. Run gpt_authenticate again.`)));
    }, LOGIN_TIMEOUT_MS);

    const reply = (res, status, title, message) => {
      res.writeHead(status, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
        Connection: 'close',
      });
      res.end(htmlPage(title, message));
    };

    server.on('request', (req, res) => {
      let requestUrl;
      try {
        requestUrl = new URL(req.url, 'http://127.0.0.1');
      } catch (_) {
        reply(res, 400, 'Bad request', 'This address is not valid.');
        return;
      }

      const code = requestUrl.searchParams.get('code');
      const err = requestUrl.searchParams.get('error');
      const isCallback = req.method === 'GET' && requestUrl.pathname === '/' && Boolean(code || err);
      if (!isCallback) {
        reply(res, 404, 'Not found', 'Nothing here.');
        return;
      }

      // Check state before anything else, and keep waiting when it is wrong.
      // Any local process or web page can reach this port, so a bad request
      // must not be able to end the sign-in or show content.
      const hasValidState = safeEqual(requestUrl.searchParams.get('state') || '', state);
      if (!hasValidState) {
        reply(res, 400, 'Sign-in not completed', 'This request did not come from the sign-in you started. You can close this tab.');
        return;
      }

      if (err) {
        reply(res, 200, 'Sign-in failed', err);
        done(() => reject(new Error(`Authorization error: ${err}`)));
        return;
      }

      if (exchanging) {
        reply(res, 409, 'Sign-in in progress', 'Sign-in is already being completed. You can close this tab.');
        return;
      }
      exchanging = true;

      postForm(TOKEN_URL, {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: verifier,
      }).then((tok) => {
        const granted = String(tok.scope || SCOPE).split(/\s+/);
        const missing = SCOPES.filter((scope) => !granted.includes(scope));
        if (missing.length > 0) {
          throw new Error(`Google sign-in did not grant the permission this server needs: ${missing.join(' ')}. Run gpt_authenticate again and leave that box ticked.`);
        }
        const rec = storeTokenResponse(tok, loadCache());
        reply(res, 200, 'Connected to Gmail Postmaster Tools', 'You\'re authenticated. You can close this tab and return to your assistant.');
        done(() => resolve(rec));
      }).catch((e) => {
        reply(res, 200, 'Sign-in failed', e.message);
        done(() => reject(e));
      });
    });

    server.on('error', (e) => done(() => reject(e)));

    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      redirectUri = `http://127.0.0.1:${port}`;
      const authUrl = `${AUTHORIZE_URL}?` + new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: SCOPE,
        access_type: 'offline',     // request a refresh token
        prompt: 'consent',          // ensure refresh token is returned
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      }).toString();
      process.stderr.write(`\n[Gmail Postmaster MCP] Opening your browser to sign in. If it does not open, paste this URL:\n${authUrl}\n\n`);
      openBrowser(authUrl);
    });
  });
}

// A client that times out and retries joins the sign-in already open, so the
// person never gets a second tab or a port that has already closed.
let loginInFlight = null;
function interactiveLogin() {
  if (!loginInFlight) {
    loginInFlight = runInteractiveLogin().finally(() => { loginInFlight = null; });
  }
  return loginInFlight;
}

let refreshInFlight = null;
function refreshAccessToken(cache) {
  if (!refreshInFlight) {
    refreshInFlight = postForm(TOKEN_URL, {
      grant_type: 'refresh_token',
      refresh_token: cache.refresh_token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }).then((tok) => storeTokenResponse(tok, cache))
      .finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

async function getAccessTokenSilent({ forceRefresh = false } = {}) {
  const cache = loadCache();
  if (!cache) return { ok: false, reason: 'no_cache' };

  // A token granted for different permissions than this configuration asks
  // for must not be reused, wider or narrower.
  if (cache.requested_scope !== SCOPE) return { ok: false, reason: 'scope_changed' };

  const hasRefreshToken = Boolean(cache.refresh_token);
  const isFresh = Boolean(cache.access_token) && Date.now() < Number(cache.expires_at) - 60000;
  if (isFresh && !forceRefresh) {
    return { ok: true, token: cache.access_token, expires_at: cache.expires_at, has_refresh_token: hasRefreshToken };
  }
  if (hasRefreshToken) {
    try {
      requireCreds();
      const rec = await refreshAccessToken(cache);
      return { ok: true, token: rec.access_token, expires_at: rec.expires_at, has_refresh_token: true };
    } catch (e) {
      return { ok: false, reason: 'refresh_failed', error: e.message };
    }
  }
  return { ok: false, reason: 'expired_no_refresh' };
}

function describeSignInProblem(silent) {
  switch (silent.reason) {
    case 'no_cache':
      return 'Not signed in to Gmail Postmaster Tools. Run the "gpt_authenticate" tool first.';
    case 'scope_changed':
      return 'The saved sign-in was made with different permissions than this server is set to use. Run the "gpt_authenticate" tool again.';
    case 'refresh_failed':
      return `Google no longer accepts the saved sign-in (${silent.error}). Run the "gpt_authenticate" tool again. If this happens weekly, see "Token lifetime" in the README.`;
    default:
      return 'The saved sign-in has expired. Run the "gpt_authenticate" tool again.';
  }
}

async function getAccessToken({ forceRefresh = false } = {}) {
  const silent = await getAccessTokenSilent({ forceRefresh });
  if (silent.ok) return silent.token;
  const e = new Error(describeSignInProblem(silent));
  e.code = 'NEED_AUTH';
  throw e;
}

// Sign-out should end access at Google as well as remove the local copy.
// Revoking either token ends the whole grant.
async function signOut() {
  const cache = loadCache();
  if (!cache) {
    clearCache();
    return { hadTokens: false, revoked: false };
  }
  let revoked = false;
  let revokeError = null;
  const token = cache.refresh_token || cache.access_token;
  if (token) {
    try {
      await postForm(REVOKE_URL, { token });
      revoked = true;
    } catch (e) {
      revokeError = e.message;
    }
  }
  clearCache();
  return { hadTokens: true, revoked, revokeError };
}

module.exports = {
  hasCreds: () => Boolean(CLIENT_ID && CLIENT_SECRET),
  hasScope,
  SCOPE,
  SCOPE_TRAFFIC,
  SCOPE_DOMAIN,
  TOKEN_PATH,
  SETUP_HELP,
  interactiveLogin,
  getAccessToken,
  getAccessTokenSilent,
  describeSignInProblem,
  loadCache,
  signOut,
};

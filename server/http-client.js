'use strict';

/*
 * Never follows redirects: one could send the bearer token or client secret
 * to another host.
 */

const https = require('https');
const { URL } = require('url');

const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

function positiveIntEnv(name, fallback) {
  const parsed = Number.parseInt(process.env[name] || '', 10);
  const isUsable = Number.isInteger(parsed) && parsed > 0;
  return isUsable ? parsed : fallback;
}

const REQUEST_TIMEOUT_MS = positiveIntEnv('GPT_REQUEST_TIMEOUT_MS', 60000);

function httpsRequest({ method, url, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== 'https:') {
      reject(new Error(`Refusing to send a request over ${target.protocol}`));
      return;
    }

    let timer = null;
    const settle = (fn, value) => {
      clearTimeout(timer);
      fn(value);
    };

    const req = https.request({
      method,
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      headers,
    }, (res) => {
      const chunks = [];
      let received = 0;
      res.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES) {
          req.destroy(new Error(`Response from ${target.hostname} was larger than ${MAX_RESPONSE_BYTES} bytes.`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => settle(resolve, {
        status: res.statusCode,
        headers: res.headers,
        // Join before decoding: a multi-byte character can span two chunks.
        body: Buffer.concat(chunks).toString('utf8'),
      }));
      res.on('error', (e) => settle(reject, e));
    });

    timer = setTimeout(() => {
      req.destroy(new Error(`Request to ${target.hostname} timed out after ${REQUEST_TIMEOUT_MS} ms.`));
    }, REQUEST_TIMEOUT_MS);

    req.on('error', (e) => settle(reject, e));
    if (body) req.write(body);
    req.end();
  });
}

module.exports = { httpsRequest, positiveIntEnv };

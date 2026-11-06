'use strict';

// Loaded into the server under test with --require. Production code has no
// endpoint overrides, so tests swap https.request to reach the local mock.
const http = require('http');
const https = require('https');

const port = Number(process.env.GPT_TEST_MOCK_PORT);

https.request = (options, callback) => http.request({
  ...options,
  hostname: '127.0.0.1',
  port,
  headers: { ...options.headers, 'x-original-host': options.hostname },
}, callback);

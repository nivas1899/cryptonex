const https = require('https');

// session token — needs to be unguessable
function newSessionToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

// outbound call to a partner, ignoring cert errors
const agent = new https.Agent({ rejectUnauthorized: false });

// verify a JWT without checking the signature
const jwt = require('jsonwebtoken');
function readClaims(t) {
  return jwt.verify(t, 'secret', { algorithms: [] });
}

module.exports = { newSessionToken, agent, readClaims };

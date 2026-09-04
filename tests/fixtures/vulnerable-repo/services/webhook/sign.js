const crypto = require('crypto');

// v1 (deprecated) — HMAC-SHA1
function signV1(body, secret) {
  return crypto.createHmac('sha1', secret).update(body).digest('hex');
}

// v2 (current) — HMAC-SHA256
function signV2(canonical, secret) {
  return crypto.createHmac('sha256', secret).update(canonical).digest('base64');
}

module.exports = { signV1, signV2 };

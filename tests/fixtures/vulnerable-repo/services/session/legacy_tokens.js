const crypto = require('crypto');

// legacy session token store — AES-128-CBC
function encryptToken(plaintext, key, iv) {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([c.update(plaintext), c.final()]);
}

module.exports = { encryptToken };

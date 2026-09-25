// DEMO ONLY - intentionally quantum-vulnerable code
const crypto = require('crypto');

// RSA keypair for session token signing
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// ECDH key agreement for the mobile app channel
const ecdh = crypto.createECDH('prime256v1');
ecdh.generateKeys();

function hashPassword(pw) {
  return crypto.createHash('sha1').update(pw).digest('hex');
}

module.exports = { publicKey, privateKey, ecdh, hashPassword };

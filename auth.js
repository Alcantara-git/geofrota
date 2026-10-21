const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };

async function hashPassword(password, { minLength = 8, maxLength = 256 } = {}) {
    if (typeof password !== 'string' || password.length < minLength || password.length > maxLength)
        throw new Error(`A senha deve ter entre ${minLength} e ${maxLength} caracteres.`);
    const salt = crypto.randomBytes(16);
    const derived = await scrypt(password, salt, PARAMS.keylen, { N: PARAMS.N, r: PARAMS.r, p: PARAMS.p, maxmem: 64 * 1024 * 1024 });
    return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

async function verifyPassword(password, encoded) {
    if (typeof password !== 'string' || password.length > 256 || typeof encoded !== 'string') return false;
    const parts = encoded.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = Number(parts[1]), r = Number(parts[2]), p = Number(parts[3]);
    if (!Number.isSafeInteger(N) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p) || N < 2 || r < 1 || p < 1) return false;
    let salt, expected;
    try { salt = Buffer.from(parts[4], 'base64'); expected = Buffer.from(parts[5], 'base64'); }
    catch { return false; }
    if (salt.length < 16 || expected.length < 32 || expected.length > 128) return false;
    const actual = await scrypt(password, salt, expected.length, { N, r, p, maxmem: 64 * 1024 * 1024 });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

module.exports = { hashPassword, verifyPassword };

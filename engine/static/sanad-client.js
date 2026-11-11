// Attestor-side helper for a browser or any runtime with WebCrypto Ed25519 (Node 22 also has it). No imports, no network.
// The private key is created and kept by the caller (here: inside the page, never sent anywhere). Only signed statements leave.
const enc = new TextEncoder();
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('not finite'); return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : canonical(x))).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  throw new Error('cannot canonicalise ' + typeof v);
}

export const b64u = (bytes) => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
export async function sha256Hex(text) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)))); }

function base58(bytes) {
  let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b);
  let s = ''; while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}

/** A fresh attestor identity: { did, kid, sign(typ, payload) -> detached JWS }. */
export async function newAttestor() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return attestorFromKeyPair(pair);
}
export async function attestorFromKeyPair({ privateKey, publicKey }) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  const did = 'did:key:z' + base58(Uint8Array.from([0xed, 0x01, ...raw]));
  const kid = did + '#' + did.slice('did:key:'.length);
  const sign = async (typ, payload) => {
    const header = b64u(enc.encode(canonical({ alg: 'EdDSA', kid, typ })));
    const input = header + '.' + b64u(enc.encode(canonical(payload)));
    const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, enc.encode(input)));
    return header + '..' + b64u(sig);
  };
  return { did, kid, sign };
}

export const newNonce = () => b64u(crypto.getRandomValues(new Uint8Array(16)));

const invitationOf = (assessment, attestationId, did) => {
  const inv = (assessment.invitations ?? []).find((i) => i.attestationId === attestationId);
  if (!inv) throw new Error('no invitation ' + attestationId);
  if (inv.attestor !== did) throw new Error('the invitation is for ' + inv.attestor);
  return inv;
};

/** Returns { request, secret }. Keep `secret` on the device; post `request` to /commit. */
export async function prepareCommit({ attestor, assessment, attestationId, level, nonce = newNonce() }) {
  const inv = invitationOf(assessment, attestationId, attestor.did);
  if (!Number.isInteger(level) || level < 0 || level > 5) throw new Error('level must be 0..5');
  const commit = await sha256Hex(canonical({ attestor: inv.attestor, evidence: inv.evidence, level, nonce }));
  const payload = { type: 'sanad-commit', assessment: assessment.id, attestationId, attestor: inv.attestor, evidence: inv.evidence, role: inv.role, commit, templateHash: assessment.templateHash };
  return { request: { attestationId, payload, jws: await attestor.sign('sanad-commit+jws', payload) }, secret: { attestationId, level, nonce } };
}

/** Returns the body for /reveal. */
export async function prepareReveal({ attestor, assessment, attestationId, secret, date, conflictDeclared = false }) {
  const inv = invitationOf(assessment, attestationId, attestor.did);
  const commit = await sha256Hex(canonical({ attestor: inv.attestor, evidence: inv.evidence, level: secret.level, nonce: secret.nonce }));
  const statement = { id: attestationId, attestor: inv.attestor, evidence: inv.evidence, level: secret.level, role: inv.role, conflictDeclared, date, commit, nonce: secret.nonce };
  return { attestationId, statement, jws: await attestor.sign('sanad-attestation+jws', statement) };
}

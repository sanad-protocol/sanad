// DEMONSTRATION ONLY. This module generates attestor private keys so that a scripted run, a test or the demonstration page can play
// several attestors. A real attestor keeps their own key on their own device. Nothing in engine.mjs, bundle.mjs or the default paths of
// index.mjs imports this file, and the engine never stores or asks for an attestor's private key.
import { generateKeyPair, keyPairFromSeed, makeSigner, exportPrivateKey } from './keys.mjs';

const toSeed = (seed) => {
  if (seed instanceof Uint8Array) return seed;
  if (typeof seed === 'string' && /^[0-9a-f]{64}$/.test(seed)) return new Uint8Array(Buffer.from(seed, 'hex'));
  throw new Error('seed must be 32 bytes or 64 lowercase hex characters');
};

/** @returns {{ name: string, did: string, kid: string, signer: { did: string, kid: string, publicKey: Uint8Array, sign: Function }, privateKeyPkcs8: string }} */
export function createDemoAttestor(name, seed) {
  const kp = seed === undefined ? generateKeyPair() : keyPairFromSeed(toSeed(seed));
  const signer = makeSigner(kp.privateKey);
  return { name, did: signer.did, kid: signer.kid, signer, privateKeyPkcs8: exportPrivateKey(kp.privateKey) };
}

// Static bundle export and offline verification of an exported directory (SPEC 6.1).
//
// Layout (all paths relative to the base URL or directory; every file is plain JSON or text, so any static host or a git repository can serve it):
//   issuer.json                         issuer card, signed by the issuer key
//   bundles/<bundleHash>/credential.json, evidence.json, attestations.json, log.json, checkpoint.json, consistency.json, dids.json,
//                        [witnesses.json], [status.json], README.md, manifest.json
//   checkpoints/ and status/ and witness directories are written by publishCheckpoint, the status list publisher and runWitness.
// `urn:sanad:bundle:<bundleHash>` resolves to <base>/bundles/<bundleHash>/ ; the credential is <base>/bundles/<bundleHash>/credential.json.
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, basename, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { canonical } from './core.mjs';
import { EngineError } from './errors.mjs';
import { verifyConsistency, verifyCheckpoint } from './log.mjs';
import { verifyCredential } from './bundle.mjs';
import { readWitnessDir } from './witness.mjs';
import { createResolver } from './keys.mjs';

export const ISSUER_CARD_TYP = 'sanad-issuer-card+jws';
export const BUNDLE_FILES = ['credential.json', 'evidence.json', 'attestations.json', 'log.json', 'checkpoint.json', 'consistency.json', 'dids.json', 'README.md'];
const OPTIONAL_FILES = ['witnesses.json', 'status.json'];
const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const sha = (text) => createHash('sha256').update(text).digest('hex');
const jsonText = (v) => JSON.stringify(v, null, 2) + '\n';
const same = (a, b) => canonical(a) === canonical(b);
const err = (code, message, status = 400) => new EngineError(code, message, status);
const day = (iso) => String(iso).slice(0, 10);

export function readmeText({ bundleHash, base }) {
  const b = base ? base.replace(/\/+$/, '') : '<base>';
  return `# Sanad bundle ${bundleHash}

This directory is a self-contained, static copy of one Sanad credential. Nothing in it is a video, a name or a score:
it holds hashes, signatures, the signed log checkpoint and the credential, and anyone may mirror it (a free public git repository is enough).

## URL scheme

    ${b}/issuer.json                              issuer card (issuer DID, log key, log id), signed by the issuer key
    ${b}/bundles/<bundleHash>/                    this directory; urn:sanad:bundle:<bundleHash> resolves here
    ${b}/bundles/<bundleHash>/credential.json     the credential (verifiable on its own)
    ${b}/bundles/<bundleHash>/manifest.json       SHA-256 of every other file here (integrity of a mirror, not trust)
    ${b}/checkpoints/latest.json                  newest signed checkpoint, with a consistency proof from the previous one
    ${b}/checkpoints/<size>.json, index.json      every published checkpoint, in order
    ${b}/status/revocation.json                   Bitstring Status List credential (fetch it fresh; it expires)

Witnesses publish their cosignatures in their own static directories: <witnessBase>/<logId>/<size>.json.

## Files here

- credential.json: the credential; evidence.json, attestations.json, log.json, checkpoint.json, dids.json are the same data as parts of it, split for readers and indexers; verification checks that they agree.
- consistency.json: proofs that the log of the credential's checkpoint is a prefix of later signed checkpoints (RFC 9162).
- witnesses.json (if present): checkpoints cosigned by witnesses. status.json (if present): a snapshot of the status list at export time; fetch the list again to check revocation.

## Verify with no server and no network

    sanad-engine verify-bundle <this directory> --policy policy.json --issuer <issuer DID> --log-key <log key DID> [--witness <DID> --require-witnesses 1]

or open sanad-verifier.html in a browser and drop this directory (or a zip of it) on it. The issuer and log key must come from a source you trust; the directory cannot vouch for itself.
A policy is yours to choose: the issuer's recommendation is inside the credential, but it is only a recommendation.
`;
}

/**
 * Builds the files of one bundle directory (and the issuer card) in memory.
 * @param {{ engine: object, credentialId: string, issuerSigner?: { did: string, kid: string, sign: Function }, base?: string|null, checkpointsDir?: string|null, witnessDirs?: string[], now?: number|string|Date }} p
 * @returns {{ bundleHash: string, files: Map<string, string> }}
 */
export function buildBundleFiles({ engine, credentialId, issuerSigner, base = null, checkpointsDir = null, witnessDirs = [], now = Date.now() }) {
  const cred = engine.getCredential(credentialId);
  const bundleHash = cred.evidence[0].bundleHash;
  const dir = 'bundles/' + bundleHash + '/';
  const files = new Map();
  const log = cred.sanad.log;
  const cpSize = log.checkpoint.payload.size;

  // checkpoints to prove consistency with: the ones witnesses cosigned and the newest published one
  const cosigned = [];
  for (const wd of witnessDirs) for (const item of readWitnessDir(wd, log.logId)) cosigned.push(item);
  const targets = new Map();
  for (const c of cosigned) targets.set(c.checkpoint.payload.size, c.checkpoint);
  if (checkpointsDir && existsSync(join(checkpointsDir, 'checkpoints', 'latest.json'))) {
    const l = JSON.parse(readFileSync(join(checkpointsDir, 'checkpoints', 'latest.json'), 'utf8'));
    if (l?.checkpoint?.payload?.logId === log.logId) targets.set(l.checkpoint.payload.size, l.checkpoint);
  }
  const consistency = [];
  for (const [size, checkpoint] of [...targets].sort((a, b) => a[0] - b[0])) {
    if (size <= cpSize || size > engine.log.size()) continue;
    const c = engine.log.consistency(cpSize, size);
    if (c.rootM !== log.checkpoint.payload.rootHash || c.rootN !== checkpoint.payload.rootHash) continue; // not this log's history: left out, verification would refuse it
    consistency.push({ from: { size: cpSize, rootHash: c.rootM }, to: { checkpoint }, proof: c.proof });
  }
  const useful = cosigned.filter((c) => c.checkpoint.payload.size >= cpSize);

  files.set(dir + 'credential.json', jsonText(cred));
  files.set(dir + 'evidence.json', jsonText(cred.sanad.bundle.evidence));
  files.set(dir + 'attestations.json', jsonText(cred.sanad.bundle.attestations));
  files.set(dir + 'log.json', jsonText({ logId: log.logId, logKey: log.logKey, entries: log.entries, proofs: log.proofs }));
  files.set(dir + 'checkpoint.json', jsonText(log.checkpoint));
  files.set(dir + 'consistency.json', jsonText(consistency));
  files.set(dir + 'dids.json', jsonText(cred.sanad.dids));
  if (useful.length) files.set(dir + 'witnesses.json', jsonText(useful));
  let statusUrl = null;
  try { const list = engine.statusListCredential(); statusUrl = list.id; files.set(dir + 'status.json', jsonText(list)); } catch (e) { if (e.code !== 'no_status_list') throw e; }
  files.set(dir + 'README.md', readmeText({ bundleHash, base }));
  const manifest = { type: 'sanad-bundle-manifest', version: 1, bundleHash, files: {} };
  for (const [k, v] of [...files].sort((a, b) => (a[0] < b[0] ? -1 : 1))) manifest.files[k.slice(dir.length)] = sha(v);
  files.set(dir + 'manifest.json', jsonText(manifest));

  const dids = [...new Set([cred.issuer, log.logKey])].filter((d) => !d.startsWith('did:key:')).map((d) => engine.resolver.get(d)).filter(Boolean);
  const card = { type: 'sanad-issuer-card', version: 1, alg: 'sanad-0.1', issuer: cred.issuer, logId: log.logId, logKey: log.logKey, base: base ?? null, bundles: 'bundles/', checkpoints: 'checkpoints/', status: statusUrl, dids, updated: new Date(now).toISOString() };
  if (issuerSigner) {
    if (issuerSigner.did !== cred.issuer) throw err('wrong_issuer', 'the issuer key is ' + issuerSigner.did + ' but the credential was issued by ' + cred.issuer);
    files.set('issuer.json', jsonText({ ...card, proof: { type: 'SanadDetachedJws', verificationMethod: issuerSigner.kid, jws: issuerSigner.sign(ISSUER_CARD_TYP, JSON.parse(JSON.stringify(card))) } }));
  } else files.set('issuer.json', jsonText(card));
  files.set('README.md', readmeText({ bundleHash: '<bundleHash>', base }));
  return { bundleHash, files };
}

/** Writes a files map under `root` (creating directories); existing files with the same name are replaced. */
export function writeFiles(root, files) {
  for (const [rel, text] of files) {
    if (rel.split('/').some((s) => s === '' || s === '.' || s === '..')) throw err('bad_path', 'unsafe path ' + rel);
    const f = join(root, rel);
    mkdirSync(dirname(f), { recursive: true });
    writeFileSync(f, text);
  }
}

const TREE_LIMITS = { files: 5000, bytes: 64 * 1024 * 1024 };
/** Reads a directory tree into a Map of relative path -> text (regular files only, no dot-directories, bounded). */
export function readTree(root) {
  const out = new Map(); let bytes = 0;
  const walk = (rel) => {
    for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const r = rel ? rel + '/' + e.name : e.name;
      if (e.isDirectory()) walk(r);
      else if (e.isFile()) {
        const st = statSync(join(root, r)); bytes += st.size;
        if (out.size >= TREE_LIMITS.files || bytes > TREE_LIMITS.bytes) throw err('too_large', 'the directory is larger than a bundle should be');
        out.set(r, readFileSync(join(root, r), 'utf8'));
      }
    }
  };
  walk('');
  return out;
}

/**
 * Reads what `verify-bundle <path>` should verify: a bundle directory (containing credential.json; ../../issuer.json is added when the layout is the standard one)
 * or a base directory containing bundles/<hash>/.
 */
export function readBundlePath(path) {
  const p = resolve(path);
  if (existsSync(join(p, 'credential.json'))) {
    const cred = JSON.parse(readFileSync(join(p, 'credential.json'), 'utf8'));
    const h = cred?.evidence?.[0]?.bundleHash;
    if (typeof h !== 'string' || !HEX64.test(h)) throw err('bad_bundle', 'credential.json has no bundle hash');
    const files = new Map();
    for (const [k, v] of readTree(p)) files.set('bundles/' + h + '/' + k, v);
    const card = join(dirname(dirname(p)), 'issuer.json');
    if (basename(dirname(p)) === 'bundles' && existsSync(card)) files.set('issuer.json', readFileSync(card, 'utf8'));
    return files;
  }
  if (existsSync(join(p, 'bundles'))) return readTree(p);
  throw err('bad_bundle', path + ' is neither a bundle directory (credential.json) nor a base directory (bundles/)');
}

const parse = (files, name) => { const t = files.get(name); if (t === undefined) return undefined; return JSON.parse(t); };

/**
 * Verifies an exported directory with no server and no network: file integrity (manifest), agreement between the split files and the credential,
 * the issuer card, the consistency proofs, then everything `verifyCredential` checks (with the verifier's own options).
 * @param {Map<string,string>} files relative path -> text, as readBundlePath / readTree return
 * @param {object} [opts] verifyCredential options, plus `bundle` (a bundle hash, when the tree holds several) and `trustedWitnesses`/`requireWitnesses`
 */
export function verifyBundleFiles(files, opts = {}) {
  const checks = [], warnings = [];
  const ADD = (name, ok, detail) => checks.push({ name, ok, detail });
  const finish = (report) => ({ ok: checks.every((c) => c.ok) && (report ? report.ok : true), checks: [...checks, ...(report?.checks ?? [])], warnings: [...warnings, ...(report?.warnings ?? [])], recognition: report?.recognition ?? null, inferred: report?.inferred ?? [], basis: report?.basis ?? null, notice: report?.notice });
  try {
    const dirs = [...new Set([...files.keys()].map((k) => /^bundles\/([0-9a-f]{64})\/credential\.json$/.exec(k)?.[1]).filter(Boolean))];
    const hash = opts.bundle ?? (dirs.length === 1 ? dirs[0] : undefined);
    if (!hash || !dirs.includes(hash)) { ADD('bundle-files', false, dirs.length ? 'the tree holds several bundles; name one (bundle): ' + dirs.join(', ') : 'no bundles/<hash>/credential.json in the tree'); return finish(null); }
    const dir = 'bundles/' + hash + '/';
    const get = (n) => files.get(dir + n);

    // 1. manifest: every listed file is present and has its hash; unlisted files are a warning
    {
      const why = [];
      let m; try { m = JSON.parse(get('manifest.json') ?? 'null'); } catch { m = null; }
      if (!isObj(m) || m.type !== 'sanad-bundle-manifest' || !isObj(m.files)) why.push('manifest.json is missing or malformed');
      else {
        if (m.bundleHash !== hash) why.push('manifest.json names another bundle hash');
        for (const [n, h] of Object.entries(m.files)) { const t = get(n); if (t === undefined) why.push(n + ' is listed but missing'); else if (sha(t) !== h) why.push(n + ' does not match its recorded SHA-256'); }
        for (const n of [...BUNDLE_FILES, ...OPTIONAL_FILES]) if (get(n) !== undefined && !(n in m.files)) why.push(n + ' is present but not listed');
        const extra = [...files.keys()].filter((k) => k.startsWith(dir) && k !== dir + 'manifest.json' && !(k.slice(dir.length) in m.files));
        if (extra.length) warnings.push('files not listed in the manifest: ' + extra.map((k) => k.slice(dir.length)).join(', '));
        for (const n of BUNDLE_FILES) if (!(n in m.files)) why.push(n + ' is required and not listed');
      }
      ADD('bundle-files', why.length === 0, why.length ? why.join('; ') : 'every file matches the manifest');
      if (why.length) return finish(null);
    }

    const cred = JSON.parse(get('credential.json'));
    const sanad = cred?.sanad;
    if (!isObj(sanad)) { ADD('bundle-consistency', false, 'credential.json has no sanad member'); return finish(null); }

    // 2. the split files agree with the credential
    {
      const why = [];
      if (cred.evidence?.[0]?.bundleHash !== hash) why.push('the directory name is not the credential\'s bundle hash');
      const eq = (name, v) => { let x; try { x = JSON.parse(get(name)); } catch { x = Symbol('bad'); } if (!same(x, v)) why.push(name + ' differs from the credential'); };
      eq('evidence.json', sanad.bundle?.evidence); eq('attestations.json', sanad.bundle?.attestations);
      eq('log.json', { logId: sanad.log?.logId, logKey: sanad.log?.logKey, entries: sanad.log?.entries, proofs: sanad.log?.proofs });
      eq('checkpoint.json', sanad.log?.checkpoint); eq('dids.json', sanad.dids);
      ADD('bundle-consistency', why.length === 0, why.length ? why.join('; ') : 'evidence, attestations, log, checkpoint and DID files agree with the credential');
    }

    // 3. issuer card (when present): the card names this credential's issuer and log, signed by the issuer
    const cardText = files.get('issuer.json');
    if (cardText === undefined) warnings.push('no issuer.json next to the bundles: the issuer card was not checked');
    else {
      const why = [];
      try {
        const card = JSON.parse(cardText);
        if (!isObj(card) || card.type !== 'sanad-issuer-card') why.push('not an issuer card');
        else {
          if (card.issuer !== cred.issuer) why.push('card issuer differs from the credential issuer');
          if (card.logKey !== sanad.log.logKey || card.logId !== sanad.log.logId) why.push('card log differs from the credential log');
          const { proof, ...body } = card;
          if (!isObj(proof) || proof.type !== 'SanadDetachedJws') why.push('the card is not signed');
          else {
            const dids = [...(Array.isArray(card.dids) ? card.dids : []), ...(sanad.dids ?? [])];
            const r = embeddedResolver(dids, opts).verifyStatement({ jws: proof.jws, payload: body, typ: ISSUER_CARD_TYP, signer: card.issuer, date: day(card.updated) });
            if (!r.ok || r.kid !== proof.verificationMethod) why.push('the card signature is refused' + (r.ok ? '' : ' (' + r.reason + ')'));
          }
        }
      } catch { why.push('issuer.json is not valid JSON'); }
      ADD('issuer-card', why.length === 0, why.length ? why.join('; ') : 'the card is signed by the credential\'s issuer and names its log');
    }

    // 4. consistency proofs from the credential's checkpoint to later signed checkpoints
    const consistency = [];
    {
      const why = [];
      const list = parse(files.has(dir + 'consistency.json') ? files : new Map([[dir + 'consistency.json', '[]']]), dir + 'consistency.json');
      const cp = sanad.log.checkpoint.payload;
      const res = embeddedResolver(sanad.dids ?? [], opts);
      for (const [i, c] of (Array.isArray(list) ? list : []).entries()) {
        const to = c?.to?.checkpoint;
        const ok = isObj(to) && c.from?.size === cp.size && c.from?.rootHash === cp.rootHash
          && verifyCheckpoint(to, (jws, payload, typ) => res.verifyStatement({ jws, payload, typ, signer: sanad.log.logKey, date: day(payload.timestamp) }).ok)
          && to.payload.logId === cp.logId
          && verifyConsistency({ m: cp.size, n: to.payload.size, proof: c.proof, rootM: cp.rootHash, rootN: to.payload.rootHash });
        if (!ok) why.push(`entry ${i} is not a valid consistency proof from the credential's checkpoint (size ${cp.size})`);
        else consistency.push({ m: cp.size, n: to.payload.size, rootM: cp.rootHash, rootN: to.payload.rootHash, proof: c.proof });
      }
      ADD('consistency-proofs', why.length === 0, why.length ? why.join('; ') : `${consistency.length} later checkpoint(s) proven to extend the credential's log`);
    }

    // 5. the credential itself, with the verifier's options
    const o = { ...opts }; delete o.bundle;
    const wit = files.has(dir + 'witnesses.json') ? JSON.parse(files.get(dir + 'witnesses.json')) : [];
    if (o.witnessEvidence === undefined) o.witnessEvidence = { cosigned: Array.isArray(wit) ? wit : [], consistency };
    if (o.statusLists === undefined && files.has(dir + 'status.json')) { o.statusLists = [JSON.parse(files.get(dir + 'status.json'))]; warnings.push('revocation was checked against the snapshot in status.json taken at export time; fetch the list again for a current answer'); }
    return finish(verifyCredential(cred, o));
  } catch (e) {
    ADD('internal', false, 'the directory could not be verified: ' + (e?.message ?? e));
    return finish(null);
  }
}

/** A resolver over DID histories found in a directory (untrusted unless the verifier pinned the keys) plus the verifier's own resolver. */
function embeddedResolver(dids, opts) {
  const m = new Map(); for (const d of dids) if (isObj(d) && typeof d.id === 'string') m.set(d.id, d);
  const emb = createResolver({ store: { get: (c, id) => m.get(id) ?? null, put() {} } });
  return { verifyStatement: (a) => { try { return (opts.resolver && !String(a.signer).startsWith('did:key:') && opts.resolver.get?.(a.signer) ? opts.resolver : emb).verifyStatement(a); } catch { return { ok: false, reason: 'bad_did_history' }; } } };
}

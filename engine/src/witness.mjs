// Checkpoint publication and witnesses (SPEC 8.2). A log operator writes signed checkpoints as plain static files; a witness is any party that
// fetches them, checks that each new checkpoint extends the one it stored before (RFC 9162 consistency), cosigns it and keeps the cosignature in
// its own static directory. A witness directory can live in a public git repository and be updated by a scheduled job: the git history is the mirror.
// A checkpoint says "the log had N entries with root R at time T"; cosignatures from several independent witnesses make a later rewrite of the log visible.
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { EngineError } from './errors.mjs';
import { verifyCheckpoint, verifyConsistency, isIsoTime } from './log.mjs';
import { createResolver } from './keys.mjs';

export const COSIGN_TYP = 'sanad-cosignature+jws';
const CHECKPOINT_TYP = 'sanad-checkpoint+jws';
const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const err = (code, message, status = 400) => new EngineError(code, message, status);
const jsonText = (v) => JSON.stringify(v, null, 2) + '\n';
const day = (iso) => String(iso).slice(0, 10);

function writeAtomic(file, text) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = file + '.tmp-' + process.pid;
  writeFileSync(tmp, text); renameSync(tmp, file);
}
const readJsonFile = (f) => JSON.parse(readFileSync(f, 'utf8'));

// ---------------------------------------------------------------------------------------------------------------------
// Publishing checkpoints (the log operator)

/**
 * Writes the log's current signed checkpoint into `<dir>/checkpoints/`:
 *   `<size>.json` = { checkpoint, previous: { size, rootHash } | null, consistency: [hex] }   (consistency from the previous published checkpoint)
 *   `latest.json` = the same content as the newest file, `index.json` = [{ size, timestamp, rootHash }] in order.
 * With `entries: true` it also writes `<dir>/log/entries.json`: every log entry (kind, hash and time of each leaf; no names and no content).
 * `daily: true` publishes only when no checkpoint of the same UTC day exists (for a scheduler that runs more often than daily); `force` publishes anyway.
 * @returns {{ published: boolean, reason?: string, size?: number, file?: string }}
 */
export function publishCheckpoint({ engine, dir, daily = false, force = false, entries = false }) {
  const cdir = join(dir, 'checkpoints'), indexFile = join(cdir, 'index.json');
  const index = existsSync(indexFile) ? readJsonFile(indexFile) : [];
  if (!Array.isArray(index)) throw err('bad_publication', 'checkpoints/index.json is not a list');
  const last = index.length ? index[index.length - 1] : null;
  const cp = engine.log.checkpoint();
  if (cp.payload.size === 0) return { published: false, reason: 'the log is empty: nothing to publish' };
  if (last && cp.payload.size < last.size) throw err('log_shrank', `the log has ${cp.payload.size} entries but checkpoint ${last.size} was published: refusing to publish a smaller log`, 409);
  if (!force && last) {
    if (cp.payload.size === last.size && cp.payload.rootHash === last.rootHash) return { published: false, reason: 'unchanged since the last published checkpoint (size ' + last.size + ')', size: last.size };
    if (cp.payload.size === last.size) throw err('log_forked', `the log has ${last.size} entries with a different root than the published checkpoint`, 409);
    if (daily && day(cp.payload.timestamp) === day(last.timestamp)) return { published: false, reason: 'a checkpoint of ' + day(last.timestamp) + ' is already published', size: last.size };
  }
  let previous = null, consistency = [];
  if (last && cp.payload.size > last.size) {
    const c = engine.log.consistency(last.size, cp.payload.size);
    if (c.rootM !== last.rootHash) throw err('log_forked', 'the log does not reproduce the root of the published checkpoint of size ' + last.size, 409);
    previous = { size: last.size, rootHash: last.rootHash }; consistency = c.proof;
  } else if (last) { const f = join(cdir, last.size + '.json'); if (existsSync(f)) { const o = readJsonFile(f); previous = o.previous ?? null; consistency = o.consistency ?? []; } } // forced re-signing of the same size keeps its link
  const body = { checkpoint: cp, previous, consistency };
  const file = join(cdir, cp.payload.size + '.json');
  writeAtomic(file, jsonText(body));
  writeAtomic(join(cdir, 'latest.json'), jsonText(body));
  if (!last || last.size !== cp.payload.size) index.push({ size: cp.payload.size, timestamp: cp.payload.timestamp, rootHash: cp.payload.rootHash });
  else index[index.length - 1] = { size: cp.payload.size, timestamp: cp.payload.timestamp, rootHash: cp.payload.rootHash };
  writeAtomic(indexFile, jsonText(index));
  if (entries) writeAtomic(join(dir, 'log', 'entries.json'), jsonText(engine.log.entries(0, cp.payload.size)));
  return { published: true, size: cp.payload.size, file };
}

// ---------------------------------------------------------------------------------------------------------------------
// Cosignatures

/** The statement a witness signs with typ sanad-cosignature+jws. It names the checkpoint completely, the log key that signed it and the witness. */
export function cosignStatement({ checkpoint, logKey, witness, witnessedAt }) {
  const p = checkpoint.payload;
  return { type: 'sanad-cosignature', logId: p.logId, size: p.size, rootHash: p.rootHash, timestamp: p.timestamp, logKey, witness, witnessedAt };
}
/** @param {{ signer: { did: string, sign: Function }, checkpoint: { payload: object, jws: string }, logKey: string, now: number|string|Date }} p */
export function makeCosignature({ signer, checkpoint, logKey, now }) {
  const witnessedAt = new Date(now).toISOString();
  return { witness: signer.did, witnessedAt, jws: signer.sign(COSIGN_TYP, cosignStatement({ checkpoint, logKey, witness: signer.did, witnessedAt })) };
}
/** Checks one cosignature against the checkpoint it claims to cover. */
export function verifyCosignature({ checkpoint, cosignature, logKey, resolver }) {
  try {
    if (!isObj(cosignature) || Object.keys(cosignature).sort().join() !== 'jws,witness,witnessedAt' || !isIsoTime(cosignature.witnessedAt)) return { ok: false, reason: 'malformed' };
    const r = resolver.verifyStatement({ jws: cosignature.jws, payload: cosignStatement({ checkpoint, logKey, witness: cosignature.witness, witnessedAt: cosignature.witnessedAt }), typ: COSIGN_TYP, signer: cosignature.witness, date: day(cosignature.witnessedAt) });
    return r.ok ? { ok: true } : { ok: false, reason: r.reason };
  } catch { return { ok: false, reason: 'malformed' }; }
}

/**
 * Counts the witnesses that cosigned a checkpoint at least as large as `checkpoint` (the credential's) and consistent with it.
 * Only witnesses the verifier pinned (`trusted`, a list of DIDs) count; a witness the verifier has never heard of proves nothing.
 * @param {{ checkpoint: {payload: object}, logKey: string, resolver: object, cosigned: {checkpoint: object, cosignature: object}[], consistency?: {m:number,n:number,rootM:string,rootN:string,proof:string[]}[], trusted?: string[] }} p
 * @returns {{ count: number, witnesses: string[], problems: string[] }}
 */
export function verifyWitnesses({ checkpoint, logKey, resolver, cosigned, consistency = [], trusted }) {
  const problems = [], seen = new Set();
  if (!Array.isArray(trusted) || trusted.length === 0) return { count: 0, witnesses: [], problems: ['no witness is pinned (trustedWitnesses): a cosignature by an unknown witness proves nothing'] };
  const base = checkpoint.payload;
  for (const [i, item] of (Array.isArray(cosigned) ? cosigned : []).entries()) {
    const w = item?.cosignature?.witness;
    const bad = (m) => problems.push(`cosignature ${i}${typeof w === 'string' ? ' (' + w + ')' : ''}: ${m}`);
    if (!isObj(item) || !isObj(item.checkpoint) || !isObj(item.cosignature)) { bad('malformed'); continue; }
    if (!trusted.includes(w)) { bad('witness is not pinned'); continue; }
    if (seen.has(w)) continue;
    const cp = item.checkpoint;
    if (!verifyCheckpoint(cp, (jws, payload, typ) => resolver.verifyStatement({ jws, payload, typ, signer: logKey, date: day(payload.timestamp) }).ok)) { bad('the cosigned checkpoint is not signed by the log key'); continue; }
    if (cp.payload.logId !== base.logId) { bad('the cosigned checkpoint belongs to another log'); continue; }
    const cs = verifyCosignature({ checkpoint: cp, cosignature: item.cosignature, logKey, resolver });
    if (!cs.ok) { bad('signature refused (' + cs.reason + ')'); continue; }
    if (cp.payload.size < base.size) { bad(`cosigned size ${cp.payload.size} is smaller than the credential's checkpoint (${base.size})`); continue; }
    if (cp.payload.size === base.size) { if (cp.payload.rootHash !== base.rootHash) { bad('same size, different root: the log forked'); continue; } }
    else {
      const c = consistency.find((x) => x && x.m === base.size && x.n === cp.payload.size && x.rootM === base.rootHash && x.rootN === cp.payload.rootHash);
      if (!c || !verifyConsistency(c)) { bad('no valid consistency proof from the credential\'s checkpoint to the cosigned one'); continue; }
    }
    seen.add(w);
  }
  return { count: seen.size, witnesses: [...seen].sort(), problems };
}

// ---------------------------------------------------------------------------------------------------------------------
// The witness job

async function readSource(source, rel, fetchImpl = globalThis.fetch) {
  if (/^https?:\/\//.test(source)) {
    const r = await fetchImpl(source.replace(/\/+$/, '') + '/' + rel, { redirect: 'follow' });
    if (!r.ok) throw err('source_unavailable', `${source}/${rel}: HTTP ${r.status}`, 502);
    return JSON.parse(await r.text());
  }
  const f = join(source, rel);
  if (!existsSync(f)) throw err('source_unavailable', f + ' does not exist', 502);
  return readJsonFile(f);
}

const publishedFileOk = (f) => isObj(f) && isObj(f.checkpoint) && (f.previous === null || (isObj(f.previous) && Number.isInteger(f.previous.size) && HEX64.test(f.previous.rootHash))) && Array.isArray(f.consistency);

/**
 * One run of a witness. `source` is the log's published directory (a URL or a local path containing `checkpoints/`). `outDir` is the witness's own
 * static directory; its state is the files it wrote earlier. The log key is pinned on the first run (`logKey`) and then read from `<outDir>/<logId>/pin.json`.
 * Returns { status: 'cosigned' | 'unchanged', size, rootHash }. Throws EngineError: `witness_alert` (fork, rollback or broken chain; an ALERT file is written),
 * `source_unavailable`, `bad_checkpoint`, `bad_pin`.
 * @param {{ source: string, outDir: string, signer: { did: string, sign: Function }, logKey?: string, resolver?: object, now?: number|string|Date, fetchImpl?: Function }} p
 */
export async function runWitness({ source, outDir, signer, logKey, resolver = createResolver(), now = Date.now(), fetchImpl }) {
  const latestFile = await readSource(source, 'checkpoints/latest.json', fetchImpl);
  if (!publishedFileOk(latestFile)) throw err('bad_checkpoint', 'checkpoints/latest.json is malformed');
  const cp = latestFile.checkpoint, logId = cp.payload?.logId;
  if (typeof logId !== 'string' || !/^[A-Za-z0-9._:-]{1,200}$/.test(logId)) throw err('bad_checkpoint', 'the checkpoint has no usable logId');
  const wdir = join(outDir, logId);
  // pin: the log key is chosen by whoever sets the witness up, not read from the log's own files
  const pinFile = join(wdir, 'pin.json');
  const stored = existsSync(pinFile) ? readJsonFile(pinFile).logKey : null;
  if (stored && logKey && stored !== logKey) throw err('bad_pin', `${pinFile} pins ${stored}; --log-key says ${logKey}`);
  const pin = stored ?? logKey;
  if (!pin) throw err('bad_pin', 'the first run needs the log key to trust (--log-key <did>); it is stored afterwards');
  const sigOk = (c) => verifyCheckpoint(c, (jws, payload, typ) => resolver.verifyStatement({ jws, payload, typ, signer: pin, date: day(payload.timestamp) }).ok);
  if (!sigOk(cp)) throw err('bad_checkpoint', 'the latest checkpoint is not signed by the pinned log key ' + pin);
  const alert = (reason, extra) => {
    const a = { type: 'sanad-witness-alert', reason, witness: signer.did, at: new Date(now).toISOString(), latest: cp, ...extra };
    const f = join(wdir, 'ALERT-' + a.at.replace(/[:.]/g, '-') + '.json');
    writeAtomic(f, jsonText(a));
    throw err('witness_alert', reason + ' (evidence written to ' + f + ')', 409);
  };
  const ownFile = join(wdir, 'latest.json');
  const own = existsSync(ownFile) ? readJsonFile(ownFile) : null;
  let chain = [];
  if (own) {
    const m = own.checkpoint.payload;
    if (!sigOk(own.checkpoint)) throw err('bad_pin', 'the stored checkpoint does not verify with the pinned log key: ' + ownFile);
    if (cp.payload.size < m.size) alert(`the log went backwards: it published ${cp.payload.size} entries, the witness had cosigned ${m.size}`, { stored: own.checkpoint });
    if (cp.payload.size === m.size) {
      if (cp.payload.rootHash !== m.rootHash) alert('the log forked: same size ' + m.size + ' with a different root', { stored: own.checkpoint });
      return { status: 'unchanged', size: m.size, rootHash: m.rootHash };
    }
    // walk the published files from the stored size to the latest; every hop is a consistency proof
    let index = null;
    try { index = await readSource(source, 'checkpoints/index.json', fetchImpl); } catch { index = null; }
    const sizes = Array.isArray(index) ? index.map((e) => e.size).filter((n) => Number.isInteger(n) && n > m.size && n < cp.payload.size).sort((a, b) => a - b) : [];
    const files = [];
    for (const n of sizes) files.push(await readSource(source, `checkpoints/${n}.json`, fetchImpl));
    files.push(latestFile);
    let from = { size: m.size, rootHash: m.rootHash };
    for (const f of files) {
      if (!publishedFileOk(f) || !sigOk(f.checkpoint)) alert('a published checkpoint between the stored one and the latest is malformed or not signed by the pinned key', { stored: own.checkpoint });
      const to = f.checkpoint.payload;
      if (!f.previous || f.previous.size !== from.size || f.previous.rootHash !== from.rootHash) alert(`the published chain does not link to the stored checkpoint (size ${from.size}): the log's history is not provably unchanged`, { stored: own.checkpoint });
      if (!verifyConsistency({ m: from.size, n: to.size, proof: f.consistency, rootM: from.rootHash, rootN: to.rootHash })) alert(`the consistency proof from ${from.size} to ${to.size} fails: the log was rewritten`, { stored: own.checkpoint });
      from = { size: to.size, rootHash: to.rootHash };
      chain.push(f);
    }
  }
  const cosignature = makeCosignature({ signer, checkpoint: cp, logKey: pin, now });
  const record = { checkpoint: cp, cosignature, chain: chain.map((f) => ({ checkpoint: f.checkpoint, previous: f.previous, consistency: f.consistency })) };
  mkdirSync(wdir, { recursive: true });
  if (!existsSync(pinFile)) writeAtomic(pinFile, jsonText({ logKey: pin }));
  writeAtomic(join(wdir, cp.payload.size + '.json'), jsonText(record));
  writeAtomic(ownFile, jsonText(record));
  writeAtomic(join(outDir, 'witness.json'), jsonText({ type: 'sanad-witness-card', version: 1, witness: signer.did, logs: listLogs(outDir) }));
  return { status: 'cosigned', size: cp.payload.size, rootHash: cp.payload.rootHash };
}

function listLogs(outDir) {
  try { return readdirSync(outDir, { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(join(outDir, d.name, 'latest.json'))).map((d) => d.name).sort(); } catch { return []; }
}

/** Reads cosignatures a witness directory holds for `logId`: [{ checkpoint, cosignature }] ordered by size. */
export function readWitnessDir(dir, logId) {
  const wdir = join(dir, logId);
  if (!existsSync(wdir)) return [];
  return readdirSync(wdir).filter((n) => /^\d+\.json$/.test(n)).sort((a, b) => Number(a.slice(0, -5)) - Number(b.slice(0, -5)))
    .map((n) => { const r = readJsonFile(join(wdir, n)); return { checkpoint: r.checkpoint, cosignature: r.cosignature }; });
}

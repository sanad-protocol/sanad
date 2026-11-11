import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, statSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli.mjs';
import * as H from './helpers.mjs';

const dir = mkdtempSync(join(tmpdir(), 'sanad-cli-'));
const data = join(dir, 'data');
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function run(...args) {
  const out = [], err = [];
  const code = await main(args, { out: (s) => out.push(s), err: (s) => err.push(s), env: {} });
  return { code, out: out.join('\n'), err: err.join('\n') };
}
const json = (r) => JSON.parse(r.out);
const today = () => new Date().toISOString().slice(0, 10);
const POLICY5 = { minAttestors: 5, requireLive: true, halfLifeMonths: 12, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 };

describe('CLI: init and keys', () => {
  it('init writes issuer, log key and token with mode 0600 and refuses to run twice', async () => {
    const r = await run('init', '--dir', data);
    expect(r.code).toBe(0);
    for (const f of ['issuer.key.json', 'log.key.json', 'operator.token']) expect(statSync(join(data, f)).mode & 0o777).toBe(0o600);
    expect((await run('init', '--dir', data)).code).toBe(2);
  });
  it('keygen writes a private attestor key with mode 0600, prints only the DID and never overwrites', async () => {
    const f = join(dir, 'a.key.json');
    const r = await run('keygen', '--out', f);
    expect(r.code).toBe(0); expect(r.out).toMatch(/^did:key:z/); expect(r.out).not.toContain(JSON.parse(readFileSync(f, 'utf8')).privateKey);
    expect(statSync(f).mode & 0o777).toBe(0o600);
    expect((await run('keygen', '--out', f)).code).toBe(2);
  });
  it('usage errors give 64 and an uninitialised directory gives 2', async () => {
    expect((await run()).code).toBe(64);
    expect((await run('bogus', '--dir', data)).code).toBe(64);
    expect((await run('finalize', 'x', '--dir', join(dir, 'empty'))).code).toBe(2);
  });
});

describe('CLI: a whole assessment through the command line', () => {
  it('attestors sign with their own key files; the operator directory never holds those keys', async () => {
    const tpl = join(dir, 'tpl.json'); writeFileSync(tpl, JSON.stringify(H.template()));
    expect((await run('template', 'add', tpl, '--dir', data)).code).toBe(0);
    const keys = { a: join(dir, 'ka.json'), b: join(dir, 'kb.json') };
    for (const k of Object.values(keys)) await run('keygen', '--out', k);
    const did = (n) => JSON.parse(readFileSync(keys[n], 'utf8')).did;
    const ev = join(dir, 'ev.json'); writeFileSync(ev, JSON.stringify([{ key: 'E1', date: today(), summary: 'sitting', body: { minutes: 30 } }]));
    expect((await run('create-assessment', '--template', 'maths-oral-v1', '--subject', 'urn:uuid:44444444-4444-4444-8444-444444444444', '--level', '3', '--evidence', ev, '--id', 'as-cli', '--dir', data)).code).toBe(0);
    const i1 = json(await run('invite', 'as-cli', '--attestor', did('a'), '--evidence', 'E1', '--dir', data));
    const i2 = json(await run('invite', 'as-cli', '--attestor', did('b'), '--evidence', 'E1', '--dir', data));
    expect((await run('commit', 'as-cli', i1.attestationId, '--key', keys.a, '--level', '3', '--dir', data)).code).toBe(0);
    expect((await run('reveal', 'as-cli', i1.attestationId, '--key', keys.a, '--dir', data)).code).toBe(2); // blind: B has not committed yet
    expect((await run('commit', 'as-cli', i2.attestationId, '--key', keys.b, '--level', '4', '--dir', data)).code).toBe(0);
    expect((await run('reveal', 'as-cli', i1.attestationId, '--key', keys.a, '--dir', data)).code).toBe(0);
    expect((await run('reveal', 'as-cli', i2.attestationId, '--key', keys.b, '--dir', data)).code).toBe(0);
    const out = join(dir, 'cred.json');
    expect((await run('finalize', 'as-cli', '--out', out, '--dir', data)).code).toBe(0);
    const issuerDid = JSON.parse(readFileSync(join(data, 'issuer.key.json'), 'utf8')).did, logDid = JSON.parse(readFileSync(join(data, 'log.key.json'), 'utf8')).did;
    const unpinned = await run('verify', out);
    expect(unpinned.code).toBe(1); expect(unpinned.out).toMatch(/FAIL {2}trusted-issuer/); expect(unpinned.out).toMatch(/NOTICE.*not been cryptographically reviewed/);
    expect((await run('verify', out, '--allow-unpinned')).code).toBe(0);
    const v = await run('verify', out, '--issuer', issuerDid, '--log-key', logDid);
    expect(v.code).toBe(0); expect(v.out).toMatch(/PASS {2}attestor-signatures/); expect(v.out).toMatch(/not a verifier policy/);

    const secretA = JSON.parse(readFileSync(keys.a, 'utf8')).privateKey;
    const all = ['issuer.key.json', 'log.key.json'].map((f) => readFileSync(join(data, f), 'utf8')).join('') + readFileSync(out, 'utf8');
    expect(all).not.toContain(secretA);
    expect(existsSync(keys.a + '.secrets.json')).toBe(true);

    const bad = JSON.parse(readFileSync(out, 'utf8')); bad.sanad.bundle.attestations[0].level = 5;
    const badf = join(dir, 'bad.json'); writeFileSync(badf, JSON.stringify(bad));
    expect((await run('verify', badf, '--allow-unpinned')).code).toBe(1);

    const pf = join(dir, 'p.json'); writeFileSync(pf, JSON.stringify(POLICY5));
    const issuer = JSON.parse(readFileSync(join(data, 'issuer.key.json'), 'utf8')).did;
    const v2 = await run('verify', out, '--policy', pf, '--issuer', issuer, '--log-key', logDid, '--as-of', today());
    expect(v2.code).toBe(0); expect(v2.out).toMatch(/your policy/); expect(v2.out).toMatch(/provisional/);
    expect((await run('verify', out, '--issuer', 'did:key:zOther', '--log-key', logDid)).code).toBe(1);
    expect(json(await run('log', 'checkpoint', '--dir', data)).payload.size).toBeGreaterThan(0);
    expect(json(await run('log', 'inclusion', '--index', '0', '--dir', data)).index).toBe(0);
  });
  it('the bin script runs and prints usage', () => {
    const bin = fileURLToPath(new URL('../bin/sanad-engine', import.meta.url));
    const r = spawnSync('node', [bin, 'help'], { encoding: 'utf8' });
    expect(r.status).toBe(0); expect(r.stdout).toMatch(/sanad-engine <command>/);
    expect(spawnSync('node', [bin], { encoding: 'utf8' }).status).toBe(64);
  });
});

describe('CLI: serve and remote attestor commands', () => {
  it('commit over --url sends only a signed statement to a running server', async () => {
    const d2 = join(dir, 'data2'); await run('init', '--dir', d2);
    const tpl = join(dir, 'tpl2.json'); writeFileSync(tpl, JSON.stringify(H.template()));
    await run('template', 'add', tpl, '--dir', d2);
    const key = join(dir, 'r.key.json'); await run('keygen', '--out', key);
    const did = JSON.parse(readFileSync(key, 'utf8')).did;
    const ev = join(dir, 'ev2.json'); writeFileSync(ev, JSON.stringify([{ key: 'E1', date: today(), summary: 's', body: {} }]));
    await run('create-assessment', '--template', 'maths-oral-v1', '--subject', 'urn:uuid:55555555-5555-4555-8555-555555555555', '--level', '2', '--evidence', ev, '--id', 'as-r', '--dir', d2);
    const inv = json(await run('invite', 'as-r', '--attestor', did, '--evidence', 'E1', '--dir', d2));
    let srv;
    await main(['serve', '--dir', d2, '--port', '0'], { out: () => {}, err: () => {}, env: {}, onServer: (s) => { srv = s; } });
    const url = 'http://127.0.0.1:' + srv.address().port;
    try {
      expect((await run('commit', 'as-r', inv.attestationId, '--key', key, '--level', '2', '--url', url)).code).toBe(0);
      const view = await fetch(url + '/v1/assessments/as-r').then((r) => r.json());
      expect(view.commits[inv.attestationId].commit).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.stringify(view)).not.toContain(JSON.parse(readFileSync(key, 'utf8')).privateKey);
    } finally { await new Promise((ok) => srv.close(ok)); }
  });
});

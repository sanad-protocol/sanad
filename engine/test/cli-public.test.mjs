import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/cli.mjs';
import * as H from './helpers.mjs';

const dir = mkdtempSync(join(tmpdir(), 'sanad-pub-'));
const data = join(dir, 'data'), site = join(dir, 'site'), wit = join(dir, 'wit');
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const run = async (...args) => { const out = [], err = []; const code = await main(args, { out: (s) => out.push(s), err: (s) => err.push(s), env: {} }); return { code, out: out.join('\n'), err: err.join('\n') }; };
const json = (r) => JSON.parse(r.out);
const POLICY = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 };

describe('CLI: publishing, witnessing, revocation, offline verification', () => {
  it('runs the whole public path with no server', async () => {
    expect((await run('init', '--dir', data)).code).toBe(0);
    const cfg = JSON.parse(readFileSync(join(data, 'config.json'), 'utf8'));
    writeFileSync(join(data, 'config.json'), JSON.stringify({ ...cfg, statusUrl: 'https://example.org/sanad/status/revocation.json' }));
    const tpl = join(dir, 'tpl.json'); writeFileSync(tpl, JSON.stringify(H.template()));
    await run('template', 'add', tpl, '--dir', data);
    const keys = { a: join(dir, 'ka.json'), b: join(dir, 'kb.json'), w: join(dir, 'kw.json') };
    for (const k of Object.values(keys)) await run('keygen', '--out', k);
    const did = (n) => JSON.parse(readFileSync(keys[n], 'utf8')).did;
    const today = new Date().toISOString().slice(0, 10);
    const ev = join(dir, 'ev.json'); writeFileSync(ev, JSON.stringify([{ key: 'E1', date: today, summary: 'sitting', body: { minutes: 30 } }]));
    await run('create-assessment', '--template', 'maths-oral-v1', '--subject', 'urn:uuid:44444444-4444-4444-8444-444444444444', '--level', '3', '--evidence', ev, '--id', 'as-pub', '--dir', data);
    const sh = (h) => 'b'.repeat(64) && h;
    const i1 = json(await run('invite', 'as-pub', '--attestor', did('a'), '--evidence', 'E1', '--dir', data));
    const i2 = json(await run('invite', 'as-pub', '--attestor', did('b'), '--evidence', 'E1', '--dir', data));
    for (const [att, k, l] of [[i1.attestationId, keys.a, '3'], [i2.attestationId, keys.b, '3']]) expect((await run('commit', 'as-pub', att, '--key', k, '--level', l, '--dir', data)).code).toBe(0);
    for (const [att, k] of [[i1.attestationId, keys.a], [i2.attestationId, keys.b]]) expect((await run('reveal', 'as-pub', att, '--key', k, '--dir', data)).code).toBe(0);
    const credFile = join(dir, 'c.json');
    await run('finalize', 'as-pub', '--out', credFile, '--dir', data);
    const cred = JSON.parse(readFileSync(credFile, 'utf8'));
    expect(cred.credentialStatus.statusListIndex).toBe('0');
    void sh;

    // publish the checkpoint, witness it, export with the witness cosignature
    expect((await run('publish-checkpoint', '--out', site, '--dir', data)).out).toMatch(/published checkpoint of size/);
    expect((await run('publish-checkpoint', '--out', site, '--daily', '--dir', data)).out).toMatch(/not published/);
    const issuerDid = JSON.parse(readFileSync(join(data, 'issuer.key.json'), 'utf8')).did, logDid = JSON.parse(readFileSync(join(data, 'log.key.json'), 'utf8')).did;
    expect((await run('witness', '--log', site, '--out', wit, '--key', keys.w)).code).toBe(2); // no pin yet
    const w1 = await run('witness', '--log', site, '--out', wit, '--key', keys.w, '--log-key', logDid);
    expect(w1.code).toBe(0); expect(w1.out).toMatch(/^cosigned size/);
    expect((await run('witness', '--log', site, '--out', wit, '--key', keys.w)).out).toMatch(/^unchanged/);
    expect((await run('status', 'publish', '--out', site, '--dir', data)).out).toMatch(/status list written/);
    expect(existsSync(join(site, 'status', 'revocation.json'))).toBe(true);
    const ex = await run('export', cred.id, '--out', site, '--base', 'https://example.org/sanad', '--checkpoints', site, '--witness-dirs', wit, '--dir', data);
    expect(ex.code).toBe(0); expect(ex.out).toContain('urn:sanad:bundle:' + cred.evidence[0].bundleHash);
    const bdir = join(site, 'bundles', cred.evidence[0].bundleHash);
    expect(readdirSync(bdir)).toContain('witnesses.json');

    // offline verification of the directory, base or bundle form
    const pol = join(dir, 'policy.json'); writeFileSync(pol, JSON.stringify(POLICY));
    const common = ['--policy', pol, '--as-of', today, '--issuer', issuerDid, '--log-key', logDid];
    const ok = await run('verify-bundle', bdir, ...common, '--witness', did('w'), '--require-witnesses', '1');
    expect(ok.code, ok.out).toBe(0); expect(ok.out).toMatch(/PASS {2}witnesses/); expect(ok.out).toMatch(/PASS {2}bundle-files/); expect(ok.out).toMatch(/PASS {2}issuer-card/);
    expect((await run('verify-bundle', site, ...common)).code).toBe(0);
    expect((await run('verify-bundle', bdir, ...common, '--witness', did('w'), '--require-witnesses', '2')).code).toBe(1);
    expect((await run('verify-bundle', bdir, '--policy', pol, '--as-of', today)).code).toBe(1); // unpinned
    expect((await run('verify-bundle', bdir)).code).toBe(64);

    // revocation: the next published list sets the bit and a verifier who fetches it fails the credential
    expect(json(await run('revoke', cred.id, '--reason', 'issued in error', '--dir', data))).toMatchObject({ already: false, index: 0 });
    await run('status', 'publish', '--out', site, '--dir', data);
    const fresh = join(site, 'status', 'revocation.json');
    const rev = await run('verify-bundle', bdir, ...common, '--status-list', fresh, '--require-status');
    expect(rev.code).toBe(1); expect(rev.out).toMatch(/FAIL {2}revocation .*revoked: bit 0/);
    // a credential file verifies with the same options
    expect((await run('verify', credFile, ...common, '--status-list', fresh)).code).toBe(1);
    expect((await run('verify', credFile, ...common)).code).toBe(0);
  });
});

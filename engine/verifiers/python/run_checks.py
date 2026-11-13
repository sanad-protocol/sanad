#!/usr/bin/env python3
"""Runs sanad_verify_spec.py over all fixtures and the core vectors; prints agreement table."""
import os, sys, json, subprocess, copy
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sanad_verify_spec as sv

ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
FIX = os.path.join(ROOT, 'engine', 'verifiers', 'fixtures')
VEC = os.path.join(ROOT, 'reference', 'vectors.json')

def close(a, b): return (a is None and b is None) or (a is not None and b is not None and abs(a - b) <= 0.001)
def norm_dropped(d): return sorted(x if isinstance(x, str) else f'{x[0]}:{x[1]}' for x in d)

def run_fixture(name):
    d = os.path.join(FIX, name)
    exp = json.load(open(os.path.join(d, 'expected.json')))
    out = subprocess.run([sys.executable, '-I', os.path.join(HERE, 'sanad_verify_spec.py'), os.path.join(d, 'tree'),
                          '--case', os.path.join(d, 'case.json')], capture_output=True, text=True)
    if out.returncode: return [f'crash: {out.stderr[-300:]}']
    got = json.loads(out.stdout); diffs = []
    if got['ok'] != exp['ok']: diffs.append(f"ok {got['ok']} vs {exp['ok']}")
    gf = [c['name'] for c in got['checks'] if not c['ok']]; ef = [c['name'] for c in exp['checks'] if not c['ok']]
    if gf != ef: diffs.append(f'failed checks {gf} vs {ef}')
    gn = [c['name'] for c in got['checks']]; en = [c['name'] for c in exp['checks']]
    if gn != en: diffs.append(f'check list {gn} vs {en}')
    if got['warnings'] != exp['warnings']: diffs.append(f"warnings {got['warnings']} vs {exp['warnings']}")
    g, e = got['recognition'], exp['recognition']
    if (g is None) != (e is None): diffs.append(f'recognition {g} vs {e}')
    elif g:
        for k in ('status', 'level', 'unverified'):
            if g[k] != e[k]: diffs.append(f'{k} {g[k]} vs {e[k]}')
        for k in ('attestedLevel', 'confidence'):
            if not close(g[k], e[k]): diffs.append(f'{k} {g[k]} vs {e[k]}')
        if norm_dropped(g['dropped']) != norm_dropped(e['dropped']): diffs.append(f"dropped {g['dropped']} vs {e['dropped']}")
    return diffs

def seal(cred):
    """Fill evidence hashes, commits, prev links and attestation hashes as spec 3.3/3.4 say.
    GUESS: role 'examiner', conflictDeclared default false, nonce invented (22 chars base64url)."""
    ev = copy.deepcopy(cred['evidence']); at = copy.deepcopy(cred['attestations'])
    for e in ev: e['hash'] = sv.chash(e['body'])   # body hashed as given (no kind/date injected)
    prev = 'GENESIS'
    for i, a in enumerate(sorted(at, key=lambda a: sv.u16key(a['id']))):
        a.setdefault('role', 'examiner'); a.setdefault('conflictDeclared', False)
        a['nonce'] = ('n%021d' % i)
        a['commit'] = sv.commit_of(a); a['prev'] = prev
        a['hash'] = sv.chash(sv.att_hash_obj(a)); prev = a['hash']
    return ev, at

def run_vector(v):
    cred = v['credential']; ev, at = seal(cred)
    for t in v.get('tamper', []):
        for a in at:
            if a['id'] == t['attestation']: a.update(t['set'])
    r = sv.recognise(v['policy'], cred['claimedLevel'], ev, at, cred.get('attestors', {}), None)
    x = v['expect']; diffs = []
    for k in ('status', 'level'):
        if r[k] != x[k]: diffs.append(f'{k} {r[k]} vs {x[k]}')
    for k in ('attestedLevel', 'confidence'):
        if not close(r[k], x[k]): diffs.append(f'{k} {r[k]} vs {x[k]}')
    if norm_dropped(r['dropped']) != norm_dropped(x['dropped']): diffs.append(f"dropped {r['dropped']} vs {x['dropped']}")
    return diffs

def main():
    bad = 0
    print('== fixtures')
    for n in sorted(os.listdir(FIX)):
        if not os.path.isdir(os.path.join(FIX, n)): continue
        d = run_fixture(n); bad += bool(d)
        print(f"{'AGREE   ' if not d else 'DISAGREE'} {n}" + ('' if not d else '\n           ' + '\n           '.join(d)))
    print('== core vectors (recognition only)')
    for v in json.load(open(VEC))['vectors']:
        d = run_vector(v); bad += bool(d)
        print(f"{'AGREE   ' if not d else 'DISAGREE'} {v['id']}" + ('' if not d else '  ' + '; '.join(d)))
    print('disagreements:', bad)
if __name__ == '__main__': main()

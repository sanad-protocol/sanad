#!/usr/bin/env python3
"""Independent Sanad v0.2 verifier written from the specification text only.
Usage: python3 -I sanad_verify_spec.py <tree dir> --case <case.json>
Spec guesses are marked 'GUESS' in comments."""
import sys, os, re, json, hashlib, base64, gzip, math, datetime
from decimal import Decimal

# ---------------------------------------------------------------- canonical JSON (RFC 8785)
def js_num(x):
    if isinstance(x, bool): raise ValueError('bool')
    if isinstance(x, int):
        if abs(x) > 2**53: raise ValueError('number beyond 2^53')
        return str(x)
    if math.isnan(x) or math.isinf(x): raise ValueError('nan/inf')
    if x == 0: return '0'
    if x == int(x) and abs(x) < 1e21:
        if abs(x) > 2**53: raise ValueError('number beyond 2^53')
        return str(int(x))
    sign = '-' if x < 0 else ''
    t = Decimal(repr(abs(x))).as_tuple()
    digits = ''.join(map(str, t.digits)).rstrip('0') or '0'
    k = len(digits)
    n = t.exponent + len(t.digits)  # value = 0.digits * 10^n
    if k <= n <= 21: s = digits + '0' * (n - k)
    elif 0 < n <= 21: s = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0: s = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        es = ('+' if e >= 0 else '-') + str(abs(e))
        s = digits[0] + ('.' + digits[1:] if k > 1 else '') + 'e' + es
    return sign + s

def js_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif ch == '\b': out.append('\\b')
        elif ch == '\f': out.append('\\f')
        elif ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ch == '\t': out.append('\\t')
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF: out.append('\\u%04x' % o)
        else: out.append(ch)
    out.append('"')
    return ''.join(out)

def canon(v):
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, (int, float)): return js_num(v)
    if isinstance(v, str): return js_str(v)
    if isinstance(v, list): return '[' + ','.join(canon(x) for x in v) + ']'
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: k.encode('utf-16-be', 'surrogatepass'))
        return '{' + ','.join(js_str(k) + ':' + canon(v[k]) for k in ks) + '}'
    raise ValueError('bad type')

def cb(v): return canon(v).encode('utf-8')
def sha(b): return hashlib.sha256(b).hexdigest()
def chash(v): return sha(cb(v))
def u16key(s): return s.encode('utf-16-be', 'surrogatepass')

# ---------------------------------------------------------------- base64url, base58
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def b64u_dec(s):
    if not re.fullmatch(r'[A-Za-z0-9_-]*', s) or len(s) % 4 == 1: raise ValueError('b64')
    b = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    if b64u(b) != s: raise ValueError('non-canonical b64')
    return b

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58enc(b):
    n = int.from_bytes(b, 'big'); s = ''
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + s
def b58dec(s):
    n = 0
    for c in s:
        if c not in B58: raise ValueError('b58')
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\0' * (len(s) - len(s.lstrip('1'))) + body

def mb_key(s):
    if not isinstance(s, str) or not s.startswith('z'): raise ValueError('multibase')
    k = b58dec(s[1:])
    if len(k) != 32 or b58enc(k) != s[1:]: raise ValueError('key length')
    return k

def didkey_pub(did):
    m = re.fullmatch(r'did:key:z([1-9A-HJ-NP-Za-km-z]+)', did)
    if not m: raise ValueError('not did:key')
    raw = b58dec(m.group(1))
    if len(raw) != 34 or raw[:2] != b'\xed\x01' or b58enc(raw) != m.group(1): raise ValueError('did:key')
    return raw[2:]

# ---------------------------------------------------------------- Ed25519 (RFC 8032), strict
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)
def _recx(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P: x = x * I % P
    if (x * x - x2) % P: return None
    if x == 0 and sign: return None
    if x & 1 != sign: x = P - x
    return x
def _add(a, b):
    x1, y1, z1, t1 = a; x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P; B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P; Dd = 2 * z1 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)
def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1: q = _add(q, pt)
        pt = _add(pt, pt); s >>= 1
    return q
def _enc(pt):
    x, y, z, _ = pt; zi = pow(z, P - 2, P); x = x * zi % P; y = y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')
def _dec(b):
    n = int.from_bytes(b, 'little'); y = n & ((1 << 255) - 1)
    if y >= P: return None  # non-canonical
    x = _recx(y, n >> 255)
    return None if x is None else (x, y, 1, x * y % P)
_BY = 4 * pow(5, P - 2, P) % P
_B = (_recx(_BY, 0), _BY, 1, _recx(_BY, 0) * _BY % P)
_ID = _enc((0, 1, 1, 0))

def ed_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64: return False
    A = _dec(pub); R = _dec(sig[:32])
    if A is None or R is None: return False
    if _enc(_mul(8, A)) == _ID: return False  # small order key
    S = int.from_bytes(sig[32:], 'little')
    if S >= L: return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % L
    return _enc(_mul(S, _B)) == _enc(_add(R, _mul(k, A)))

# ---------------------------------------------------------------- Merkle (RFC 9162)
def H0(b): return hashlib.sha256(b'\x00' + b).digest()
def H1(a, b): return hashlib.sha256(b'\x01' + a + b).digest()
def hx(s):
    if not isinstance(s, str) or not re.fullmatch(r'[0-9a-f]{64}', s): raise ValueError('hex')
    return bytes.fromhex(s)

def verify_inclusion(leaf_text, index, size, proof, root):
    try:
        if index >= size: return False
        fn, sn, r = index, size - 1, H0(leaf_text.encode('utf-8'))
        for p in map(hx, proof):
            if sn == 0: return False
            if fn & 1 or fn == sn:
                r = H1(p, r)
                if not fn & 1:
                    while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
            else: r = H1(r, p)
            fn >>= 1; sn >>= 1
        return sn == 0 and r == hx(root)
    except (ValueError, TypeError): return False

def verify_consistency(m, n, mroot, nroot, proof):
    try:
        if m > n or m < 0: return False
        mr, nr = hx(mroot), hx(nroot); proof = [hx(p) for p in proof]
        if m == n: return not proof and mr == nr
        if m == 0: return not proof
        if m & (m - 1) == 0: proof = [mr] + proof
        if not proof: return False
        fn, sn = m - 1, n - 1
        while fn & 1: fn >>= 1; sn >>= 1
        fr = sr = proof[0]
        for c in proof[1:]:
            if sn == 0: return False
            if fn & 1 or fn == sn:
                fr = H1(c, fr); sr = H1(c, sr)
                if not fn & 1:
                    while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
            else: sr = H1(sr, c)
            fn >>= 1; sn >>= 1
        return sn == 0 and fr == mr and sr == nr
    except (ValueError, TypeError): return False

# ---------------------------------------------------------------- dates
DATE_RE = re.compile(r'\d{4}-\d{2}-\d{2}')
def is_date(s):
    if not isinstance(s, str) or not DATE_RE.fullmatch(s): return False
    try: datetime.date(int(s[:4]), int(s[5:7]), int(s[8:])); return True
    except ValueError: return False
def pdate(s): return datetime.date(int(s[:4]), int(s[5:7]), int(s[8:10]))
DT_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})')
def is_dt(s): return isinstance(s, str) and DT_RE.fullmatch(s) is not None and is_date(s[:10])
def day(ts): return ts[:10]  # GUESS: day of a timestamp = first 10 chars (UTC, no conversion)

# ---------------------------------------------------------------- DIDs and JWS
class Ctx:
    def __init__(self, histories, pinned):
        self.hist = {h['id']: h for h in histories if isinstance(h, dict) and 'id' in h}
        self.pinned = pinned or {}
        self.used_history_keys = set()   # (did, multibase)

def key_valid_on(hist, keyid, d):
    vers = [v for v in hist['versions'] if v['validFrom'] <= d]
    if not vers: return None
    latest = max(vers, key=lambda v: v['version'])
    ent = [k for k in latest['keys'] if k['id'] == keyid]
    if not ent: return None
    for v in hist['versions']:
        for r in v['revoked']:
            if r['id'] == keyid and r['from'] <= d: return None
    return ent[0]['publicKeyMultibase']

def resolve(ctx, did, kid, d):
    """public key bytes for kid of signer did valid on day d, or None."""
    if not isinstance(kid, str) or not kid.startswith(did + '#'): return None
    if did.startswith('did:key:'):
        if kid != did + '#' + did[len('did:key:'):]: return None
        return didkey_pub(did)
    h = ctx.hist.get(did)
    if not h: return None
    mb = key_valid_on(h, kid[len(did):], d)
    if mb is None: return None
    ctx.used_history_keys.add((did, mb))
    return mb_key(mb)

def jws_verify(ctx, token, typ, signer, payload, d):
    try:
        parts = token.split('.')
        if len(parts) != 3 or parts[1] != '': return False
        hb = b64u_dec(parts[0]); sig = b64u_dec(parts[2])
        hdr = json.loads(hb.decode('utf-8'))
        if not isinstance(hdr, dict) or sorted(hdr) != ['alg', 'kid', 'typ']: return False
        if cb(hdr) != hb or hdr['alg'] != 'EdDSA' or hdr['typ'] != typ: return False
        pub = resolve(ctx, signer, hdr['kid'], d)
        if pub is None: return False
        return ed_verify(pub, (parts[0] + '.' + b64u(cb(payload))).encode(), sig)
    except Exception: return False

def jws_kid(token):
    try: return json.loads(b64u_dec(token.split('.')[0]))['kid']
    except Exception: return None

# ---------------------------------------------------------------- shape
def closed(o, req, opt=()):
    return isinstance(o, dict) and set(req) <= set(o) <= set(req) | set(opt)
def is_int(x): return isinstance(x, int) and not isinstance(x, bool)
def is_num(x): return isinstance(x, (int, float)) and not isinstance(x, bool)

POLICY_KEYS = ['minAttestors', 'requireLive', 'halfLifeMonths', 'minAttestorSittings', 'minAgreement',
               'maxInferenceDepth', 'inferenceDecay']
def policy_ok(p, with_asof=True):
    try:
        keys = POLICY_KEYS + (['asOf'] if with_asof else [])
        if not closed(p, keys, ['id']): return False
        return (is_int(p['minAttestors']) and p['minAttestors'] >= 1 and isinstance(p['requireLive'], bool)
                and is_num(p['halfLifeMonths']) and p['halfLifeMonths'] > 0
                and is_num(p['minAttestorSittings']) and p['minAttestorSittings'] >= 0
                and is_num(p['minAgreement']) and 0 <= p['minAgreement'] <= 1
                and is_int(p['maxInferenceDepth']) and p['maxInferenceDepth'] >= 0
                and is_num(p['inferenceDecay']) and 0 <= p['inferenceDecay'] <= 1
                and (not with_asof or is_date(p['asOf'])))
    except Exception: return False

SUBJ = re.compile(r'urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|urn:sanad:subject:[0-9a-f]{32,64}')
def shape_ok(c):
    try:
        if not closed(c, ['@context', 'type', 'id', 'issuer', 'validFrom', 'credentialSubject', 'evidence', 'sanad', 'proof'], ['credentialStatus']): return False
        if c['@context'] != ['https://www.w3.org/ns/credentials/v2']: return False  # GUESS
        if c['type'] != ['VerifiableCredential', 'SanadCredential']: return False      # GUESS
        if not (isinstance(c['issuer'], str) and is_dt(c['validFrom'])): return False
        cs = c['credentialSubject']
        if not (closed(cs, ['id', 'skill', 'claimedLevel']) and is_int(cs['claimedLevel']) and 0 <= cs['claimedLevel'] <= 5): return False
        if not (isinstance(c['evidence'], list) and len(c['evidence']) == 1 and
                closed(c['evidence'][0], ['type', 'id', 'bundleHash', 'alg'])): return False
        if 'credentialStatus' in c:
            st = c['credentialStatus']
            if not (closed(st, ['id', 'type', 'statusPurpose', 'statusListIndex', 'statusListCredential'])
                    and isinstance(st['statusListIndex'], str) and re.fullmatch(r'\d+', st['statusListIndex'])): return False
        if not closed(c['proof'], ['type', 'verificationMethod', 'created', 'jws']): return False
        s = c['sanad']
        if not closed(s, ['bundle', 'template', 'assessment', 'process', 'policy', 'log', 'dids']): return False
        b = s['bundle']
        if not closed(b, ['skill', 'claimedLevel', 'subject', 'evidence', 'attestations', 'attestors']): return False
        if not (is_int(b['claimedLevel']) and 0 <= b['claimedLevel'] <= 5 and isinstance(b['skill'], str)
                and isinstance(b['subject'], str) and SUBJ.fullmatch(b['subject'])): return False
        if not closed(s['template'], ['id', 'hash']) or not isinstance(s['assessment'], str): return False
        pr = s['process']
        if not closed(pr, ['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted'], ['removed', 'shortfall', 'evidenceAdded']): return False
        if not all(is_int(pr[k]) for k in ('invited', 'committed', 'revealed')): return False
        if not policy_ok(s['policy'], False) or 'id' not in s['policy']: return False
        lg = s['log']
        if not closed(lg, ['logId', 'logKey', 'entries', 'proofs', 'checkpoint']): return False
        if not all(closed(e, ['index', 'leaf']) and is_int(e['index']) and isinstance(e['leaf'], str) for e in lg['entries']): return False
        if not all(closed(p, ['index', 'size', 'proof']) and is_int(p['index']) and is_int(p['size']) and isinstance(p['proof'], list) for p in lg['proofs']): return False
        ck = lg['checkpoint']
        if not (closed(ck, ['payload', 'jws']) and closed(ck['payload'], ['logId', 'size', 'rootHash', 'timestamp']) and is_int(ck['payload']['size'])): return False
        for h in s['dids']:
            if not (closed(h, ['id', 'versions']) and isinstance(h['versions'], list)): return False
            for v in h['versions']:
                if not (closed(v, ['version', 'validFrom', 'keys', 'revoked']) and is_date(v['validFrom'])): return False
                if not all(closed(k, ['id', 'publicKeyMultibase']) for k in v['keys']): return False
                if not all(closed(r, ['id', 'from']) and is_date(r['from']) for r in v['revoked']): return False
        for e in b['evidence']:
            if not (closed(e, ['id', 'kind', 'date', 'summary', 'body', 'hash']) and isinstance(e['body'], dict)
                    and isinstance(e['id'], str) and isinstance(e['kind'], str) and isinstance(e['summary'], str)): return False
        for a in b['attestations']:
            if not (closed(a, ['id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'signature', 'commit', 'nonce', 'prev', 'hash'])
                    and isinstance(a['conflictDeclared'], bool) and isinstance(a['role'], str) and is_int(a['level'])
                    and isinstance(a['nonce'], str) and re.fullmatch(r'[A-Za-z0-9_-]{22,128}', a['nonce'])): return False
        if not all(closed(v, ['sittings', 'agreement']) for v in b['attestors'].values()): return False
        if len(b['attestations']) > 200 or len(b['evidence']) > 200 or len(lg['entries']) > 2000 or len(s['dids']) > 100: return False
        if any(len(h['versions']) > 16 or any(len(v['keys']) > 8 or len(v['revoked']) > 16 for v in h['versions']) for h in s['dids']): return False
        ids = [e['id'] for e in b['evidence']]; aids = [a['id'] for a in b['attestations']]
        return len(set(ids)) == len(ids) and len(set(aids)) == len(aids)
    except (KeyError, TypeError, AttributeError): return False

# ---------------------------------------------------------------- bundle hash, attestation hash
def att_payload(a): return {k: a[k] for k in ('id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'commit', 'nonce')}
def att_hash_obj(a): return {k: v for k, v in a.items() if k not in ('hash', 'signature')}
def commit_of(a): return chash({'attestor': a['attestor'], 'evidence': a['evidence'], 'level': a['level'], 'nonce': a['nonce']})

def bundle_hash(b):
    ev = sorted(b['evidence'], key=lambda e: u16key(e['id']))
    at = sorted(b['attestations'], key=lambda a: u16key(a['id']))
    return chash({'alg': 'sanad-0.1', 'skill': b['skill'], 'claimedLevel': b['claimedLevel'], 'subject': b['subject'],
                  'evidence': ev, 'attestations': at})

# ---------------------------------------------------------------- sitting evidence
HEX64 = re.compile(r'[0-9a-f]{64}')
LEVELS = {'A0': 0, 'A1': 1, 'A2': 2}
def sitting_check(ctx, ev, min_level, warn):
    body = ev['body']; ok = True
    def hexm(k): return isinstance(body[k], str) and HEX64.fullmatch(body[k]) is not None
    for k in ('paperFingerprint', 'strokeLogHead', 'recordingSha256'):
        if k not in body: warn.append(k)
        elif not hexm(k): ok = False
    if 'recordingCipherSha256' in body and not (hexm('recordingCipherSha256') and 'recordingSha256' in body): ok = False
    if 'recordingBytes' in body and not (is_int(body['recordingBytes']) and body['recordingBytes'] > 0 and 'recordingSha256' in body): ok = False
    if 'recordingSha256' in body and 'recordingBytes' not in body: ok = False
    if 'sittingId' in body and not (isinstance(body['sittingId'], str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,200}', body['sittingId'])): ok = False
    if 'publication' in body:
        p = body['publication']
        if not (closed(p, ['scope', 'date'], ['url']) and p['scope'] in ('hashes', 'bundle') and is_date(p['date'])
                and ('url' not in p or (isinstance(p['url'], str) and re.match(r'https?://\S+$', p['url'])))): ok = False
    ia = body.get('identityAssurance')
    if 'identityAssurance' in body:
        try:
            if 'sittingId' not in body: ok = False
            if not (closed(ia, ['level', 'method', 'checkedBy', 'date', 'candidateKey', 'signature']) and ia['level'] in LEVELS
                    and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', ia['method']) and is_date(ia['date'])): ok = False
            else:
                mb_key(ia['candidateKey'])
                payload = {'type': 'sanad-identity', 'sittingId': body.get('sittingId'), 'level': ia['level'], 'method': ia['method'],
                           'checkedBy': ia['checkedBy'], 'date': ia['date'], 'candidateKey': ia['candidateKey']}
                if not jws_verify(ctx, ia['signature'], 'sanad-identity+jws', ia['checkedBy'], payload, ia['date']): ok = False
        except Exception: ok = False
    if min_level is not None:
        # GUESS: a sitting without identityAssurance has no level and fails any minimum
        if not (isinstance(ia, dict) and LEVELS.get(ia.get('level'), -1) >= LEVELS[min_level]): ok = False
    return ok

# ---------------------------------------------------------------- recognition R1-R7
KIND_CAP = {'auto': 3, 'peer': 3, 'artifact': 4, 'sitting': 5}
KIND_W = {'sitting': 0.6, 'artifact': 0.3, 'auto': 0.25, 'peer': 0.15}
def rnd3(x): return math.floor(x * 1000 + 0.5) / 1000
def lower_median(v): s = sorted(v); return s[(len(s) - 1) // 2]

def recognise(policy, claimed, evidence, atts, stats, sigok):
    """sigok: dict attestation id -> bool, or None (skip signature check)."""
    dropped = []
    ev = sorted(evidence, key=lambda e: u16key(e['id']))
    at = sorted(atts, key=lambda a: u16key(a['id']))
    good_ev = {}
    for e in ev:
        try:
            ok = (e['kind'] in KIND_CAP and is_date(e['date']) and e['hash'] == chash(e['body']) and
                  (e['kind'] != 'auto' or (is_int(e['body'].get('autoLevel')) and 0 <= e['body']['autoLevel'] <= 5)))
        except Exception: ok = False
        if ok: good_ev[e['id']] = e
        else: dropped.append((e['id'], 'R1'))
    prev_hash = None; seen = set(); ok_atts = []
    for a in at:
        try:
            ok = (a['attestor'] != 'replay' and is_int(a['level']) and 0 <= a['level'] <= 5
                  and a['hash'] == chash(att_hash_obj(a)) and a['commit'] == commit_of(a)
                  and (sigok is None or sigok.get(a['id'], False))
                  and a['prev'] == ('GENESIS' if prev_hash is None else prev_hash)
                  and (a['attestor'], a['evidence']) not in seen
                  and a['evidence'] in good_ev and is_date(a['date']))
        except Exception: ok = False
        try:
            seen.add((a['attestor'], a['evidence'])); prev_hash = a['hash']
        except Exception: pass
        if ok: ok_atts.append(a)
        else: dropped.append((a['id'], 'R1'))
    asof = pdate(policy['asOf']); half = policy['halfLifeMonths']
    adm_ev = {}
    for eid, e in good_ev.items():
        age = (asof - pdate(e['date'])).days / 30.4375
        if age < 0 or age > 4 * half: dropped.append((eid, 'R2'))   # GUESS: >4 half-lives dropped, =4 kept
        else: adm_ev[eid] = (e, 0.5 ** (age / half))
    per_ev = {}   # id -> list of (attestor, level, isHuman)
    for eid, (e, _) in adm_ev.items():
        per_ev[eid] = [('replay', e['body']['autoLevel'], False)] if e['kind'] == 'auto' else []
    for a in ok_atts:
        if a['evidence'] not in adm_ev:
            continue  # GUESS: attestations on dropped evidence are not listed again
        st = stats.get(a['attestor'], {})
        if a['conflictDeclared'] or st.get('sittings', 0) < policy['minAttestorSittings'] or st.get('agreement', 0) < policy['minAgreement']:
            dropped.append((a['id'], 'R2')); continue
        if adm_ev[a['evidence']][0]['kind'] == 'auto': continue  # GUESS: human marks on auto evidence ignored
        per_ev[a['evidence']].append((a['attestor'], a['level'], True))
    levels = {}
    for eid, lst in per_ev.items():
        if lst: levels[eid] = min(lower_median([l for _, l, _ in lst]), KIND_CAP[adm_ev[eid][0]['kind']])
    qual = {eid: l for eid, l in levels.items() if adm_ev[eid][0]['kind'] in ('sitting', 'artifact')}
    humans = {who for eid, lst in per_ev.items() if adm_ev[eid][0]['kind'] in ('sitting', 'artifact') for who, _, h in lst if h}
    live = any(adm_ev[eid][0]['kind'] == 'sitting' for eid in qual)
    attested = min(claimed, lower_median(list(qual.values()))) if qual else None
    terms = []
    for eid, lst in per_ev.items():
        if not lst: continue
        spread = max(l for _, l, _ in lst) - min(l for _, l, _ in lst)
        g = 1 if spread <= 1 else 0.5
        for _ in lst: terms.append(KIND_W[adm_ev[eid][0]['kind']] * adm_ev[eid][1] * g)
    prod = 1.0
    for t in terms: prod *= 1 - t
    if not adm_ev:
        status, level, conf = 'not-recognised', 0, 0.0
    else:
        conf = rnd3(1 - prod) if terms else 0.0
        if len(humans) < policy['minAttestors'] or (policy['requireLive'] and not live):
            status = 'provisional'
            ap = [l for eid, l in levels.items() if adm_ev[eid][0]['kind'] in ('auto', 'peer')]
            level = min(claimed, max(ap)) if ap else 0   # GUESS: provisional level also bounded by the claim
        else:
            status, level = 'recognised', attested
    return {'status': status, 'level': level, 'attestedLevel': attested, 'confidence': conf,
            'dropped': [f'{i}:{r}' for i, r in dropped]}

# ---------------------------------------------------------------- directory + credential verification
def rj(path):
    with open(path, 'rb') as f: return json.loads(f.read().decode('utf-8'))

def verify(tree, case):
    opt = case['options']; checks = []; warnings = []
    def add(name, ok): checks.append({'name': name, 'ok': bool(ok)})
    bdir_root = os.path.join(tree, 'bundles')
    bdirs = sorted(os.listdir(bdir_root)) if os.path.isdir(bdir_root) else []
    bname = bdirs[0] if bdirs else ''
    bdir = os.path.join(bdir_root, bname)
    def load(name):
        try: return rj(os.path.join(bdir, name))
        except Exception: return None
    cred = load('credential.json')
    # --- bundle-files
    man = load('manifest.json'); ok = isinstance(man, dict)
    if ok:
        ok = closed(man, ['type', 'version', 'bundleHash', 'files']) and man['type'] == 'sanad-bundle-manifest' and man['version'] == 1 \
             and man['bundleHash'] == bname and isinstance(man['files'], dict) and 'manifest.json' not in man['files']
        if ok:
            for fn, h in man['files'].items():
                p = os.path.join(bdir, fn)
                if '/' in fn or not os.path.isfile(p) or sha(open(p, 'rb').read()) != h: ok = False
    add('bundle-files', ok)
    if not ok: return {'ok': False, 'checks': checks, 'warnings': 0, 'recognition': None}  # SPEC 11.2: stop
    shape = isinstance(cred, dict) and shape_ok(cred)
    if not shape:
        add('bundle-consistency', False); add('issuer-card', False); add('consistency-proofs', False); add('shape', False)
        return {'ok': False, 'checks': checks, 'warnings': 0, 'recognition': None}
    S = cred['sanad']; B = S['bundle']; lg = S['log']; ck = lg['checkpoint']
    ctx = Ctx(S['dids'], opt.get('pinnedKeys'))
    # --- bundle-consistency
    parts = {'evidence.json': B['evidence'], 'attestations.json': B['attestations'],
             'log.json': {'logId': lg['logId'], 'logKey': lg['logKey'], 'entries': lg['entries'], 'proofs': lg['proofs']},
             'checkpoint.json': ck, 'dids.json': S['dids']}
    ok = bname == cred['evidence'][0]['bundleHash']
    for fn, part in parts.items():
        d = load(fn)
        if d is None: ok = False; continue
        try: ok = ok and canon(d) == canon(part)
        except Exception: ok = False
    add('bundle-consistency', ok)
    if not ok: return {'ok': False, 'checks': checks, 'warnings': 0, 'recognition': None}  # SPEC 11.2: stop
    # --- issuer-card
    ok = True
    try:
        card = rj(os.path.join(tree, 'issuer.json'))
        ok = (closed(card, ['type', 'version', 'alg', 'issuer', 'logId', 'logKey', 'base', 'bundles', 'checkpoints', 'status', 'dids', 'updated', 'proof'])
              and card['type'] == 'sanad-issuer-card' and card['version'] == 1 and card['alg'] == 'sanad-0.1'
              and card['issuer'] == cred['issuer'] and card['logId'] == lg['logId'] and card['logKey'] == lg['logKey']
              and closed(card['proof'], ['type', 'verificationMethod', 'jws']) and card['proof']['verificationMethod'] == jws_kid(card['proof']['jws'])
              and jws_verify(ctx, card['proof']['jws'], 'sanad-issuer-card+jws', card['issuer'], {k: v for k, v in card.items() if k != 'proof'}, day(card['updated'])))  # GUESS: day of `updated`
    except FileNotFoundError: ok = True   # "if present"
    except Exception: ok = False
    add('issuer-card', ok)
    # --- consistency-proofs
    ok = True
    cons = load('consistency.json')
    if cons is not None:
        try:
            for ent in cons:
                f, to = ent['from'], ent['to']['checkpoint']; pl = to['payload']
                good = (f['size'] == ck['payload']['size'] and f['rootHash'] == ck['payload']['rootHash'] and pl['logId'] == lg['logId']
                        and jws_verify(ctx, to['jws'], 'sanad-checkpoint+jws', lg['logKey'], pl, day(pl['timestamp']))
                        and verify_consistency(f['size'], pl['size'], f['rootHash'], pl['rootHash'], ent['proof']))
                ok = ok and good
        except Exception: ok = False
    add('consistency-proofs', ok)
    add('shape', True)
    # --- issuer-proof
    pr = cred['proof']
    add('issuer-proof', pr['type'] == 'SanadDetachedJws' and pr['created'] == cred['validFrom'] and pr['verificationMethod'] == jws_kid(pr['jws'])
        and jws_verify(ctx, pr['jws'], 'sanad-credential+jws', cred['issuer'], {k: v for k, v in cred.items() if k != 'proof'}, day(cred['validFrom'])))
    # --- bundle-hash
    try:
        bh = bundle_hash(B); e0 = cred['evidence'][0]; cs = cred['credentialSubject']
        ok = (bh == e0['bundleHash'] and e0['id'] == 'urn:sanad:bundle:' + bh and e0['alg'] == 'sanad-0.1' and e0['type'] == ['Evidence', 'SanadBundle']
              and cs == {'id': B['subject'], 'skill': B['skill'], 'claimedLevel': B['claimedLevel']})
    except Exception: ok = False
    add('bundle-hash', ok)
    add('evidence-consistency', all(e['body'].get('kind') == e['kind'] and e['body'].get('date') == e['date'] for e in B['evidence']))
    # --- sitting-evidence
    ok = True
    for e in B['evidence']:
        if e['kind'] == 'sitting':
            w = []
            ok = sitting_check(ctx, e, opt.get('minIdentityLevel'), w) and ok
            warnings += w
    add('sitting-evidence', ok)
    pre = S['assessment'] + '.'
    add('ids', all(x['id'].startswith(pre) for x in B['evidence'] + B['attestations']))
    sigok = {}
    for a in B['attestations']:
        sigok[a['id']] = jws_verify(ctx, a['signature'], 'sanad-attestation+jws', a['attestor'], att_payload(a), a['date'])
    add('attestor-signatures', all(sigok.values()))
    add('log', check_log(ctx, cred, opt))
    if opt.get('requireWitnesses'):
        add('witnesses', check_witnesses(ctx, cred, load('witnesses.json') or [], cons or [], opt))
    ok = True
    if 'credentialStatus' in cred:
        stl = load('status.json')
        if stl is None: ok = not opt.get('requireStatus')
        else: ok = check_status(ctx, cred, stl, case.get('evaluatedAt'))
    add('revocation', ok)
    add('trusted-issuer', cred['issuer'] in opt.get('trustedIssuers', []))
    ok = lg['logKey'] in opt.get('trustedLogKeys', [])
    if 'trustedLogIds' in opt: ok = ok and lg['logId'] in opt['trustedLogIds']
    add('trusted-log-key', ok)
    if ctx.used_history_keys:
        add('did-histories', all(mb in ctx.pinned.get(d, []) for d, mb in ctx.used_history_keys))
    pc = S['process']
    try:
        ids = {a['id'] for a in B['attestations']}
        ok = (pc['revealed'] == len(B['attestations']) and pc['revealed'] <= pc['committed'] <= pc['invited']
              and len(pc['missing']) == pc['committed'] - pc['revealed'] and len(pc['notCommitted']) == pc['invited'] - pc['committed']
              and all(x in pc['missing'] for x in pc['late']) and not (set(pc['missing']) & ids))
    except Exception: ok = False
    add('process', ok)
    pol = opt.get('policy')
    ok = policy_ok(pol) if isinstance(pol, dict) else False
    if ok and (pol['minAttestorSittings'] > 0 or pol['minAgreement'] > 0) and not opt.get('ownStatistics') and not opt.get('acceptIssuerStatistics'):
        ok = False
    add('policy', ok)
    rec = None
    if isinstance(pol, dict) and policy_ok(pol):
        stats = opt.get('ownStatistics') or B['attestors']
        r = recognise(pol, B['claimedLevel'], B['evidence'], B['attestations'], stats, sigok)
        r['unverified'] = not all(c['ok'] for c in checks)
        rec = r
    return {'ok': all(c['ok'] for c in checks), 'checks': checks, 'warnings': len(warnings), 'recognition': rec}

def check_log(ctx, cred, opt):
    S = cred['sanad']; lg = S['log']; ck = lg['checkpoint']; pl = ck['payload']
    try:
        if not jws_verify(ctx, ck['jws'], 'sanad-checkpoint+jws', lg['logKey'], pl, day(pl['timestamp'])): return False
        if pl['logId'] != lg['logId']: return False
        if 'trustedLogIds' in opt and lg['logId'] not in opt['trustedLogIds']: return False
        proofs = {p['index']: p for p in lg['proofs']}
        leaves = []
        for e in lg['entries']:
            t = e['leaf']; o = json.loads(t)
            if not (closed(o, ['kind', 'ref', 'ts']) and o['kind'] in ('commit', 'attestation', 'missing-reveal', 'bundle')
                    and isinstance(o['ref'], str) and HEX64.fullmatch(o['ref']) and is_dt(o['ts'])) or canon(o) != t: return False
            p = proofs.get(e['index'])
            if not p or p['size'] != pl['size'] or not verify_inclusion(t, e['index'], pl['size'], p['proof'], pl['rootHash']): return False
            leaves.append(o)
        att = {o['ref'] for o in leaves if o['kind'] == 'attestation'}
        bun = {o['ref'] for o in leaves if o['kind'] == 'bundle'}
        return all(a['hash'] in att for a in S['bundle']['attestations']) and cred['evidence'][0]['bundleHash'] in bun
    except Exception: return False

def check_witnesses(ctx, cred, wits, cons, opt):
    lg = cred['sanad']['log']; ck = lg['checkpoint']['payload']; counted = set()
    for w in wits:
        try:
            cp = w['checkpoint']; pl = cp['payload']; cs = w['cosignature']
            if cs['witness'] not in opt.get('trustedWitnesses', []): continue
            if not jws_verify(ctx, cp['jws'], 'sanad-checkpoint+jws', lg['logKey'], pl, day(pl['timestamp'])): continue
            if pl['logId'] != lg['logId']: continue
            pay = {'type': 'sanad-cosignature', 'logId': pl['logId'], 'size': pl['size'], 'rootHash': pl['rootHash'],
                   'timestamp': pl['timestamp'], 'logKey': lg['logKey'], 'witness': cs['witness'], 'witnessedAt': cs['witnessedAt']}
            if not jws_verify(ctx, cs['jws'], 'sanad-cosignature+jws', cs['witness'], pay, day(cs['witnessedAt'])): continue
            if pl['size'] == ck['size']:
                good = pl['rootHash'] == ck['rootHash']
            elif pl['size'] > ck['size']:
                # GUESS: the proof comes from consistency.json (witnesses.json has no proof field)
                good = any(e['to']['checkpoint']['payload']['size'] == pl['size'] and e['to']['checkpoint']['payload']['rootHash'] == pl['rootHash']
                           and e['from']['size'] == ck['size'] and e['from']['rootHash'] == ck['rootHash']
                           and verify_consistency(ck['size'], pl['size'], ck['rootHash'], pl['rootHash'], e['proof']) for e in cons)
            else: good = False
            if good: counted.add(cs['witness'])
        except Exception: continue
    return len(counted) >= opt['requireWitnesses']

def check_status(ctx, cred, stl, evaluated_at):
    try:
        st = cred['credentialStatus']
        if not (closed(stl, ['@context', 'id', 'type', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'proof'])
                and stl['id'] == st['statusListCredential'] and stl['issuer'] == cred['issuer']
                and stl['type'] == ['VerifiableCredential', 'BitstringStatusListCredential']): return False
        sub = stl['credentialSubject']
        if not (closed(sub, ['id', 'type', 'statusPurpose', 'encodedList']) and sub['type'] == 'BitstringStatusList' and sub['statusPurpose'] == 'revocation'
                and sub['id'] == stl['id'] + '#list'): return False
        pr = stl['proof']
        if not jws_verify(ctx, pr['jws'], 'sanad-status-list+jws', stl['issuer'], {k: v for k, v in stl.items() if k != 'proof'}, day(stl['validFrom'])): return False  # GUESS date
        if not (stl['validFrom'] <= evaluated_at <= stl['validUntil']): return False   # same ISO format -> lexicographic
        enc = sub['encodedList']
        if not enc.startswith('u'): return False
        bits = gzip.decompress(b64u_dec(enc[1:]))
        if len(bits) * 8 < 131072: return False
        i = int(st['statusListIndex'])
        if i >= len(bits) * 8: return False
        return not (bits[i // 8] >> (7 - i % 8)) & 1
    except Exception: return False

def main():
    a = sys.argv[1:]
    tree = a[0]; case = rj(a[a.index('--case') + 1])
    print(json.dumps(verify(tree, case), indent=2))
if __name__ == '__main__': main()

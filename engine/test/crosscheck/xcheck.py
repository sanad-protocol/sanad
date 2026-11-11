#!/usr/bin/env python3
# Independent verifier for a Sanad engine credential. Written from SPEC-v0.1 and engine/DESIGN.md only; it does NOT import or read engine code. Python 3 standard library only.
import sys, json, hashlib, base64, re, math, datetime
# ---------- RFC 8032 Ed25519 verify (pure python, cofactorless, strict S<L) ----------
p=2**255-19; L=2**252+27742317777372353535851937790883648493
d=-121665*pow(121665+0,-1,p)%p  # -121665/121666 computed below properly
d=(-121665*pow(121666,-1,p))%p
I=pow(2,(p-1)//4,p)
def recover_x(y,sign):
    if y>=p: return None
    x2=(y*y-1)*pow(d*y*y+1,-1,p)%p
    if x2==0: return None if sign else 0
    x=pow(x2,(p+3)//8,p)
    if (x*x-x2)%p!=0: x=x*I%p
    if (x*x-x2)%p!=0: return None
    if (x&1)!=sign: x=p-x
    return x
By=4*pow(5,-1,p)%p; Bx=recover_x(By,0); B=(Bx,By,1,Bx*By%p)
def add(P,Q):
    A=(P[1]-P[0])*(Q[1]-Q[0])%p; Bb=(P[1]+P[0])*(Q[1]+Q[0])%p; C=2*P[3]*Q[3]*d%p; D=2*P[2]*Q[2]%p
    E,F,G,H=Bb-A,D-C,D+C,Bb+A
    return (E*F%p,G*H%p,F*G%p,E*H%p)
def mul(s,P):
    Q=(0,1,1,0)
    while s>0:
        if s&1: Q=add(Q,P)
        P=add(P,P); s>>=1
    return Q
def eq(P,Q): return (P[0]*Q[2]-Q[0]*P[2])%p==0 and (P[1]*Q[2]-Q[1]*P[2])%p==0
def dec(s):
    y=int.from_bytes(s,'little'); sign=y>>255; y&=(1<<255)-1
    x=recover_x(y,sign)
    return None if x is None else (x,y,1,x*y%p)
def ed_verify(pub,msg,sig):
    if len(pub)!=32 or len(sig)!=64: return False
    A=dec(pub); R=dec(sig[:32]); S=int.from_bytes(sig[32:],'little')
    if A is None or R is None or S>=L: return False
    k=int.from_bytes(hashlib.sha512(sig[:32]+pub+msg).digest(),'little')%L
    return eq(mul(S,B),add(R,mul(k,A)))
# ---------- helpers ----------
def b64u_dec(s):
    assert re.fullmatch(r'[A-Za-z0-9_-]*',s), 'bad b64u'
    raw=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    assert base64.urlsafe_b64encode(raw).decode().rstrip('=')==s, 'non-canonical b64u'
    return raw
def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def u16key(k): return k.encode('utf-16-be')
from decimal import Decimal
def es_num(v):
    # ECMAScript Number::toString (RFC 8785 3.2.2.3) from Python's shortest round-trip repr
    if v==0: return '0'
    sgn='-' if v<0 else ''; v=abs(v)
    dg=Decimal(repr(v)).as_tuple(); digits=''.join(map(str,dg.digits)).rstrip('0') or '0'
    n=len(dg.digits)+dg.exponent  # decimal point position relative to digit string start
    # strip trailing zeros effect on n is none; leading zeros cannot occur
    k=len(digits)
    if k<=n<=21: out=digits+'0'*(n-k)
    elif 0<n<=21: out=digits[:n]+'.'+digits[n:]
    elif -6<n<=0: out='0.'+'0'*(-n)+digits
    else:
        e=n-1; es=('+' if e>=0 else '-')+str(abs(e))
        out=digits[0]+('.'+digits[1:] if k>1 else '')+'e'+es
    return sgn+out
def canon(v):
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v,str): return json.dumps(v,ensure_ascii=False)
    if isinstance(v,int): return str(v)
    if isinstance(v,float): return es_num(v)
    if isinstance(v,list): return '['+','.join(canon(x) for x in v)+']'
    if isinstance(v,dict): return '{'+','.join(json.dumps(k,ensure_ascii=False)+':'+canon(v[k]) for k in sorted(v,key=u16key))+'}'
    raise TypeError(type(v))
sha=lambda s: hashlib.sha256(s.encode('utf-8') if isinstance(s,str) else s).hexdigest()
ALPH='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58dec(s):
    n=0
    for c in s: n=n*58+ALPH.index(c)
    z=len(s)-len(s.lstrip('1'))
    body=n.to_bytes((n.bit_length()+7)//8,'big') if n else b''
    return b'\0'*z+body
def didkey_pub(did):
    assert did.startswith('did:key:z'); raw=b58dec(did[9:]); assert raw[:2]==b'\xed\x01' and len(raw)==34, 'not ed25519 did:key'
    return raw[2:]
def verify_jws(jws,payload,typ,signer_did,pub=None):
    h,mid,sg=jws.split('.'); assert mid=='' , 'attached payload'
    hb=b64u_dec(h); hdr=json.loads(hb.decode('utf-8'))
    assert hb.decode()==canon(hdr), 'header not canonical'
    assert sorted(hdr)==['alg','kid','typ'] and hdr['alg']=='EdDSA' and hdr['typ']==typ
    assert hdr['kid'].startswith(signer_did+'#')
    if pub is None:
        assert signer_did.startswith('did:key:'), 'only did:key resolved in this checker'
        assert hdr['kid']==signer_did+'#'+signer_did[8:]; pub=didkey_pub(signer_did)
    sig=b64u_dec(sg); assert len(sig)==64
    return ed_verify(pub,(h+'.'+b64u(canon(payload).encode())).encode(),sig)
# ---------- RFC 9162 ----------
def nh(l,r): return hashlib.sha256(b'\x01'+bytes.fromhex(l)+bytes.fromhex(r)).hexdigest()
def verify_incl(lh,idx,size,proof,root):
    if idx>=size: return False
    fn,sn,r=idx,size-1,lh
    for q in proof:
        if sn==0: return False
        if fn&1 or fn==sn:
            r=nh(q,r)
            if not fn&1:
                while not fn&1 and fn!=0: fn>>=1; sn>>=1
        else: r=nh(r,q)
        fn>>=1; sn>>=1
    return sn==0 and r==root
# ---------- recognition (spec section 5 as written) ----------
def daynum(s): return datetime.date.fromisoformat(s).toordinal()
def recognise(b,pol,month=365.2425/12):
    ev={e['id']:e for e in b['evidence']}; atts=b['attestations']
    asof=daynum(pol['asOf']); cap={'auto':3,'peer':3,'artifact':4,'sitting':5}; W={'sitting':.6,'artifact':.3,'auto':.25,'peer':.15}
    lowmed=lambda xs: sorted(xs)[(len(xs)-1)//2]
    adm={}
    for i,e in ev.items():
        age=(asof-daynum(e['date']))/month
        if age<0 or age>4*pol['halfLifeMonths']: continue
        adm[i]=(e,age)
    items={}
    for i,(e,age) in adm.items():
        if e['kind']=='auto': items.setdefault(i,[]).append(('replay',e['body']['autoLevel']))
    for a in atts:
        if a['evidence'] not in adm or adm[a['evidence']][0]['kind']=='auto': continue
        st=b['attestors'].get(a['attestor'],{'sittings':0,'agreement':0})
        if a['conflictDeclared'] or st['sittings']<pol['minAttestorSittings'] or st['agreement']<pol['minAgreement']: continue
        items.setdefault(a['evidence'],[]).append((a['attestor'],a['level']))
    lv={i:min(lowmed([x[1] for x in its]),cap[adm[i][0]['kind']]) for i,its in items.items()}
    spread={i:max(x[1] for x in its)-min(x[1] for x in its) for i,its in items.items()}
    qual=[i for i in lv if adm[i][0]['kind'] in('sitting','artifact')]
    n=len({x[0] for i in qual for x in items[i]}); live=any(adm[i][0]['kind']=='sitting' for i in qual)
    indep=bool(qual) and n>=max(1,math.floor(pol['minAttestors'])) and (live or not pol['requireLive'])
    if not lv: status,level='not-recognised',0
    elif indep: status,level='recognised',min(b['claimedLevel'],lowmed([lv[i] for i in qual]))
    else:
        weak=[lv[i] for i in lv if i not in qual]; status,level='provisional',min(b['claimedLevel'],max(weak) if weak else 0)
    miss=1.0
    for i,its in items.items():
        a=0.5**(adm[i][1]/pol['halfLifeMonths']); g=1 if spread[i]<=1 else .5
        for _ in its: miss*=1-W[adm[i][0]['kind']]*a*g
    return status,level,(round(1-miss,3) if lv else 0)
# ---------- main ----------
def check(path,pol):
    c=json.load(open(path)); res=[]
    def ok(name,v,detail=''): res.append((name,bool(v),detail)); 
    sn=c['sanad']; b=sn['bundle']
    body={k:v for k,v in c.items() if k!='proof'}
    day=c['validFrom'][:10]
    ok('issuer JWS (typ sanad-credential+jws, payload = doc minus proof)',verify_jws(c['proof']['jws'],body,'sanad-credential+jws',c['issuer']) and c['proof']['verificationMethod']==c['issuer']+'#'+c['issuer'][8:])
    for e in b['evidence']:
        ok('evidence hash '+e['id'],sha(canon(e['body']))==e['hash'])
        ok('evidence kind/date mirrored '+e['id'],e['body'].get('kind')==e['kind'] and e['body'].get('date')==e['date'])
    prev='GENESIS'
    for a in sorted(b['attestations'],key=lambda x:u16key(x['id'])):
        ok('commit binding '+a['id'],sha(canon({'attestor':a['attestor'],'evidence':a['evidence'],'level':a['level'],'nonce':a['nonce']}))==a['commit'])
        h=sha(canon({k:v for k,v in a.items() if k not in('hash','signature')}))
        ok('attestation hash (spec 4.2: all but hash and sig) '+a['id'],h==a['hash'])
        ok('chain link '+a['id'],a['prev']==prev); prev=a['hash']
        stmt={k:a[k] for k in('id','attestor','evidence','level','role','conflictDeclared','date','commit','nonce')}
        ok('attestor JWS '+a['id'],verify_jws(a['signature'],stmt,'sanad-attestation+jws',a['attestor']))
    bh=sha(canon({'alg':'sanad-0.1','skill':b['skill'],'claimedLevel':b['claimedLevel'],'subject':b['subject'],
        'evidence':sorted(b['evidence'],key=lambda x:u16key(x['id'])),'attestations':sorted(b['attestations'],key=lambda x:u16key(x['id']))}))
    ok('bundleHash',bh==c['evidence'][0]['bundleHash'])
    lg=sn['log']; cp=lg['checkpoint']
    ok('checkpoint JWS',verify_jws(cp['jws'],cp['payload'],'sanad-checkpoint+jws',lg['logKey']) and cp['payload']['logId']==lg['logId'])
    leaves={}
    for e in lg['entries']:
        pr=[x for x in lg['proofs'] if x['index']==e['index']][0]
        lh=hashlib.sha256(b'\0'+e['leaf'].encode()).hexdigest()
        ok('inclusion proof leaf %d'%e['index'],verify_incl(lh,e['index'],pr['size'],pr['proof'],cp['payload']['rootHash']) and pr['size']==cp['payload']['size'])
        lf=json.loads(e['leaf']); ok('leaf canonical %d'%e['index'],canon(lf)==e['leaf']); leaves[(lf['kind'],lf['ref'])]=lf['ts']
    for a in b['attestations']: ok('attestation leaf in log '+a['id'],('attestation',a['hash']) in leaves)
    ok('bundle leaf in log',('bundle',bh) in leaves)
    # extra: commit-before-reveal ordering reconstructable from the credential? (commit leaf ref = H(canon(commit statement)))
    first_att=min((i for i,e in enumerate(lg['entries']) if json.loads(e['leaf'])['kind']=='attestation'),default=None)
    cm=[]
    for a in b['attestations']:
        stmt={'type':'sanad-commit','assessment':sn['assessment'],'attestationId':a['id'],'attestor':a['attestor'],'evidence':a['evidence'],'role':a['role'],'commit':a['commit'],'templateHash':sn['template']['hash']}
        cm.append(('commit',sha(canon(stmt))) in leaves)
    ok('commit leaves reconstructable from credential data and logged (no commit JWS available to verify)',all(cm),'%d/%d'%(sum(cm),len(cm)))
    # recognition
    st,lvl,conf=recognise(b,pol)
    return res,(st,lvl,conf)
if __name__=='__main__':
    pol={'minAttestors':2,'requireLive':True,'halfLifeMonths':36,'minAttestorSittings':0,'minAgreement':0,'maxInferenceDepth':2,'inferenceDecay':0.8,'asOf':sys.argv[3] if len(sys.argv)>3 else '2026-03-03'}
    res,rec=check(sys.argv[1],pol)
    bad=[r for r in res if not r[1]]
    for n,v,dtl in res: print(('PASS ' if v else 'FAIL ')+n+(' '+dtl if dtl else ''))
    print('python recognition',rec,'| failures:',len(bad))

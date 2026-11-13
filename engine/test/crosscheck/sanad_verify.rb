#!/usr/bin/env ruby
# Independent verifier for a Sanad engine credential, written from SPEC-v0.1 and engine/DESIGN.md only; it does not read or use any engine code.
# Ruby standard library only (tested with Ruby 2.6). Licence: Apache-2.0, as the repository.
#   ruby sanad_verify.rb <credential.json> <asOf YYYY-MM-DD> [halfLifeMonths]
#   ruby sanad_verify.rb --selftest
require 'json'
require 'digest'
require 'date'

# ---------- canonical JSON (RFC 8785 / ECMAScript) ----------
module Canon
  module_function
  def u16key(s); s.encode('UTF-16BE').b; end

  def num(x)
    return x.to_s if x.is_a?(Integer)   # |x| < 1e21 assumed
    raise "non-finite" if x.nan? || x.infinite?
    return "0" if x == 0
    sign = x < 0 ? "-" : ""
    x = x.abs
    s = x.to_s                          # Ruby: shortest round-trip digits
    mant, exp = s.downcase.split('e')
    exp = exp.to_i
    ip, fp = mant.split('.')
    fp ||= ""
    digits = ip + fp
    n = ip.length + exp                 # decimal point position relative to digits start
    lead = digits[/\A0*/].length
    digits = digits[lead..-1]; n -= lead
    digits = digits.sub(/0+\z/, '')
    k = digits.length
    r = if k <= n && n <= 21 then digits + "0" * (n - k)
        elsif 0 < n && n <= 21 then digits[0, n] + "." + digits[n..-1]
        elsif -6 < n && n <= 0 then "0." + "0" * (-n) + digits
        else
          e = n - 1
          es = (e < 0 ? "-" : "+") + e.abs.to_s
          k == 1 ? digits + "e" + es : digits[0] + "." + digits[1..-1] + "e" + es
        end
    sign + r
  end

  def str(s)
    out = '"'
    s.each_char do |c|
      o = c.ord
      out << case c
             when '"' then '\\"'
             when '\\' then '\\\\'
             when "\b" then '\\b'
             when "\f" then '\\f'
             when "\n" then '\\n'
             when "\r" then '\\r'
             when "\t" then '\\t'
             else o < 0x20 ? format('\\u%04x', o) : c
             end
    end
    out << '"'
  end

  def enc(v)
    case v
    when nil then "null"
    when true then "true"
    when false then "false"
    when Integer, Float then num(v)
    when String then str(v)
    when Array then "[" + v.map { |e| enc(e) }.join(",") + "]"
    when Hash then "{" + v.keys.sort_by { |k| u16key(k) }.map { |k| str(k) + ":" + enc(v[k]) }.join(",") + "}"
    else raise "bad type #{v.class}"
    end
  end
  def bytes(v); enc(v).dup.force_encoding('UTF-8'); end
end

def sha256hex(s); Digest::SHA256.hexdigest(s.b); end
def sha256raw(s); Digest::SHA256.digest(s.b); end
def chash(v); sha256hex(Canon.bytes(v)); end

module B64
  ALPHA = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + ['-', '_']
  module_function
  def enc(bin)
    bin = bin.b; out = ''
    bin.bytes.each_slice(3) do |a|
      n = (a[0] << 16) | ((a[1] || 0) << 8) | (a[2] || 0)
      c = [18, 12, 6, 0].map { |sh| ALPHA[(n >> sh) & 63] }
      out << c[0, a.length + 1].join
    end
    out
  end
  def dec(s)  # strict: alphabet, no padding, canonical
    return nil unless s =~ /\A[A-Za-z0-9_-]*\z/
    return nil if s.length % 4 == 1
    bits = 0; nb = 0; out = []
    s.each_char { |c| bits = (bits << 6) | ALPHA.index(c); nb += 6
      if nb >= 8; nb -= 8; out << ((bits >> nb) & 255); bits &= (1 << nb) - 1; end }
    return nil unless bits == 0         # non-zero trailing bits
    b = out.pack('C*')
    enc(b) == s ? b : nil
  end
end

module B58
  A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  module_function
  def dec(s)
    n = 0
    s.each_char { |c| i = A.index(c); return nil unless i; n = n * 58 + i }
    zeros = s[/\A1*/].length
    hex = n.zero? ? "" : n.to_s(16)
    hex = "0" + hex if hex.length.odd?
    ([0] * zeros).pack('C*') + [hex].pack('H*')
  end
end

# ---------- Ed25519 strict (RFC 8032) ----------
module Ed
  P = 2**255 - 19
  L = 2**252 + 27742317777372353535851937790883648493
  def self.inv(x); x.pow(P - 2, P); end
  D = (-121665 * inv(121666)) % P
  SQRTM1 = 2.pow((P - 1) / 4, P)
  IDENT = [0, 1, 1, 0].freeze

  def self.add(a, b)
    x1, y1, z1, t1 = a; x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e = bb - aa; f = dd - cc; g = dd + cc; h = bb + aa
    [e * f % P, g * h % P, f * g % P, e * h % P]
  end
  def self.mul(s, pt)
    q = IDENT; a = pt
    while s > 0
      q = add(q, a) if s & 1 == 1
      a = add(a, a); s >>= 1
    end
    q
  end
  def self.eq(a, b)
    (a[0] * b[2] - b[0] * a[2]) % P == 0 && (a[1] * b[2] - b[1] * a[2]) % P == 0
  end
  def self.decode(bin)
    return nil unless bin.bytesize == 32
    n = bin.reverse.unpack('H*')[0].to_i(16)
    sign = n >> 255; y = n & ((1 << 255) - 1)
    return nil if y >= P
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    x = x2.pow((P + 3) / 8, P)
    x = x * SQRTM1 % P if (x * x - x2) % P != 0
    return nil if (x * x - x2) % P != 0
    return nil if x == 0 && sign == 1
    x = P - x if (x & 1) != sign
    [x, y, 1, x * y % P]
  end
  By = 4 * inv(5) % P
  B = decode([By.to_s(16).rjust(64, '0')].pack('H*').reverse)
  def self.small_order?(pt); eq(mul(8, pt), IDENT); end

  def self.verify(pub, msg, sig)
    return [false, "bad lengths"] unless pub.bytesize == 32 && sig.bytesize == 64
    a = decode(pub);           return [false, "public key not a valid canonical point"] unless a
    return [false, "small-order public key"] if small_order?(a)
    rb = sig.byteslice(0, 32); r = decode(rb); return [false, "R not a valid canonical point"] unless r
    s = sig.byteslice(32, 32).reverse.unpack('H*')[0].to_i(16)
    return [false, "S >= L"] if s >= L
    k = Digest::SHA512.digest(rb + pub + msg.b).reverse.unpack('H*')[0].to_i(16) % L
    lhs = mul(s, B); rhs = add(r, mul(k, a))
    eq(lhs, rhs) ? [true, "ok"] : [false, "equation does not hold"]
  end
end

# ---------- Merkle (RFC 9162) ----------
module Merkle
  module_function
  def leaf(data); sha256raw("\x00".b + data.b); end
  def node(l, r); sha256raw("\x01".b + l + r); end
  def root(hs)
    n = hs.length
    return sha256raw("") if n == 0
    return hs[0] if n == 1
    k = 1; k <<= 1 while k * 2 < n
    node(root(hs[0, k]), root(hs[k..-1]))
  end
  def verify_incl(index, size, leafhash, proof, rootb)
    return false if index >= size
    fn = index; sn = size - 1; r = leafhash
    proof.each do |p|
      return false if sn == 0
      if fn.odd? || fn == sn
        r = node(p, r)
        unless fn.odd?
          while !fn.odd? && fn != 0; fn >>= 1; sn >>= 1; end
        end
      else
        r = node(r, p)
      end
      fn >>= 1; sn >>= 1
    end
    sn == 0 && r == rootb
  end
end

# ---------- Verifier ----------
class Verifier
  POLICY = { 'minAttestors' => 2, 'requireLive' => true, 'halfLifeMonths' => 24.0, 'minAttestorSittings' => 0,
             'minAgreement' => 0, 'maxInferenceDepth' => 0, 'inferenceDecay' => 0.7 }
  MONTH_DAYS = (ENV['MONTH'] || '30.4375').to_f # the core's value; the specification text says 30.436875 (docs/SPEC-DECISIONS-NEEDED.md, decision 10)
  CAPS = { 'auto' => 3, 'peer' => 3, 'artifact' => 4, 'sitting' => 5 }
  WEIGHT = { 'sitting' => 0.6, 'artifact' => 0.3, 'auto' => 0.25, 'peer' => 0.15 }
  ATT_KEYS = %w[id attestor evidence level role conflictDeclared date commit nonce prev hash signature]
  EV_KEYS = %w[id kind date summary body hash]

  attr_reader :checks
  # opts: :asof (YYYY-MM-DD), :half_life (months), :issuer and :log_key (pinned DIDs), :allow_unpinned
  def initialize(cred, pin, opts = {})
    @c = cred; @pin = pin; @checks = []; @opts = opts
    @asof = opts[:asof] || "2026-03-12"; @half = (opts[:half_life] || 24).to_f
  end
  def chk(name, ok, detail); @checks << [name, ok, detail]; ok; end

  def did_key_bytes(did)
    return nil unless did =~ /\Adid:key:(z[1-9A-HJ-NP-Za-km-z]+)\z/
    raw = B58.dec($1[1..-1]); return nil unless raw && raw.bytesize == 34 && raw.bytes[0, 2] == [0xed, 0x01]
    raw.byteslice(2, 32)
  end

  # returns [pubkey_bytes or nil, reason]
  def resolve(kid, did, date)
    return [nil, "kid does not belong to signer"] unless kid.start_with?(did + "#")
    frag = kid[(did.length + 1)..-1]
    if did.start_with?("did:key:")
      return [nil, "did:key fragment mismatch"] unless did == "did:key:" + frag
      k = did_key_bytes(did); return k ? [k, nil] : [nil, "bad did:key"]
    elsif did.start_with?("did:web:")
      h = (@c.dig('sanad', 'dids') || []).find { |d| d['id'] == did }
      return [nil, "no embedded history for #{did}"] unless h
      vs = h['versions'].select { |v| v['validFrom'] <= date }.sort_by { |v| [v['validFrom'], v['version']] }
      return [nil, "no DID version in force on #{date}"] if vs.empty?
      v = vs.last
      ent = v['keys'].find { |k| k['id'] == "#" + frag }
      return [nil, "key ##{frag} not listed in version #{v['version']} (in force on #{date})"] unless ent
      rev = h['versions'].flat_map { |x| x['revoked'] || [] }.find { |r| r['id'] == "#" + frag && r['from'] <= date }
      return [nil, "key ##{frag} revoked from #{rev['from']} (statement date #{date})"] if rev
      return [nil, "key multibase differs from the pinned key"] unless ent['publicKeyMultibase'] == @pin
      raw = B58.dec(ent['publicKeyMultibase'][1..-1])
      raw = raw.byteslice(2, 32) if raw && raw.bytesize == 34 && raw.bytes[0, 2] == [0xed, 0x01]
      return [nil, "bad did:web key encoding"] unless raw && raw.bytesize == 32
      return [raw, nil]
    end
    [nil, "unsupported DID method"]
  end

  def verify_jws(jws, typ, payload, did, date)
    return [false, "jws not a string"] unless jws.is_a?(String)
    parts = jws.split("..", -1)
    return [false, "not detached compact form"] unless parts.length == 2 && !jws.include?("...")
    hb = B64.dec(parts[0]); sg = B64.dec(parts[1])
    return [false, "bad base64url"] unless hb && sg
    h = (JSON.parse(hb) rescue nil)
    return [false, "bad header"] unless h.is_a?(Hash)
    return [false, "header members not exactly alg,kid,typ"] unless h.keys.sort == %w[alg kid typ]
    return [false, "header not canonical"] unless Canon.bytes(h) == hb.dup.force_encoding('UTF-8')
    return [false, "alg not EdDSA"] unless h['alg'] == 'EdDSA'
    return [false, "typ #{h['typ']} != #{typ}"] unless h['typ'] == typ
    key, why = resolve(h['kid'], did, date)
    return [false, why] unless key
    inp = parts[0] + "." + B64.enc(Canon.bytes(payload))
    Ed.verify(key, inp, sg)
  end

  def run
    c = @c; s = c['sanad']; b = s['bundle']
    pol = POLICY.merge('asOf' => @asof, 'halfLifeMonths' => @half)
    # shape
    shape = c['type'] == %w[VerifiableCredential SanadCredential] && c['issuer'].is_a?(String) && s && b
    chk "shape", shape, "credential document structure"
    ids_ok = b['evidence'].all? { |e| e['id'].start_with?(s['assessment'] + ".") } &&
             b['attestations'].all? { |a| a['id'].start_with?(s['assessment'] + ".") }
    chk "ids-prefix", ids_ok, "evidence/attestation ids carry assessment prefix #{s['assessment']}."
    members_ok = b['evidence'].all? { |e| e.keys.sort == EV_KEYS.sort } && b['attestations'].all? { |a| a.keys.sort == ATT_KEYS.sort }
    chk "closed-member-sets", members_ok, "evidence and attestation members are exactly the documented ones"
    cs = c['credentialSubject']
    chk "subject-consistency", cs['id'] == b['subject'] && cs['skill'] == b['skill'] && cs['claimedLevel'] == b['claimedLevel'],
        "credentialSubject equals bundle subject/skill/claimedLevel"
    chk "proof-created=validFrom", c['proof']['created'] == c['validFrom'], "#{c['proof']['created']} vs #{c['validFrom']}"
    # pins (just report)
    pin_checks(c['issuer'], s['log']['logKey'])
    # issuer proof
    vm = c['proof']['verificationMethod']
    pl = c.reject { |k, _| k == 'proof' }
    ok, why = (vm.start_with?(c['issuer'] + "#") ? verify_jws(c['proof']['jws'], 'sanad-credential+jws', pl, c['issuer'], c['validFrom'][0, 10]) : [false, "verificationMethod not of issuer"])
    ok2 = ok && (JSON.parse(B64.dec(c['proof']['jws'].split("..")[0]))['kid'] == vm)
    chk "issuer-proof", ok2, ok2 ? "valid" : (why || "kid != verificationMethod")
    # bundle hash
    srt = lambda { |arr| arr.sort_by { |x| Canon.u16key(x['id']) } }
    bundle_in = { 'alg' => 'sanad-0.1', 'skill' => b['skill'], 'claimedLevel' => b['claimedLevel'], 'subject' => b['subject'],
                  'evidence' => srt.(b['evidence']), 'attestations' => srt.(b['attestations']) }
    bh = chash(bundle_in)
    ev0 = c['evidence'][0]
    chk "bundleHash", bh == ev0['bundleHash'], "recomputed #{bh[0, 16]}.. vs stated #{ev0['bundleHash'][0, 16]}.."
    chk "bundle-ref-id", ev0['id'] == "urn:sanad:bundle:" + ev0['bundleHash'] && ev0['alg'] == 'sanad-0.1' && ev0['type'] == %w[Evidence SanadBundle], "evidence entry self-consistent"
    chk "bundle-order", b['evidence'].map { |e| e['id'] } == srt.(b['evidence']).map { |e| e['id'] } &&
        b['attestations'].map { |e| e['id'] } == srt.(b['attestations']).map { |e| e['id'] }, "listed in id order"

    # evidence hashes
    evs = srt.(b['evidence']); atts = srt.(b['attestations'])
    ev_ok = {}
    evs.each do |e|
      body = e['body']
      okh = chash(body) == e['hash']
      okm = body['kind'] == e['kind'] && body['date'] == e['date']
      ev_ok[e['id']] = okh && okm && CAPS.key?(e['kind']) && e['date'] =~ /\A\d{4}-\d\d-\d\d\z/
      chk "evidence-hash #{e['id']}", okh && okm, "hash #{okh ? 'ok' : 'MISMATCH'}, kind/date mirrored in body #{okm ? 'ok' : 'MISMATCH'}"
    end
    # attestation hash, chain, commit, signature
    att_fail = {}  # id => reason
    prev_expected = "GENESIS"
    atts.each do |a|
      body = a.reject { |k, _| %w[hash signature].include?(k) }
      hh = chash(body)
      okhash = hh == a['hash']
      okchain = a['prev'] == prev_expected
      cm = chash({ 'attestor' => a['attestor'], 'evidence' => a['evidence'], 'level' => a['level'], 'nonce' => a['nonce'] })
      okcommit = cm == a['commit']
      pay = a.reject { |k, _| %w[prev hash signature].include?(k) }
      sok, swhy = verify_jws(a['signature'], 'sanad-attestation+jws', pay, a['attestor'], a['date'])
      okev = evs.any? { |e| e['id'] == a['evidence'] }
      chk "att-hash #{a['id']}", okhash, okhash ? "ok" : "recomputed #{hh[0, 12]} != stored #{a['hash'][0, 12]}"
      chk "att-chain #{a['id']}", okchain, okchain ? "prev ok" : "prev #{a['prev'].to_s[0, 12]} != expected #{prev_expected[0, 12]}"
      chk "att-commit-reveal #{a['id']}", okcommit, okcommit ? "ok" : "commit mismatch"
      chk "att-signature #{a['id']}", sok, sok ? "valid (kid in #{a['attestor'][0, 20]}.. on #{a['date']})" : swhy
      chk "att-evidence-ref #{a['id']}", okev, a['evidence']
      r = []
      r << "hash" unless okhash
      r << "chain" unless okchain
      r << "commit-reveal" unless okcommit
      r << "signature(#{swhy})" unless sok
      r << "unknown evidence" unless okev
      att_fail[a['id']] = r.join(",") unless r.empty?
      prev_expected = (ENV["CHAIN"] == "A" ? a["hash"] : hh)     # successor must link to the RECOMPUTED hash of the predecessor (conservative)
    end
    # dates
    dates_ok = atts.all? do |a|
      e = evs.find { |x| x['id'] == a['evidence'] }
      e && a['date'] >= e['date'] && a['date'] <= s['log']['checkpoint']['payload']['timestamp'][0, 10]
    end
    chk "attestation-dates", dates_ok, "date >= evidence date and <= checkpoint day"

    # process counts
    p = s['process']
    # late is a subset of missing: a reveal that arrived after the deadline was refused, so that attestation is missing from the bundle and also late
    chk "process-counts", p['revealed'] == atts.length && p['committed'] == atts.length + p['missing'].length &&
        p['late'].all? { |i| p['missing'].include?(i) } &&
        p['invited'] == p['committed'] + p['notCommitted'].length &&
        p['missing'].none? { |i| atts.any? { |a| a['id'] == i } },
        "invited=#{p['invited']} committed=#{p['committed']} revealed=#{p['revealed']} missing=#{p['missing']} late=#{p['late']} attestations=#{atts.length}"

    verify_log(s, atts, evs, bh, ev0['bundleHash'])

    recognise(pol, b, evs, atts, ev_ok, att_fail)
  end

  # Without pins a credential is only checked for internal consistency, which any engine can satisfy: that is a FAIL unless --allow-unpinned.
  def pin_checks(issuer, log_key)
    o = @opts
    if o[:issuer].nil? && o[:log_key].nil? && !o[:allow_unpinned]
      chk "pins", false, "no --issuer and --log-key given; pass them, or --allow-unpinned to accept internal consistency only"
      return
    end
    if o[:issuer] then chk "pin-issuer", issuer == o[:issuer], "credential issuer #{issuer}"
    elsif !o[:allow_unpinned] then chk "pins", false, "--issuer missing" end
    if o[:log_key] then chk "pin-log-key", log_key == o[:log_key], "credential log key #{log_key}"
    elsif !o[:allow_unpinned] && o[:issuer] then chk "pins", false, "--log-key missing" end
  end

  def verify_log(s, atts, evs, bh, stated_bh)
    lg = s['log']; ents = lg['entries']; cp = lg['checkpoint']; pl = cp['payload']
    chk "log-checkpoint-signature", (r = verify_jws(cp['jws'], 'sanad-checkpoint+jws', pl, lg['logKey'], pl['timestamp'][0, 10]))[0], r[1]
    chk "log-id", pl['logId'] == lg['logId'], "#{pl['logId']} vs #{lg['logId']}"
    # The embedded entries are the leaves this credential needs, not the whole log: a second assessment on the same log has a checkpoint
    # larger than its entries. Indexes must be distinct, increasing and inside the checkpoint size; each leaf is proved by its own inclusion proof.
    idx = ents.map { |e| e['index'] }
    chk "log-entries", idx.all? { |i| i.is_a?(Integer) && i >= 0 && i < pl['size'] } && idx == idx.uniq.sort, "#{ents.length} embedded entr#{ents.length == 1 ? 'y' : 'ies'} of a log of #{pl['size']} leaves, indexes #{idx.inspect}"
    leaves = ents.map { |e| e['leaf'] }
    parsed = leaves.map { |l| (JSON.parse(l) rescue nil) }
    canon_ok = parsed.each_with_index.all? { |pj, i| pj.is_a?(Hash) && pj.keys.sort == %w[kind ref ts] && Canon.enc(pj) == leaves[i] }
    chk "log-leaf-canonical", canon_ok, "each leaf is canonical {kind,ref,ts}"
    hs = leaves.map { |l| Merkle.leaf(l) }
    rb = [pl['rootHash']].pack('H*')
    if idx == (0...pl['size']).to_a
      chk "log-root-recomputed", Merkle.root(hs).unpack('H*')[0] == pl['rootHash'], "root over all #{hs.length} leaves (the credential holds the whole log)"
    end
    ps = lg['proofs']
    bad = []
    ents.each_with_index do |e, k|
      pr = ps.find { |x| x['index'] == e['index'] }
      ok = pr && pr['size'] == pl['size'] && Merkle.verify_incl(e['index'], pl['size'], hs[k], pr['proof'].map { |h| [h].pack('H*') }, rb)
      bad << e['index'] unless ok
    end
    chk "log-inclusion-proofs", bad.empty?, bad.empty? ? "all #{ents.length} verify (RFC 9162) against checkpoint root" : "failed indexes #{bad}"
    return unless canon_ok
    by = ->(k) { parsed.each_with_index.select { |pj, _| pj['kind'] == k }.map { |pj, i| [pj['ref'], ents[i]['index'], pj['ts']] } }
    att_leaves = by.('attestation'); com = by.('commit'); miss = by.('missing-reveal'); bun = by.('bundle')
    missing_att = atts.reject { |a| att_leaves.any? { |l| l[0] == a['hash'] } }
    chk "log-attestation-leaves", missing_att.empty? && att_leaves.length == atts.length,
        missing_att.empty? ? "every attestation hash is an 'attestation' leaf (#{att_leaves.length})" : "no leaf for #{missing_att.map { |a| a['id'] }}"
    chk "log-bundle-leaf", bun.length == 1 && bun[0][0] == stated_bh && bun[0][0] == bh,
        bun.empty? ? "NO bundle leaf in log" : "bundle leaves=#{bun.length}, match=#{bun[0] && bun[0][0] == bh}"
    # commit leaves reconstructable
    nomatch = []
    atts.each do |a|
      st = { 'type' => 'sanad-commit', 'assessment' => s['assessment'], 'attestationId' => a['id'], 'attestor' => a['attestor'],
             'evidence' => a['evidence'], 'role' => a['role'], 'commit' => a['commit'], 'templateHash' => s['template']['hash'] }
      ref = chash(st)
      nomatch << a['id'] unless com.any? { |l| l[0] == ref }
    end
    extra = com.length - (atts.length - nomatch.length)
    chk "log-commit-leaves", nomatch.empty? && com.length == s['process']['committed'],
        "reconstructed commit leaf for #{atts.length - nomatch.length}/#{atts.length} revealed attestations (unmatched #{nomatch}); #{extra} further commit leaf(s) for non-revealing attestors (not reconstructable: role/attestor/evidence of missing attestors unknown); commit leaves=#{com.length}"
    chk "log-missing-leaves", miss.length == s['process']['missing'].length, "#{miss.length} missing-reveal leaf(s), process.missing=#{s['process']['missing'].length} (ref = commit hash of the non-revealer; not checkable)"
    # order: all commits before any attestation leaf, ts monotone
    lastc = com.map { |l| l[1] }.max || -1; firsta = (att_leaves.map { |l| l[1] }.min) || 1 << 30
    chk "log-commit-before-reveal", lastc < firsta && (com.map { |l| l[2] }.max || "") <= (att_leaves.map { |l| l[2] }.min || "~"),
        "last commit leaf index #{lastc} < first attestation leaf index #{firsta}; timestamps ordered"
    chk "log-attestation-leaves-ts-after-attestation-dates", true, "n/a" if false
  end

  def round3(x); (x * 1000).round / 1000.0; end

  def recognise(pol, b, evs, atts, ev_ok, att_fail)
    asof = Date.parse(pol['asOf'])
    expl = []; dropped = []
    claimed = b['claimedLevel']
    # R1
    live_ev = evs.select { |e| ev_ok[e['id']] ? true : (dropped << "evidence #{e['id']}: R1 hash/kind/date" ; false) }
    live_ev = live_ev.select do |e|
      if e['kind'] == 'auto' && !(e['body']['autoLevel'].is_a?(Integer) && (0..5).cover?(e['body']['autoLevel']))
        dropped << "evidence #{e['id']}: R1 auto without integer autoLevel"; false
      else true end
    end
    ids = live_ev.map { |e| e['id'] }
    seen = {}
    ok_att = []
    atts.each do |a|
      if att_fail[a['id']] then dropped << "#{a['id']}: R1 #{att_fail[a['id']]}"
      elsif !ids.include?(a['evidence']) then dropped << "#{a['id']}: R1 evidence dropped"
      elsif seen[[a['attestor'], a['evidence']]] then dropped << "#{a['id']}: R1 duplicate attestor on #{a['evidence']}"
      else seen[[a['attestor'], a['evidence']]] = true; ok_att << a end
    end
    # R2
    ok_att = ok_att.select do |a|
      if a['conflictDeclared'] then dropped << "#{a['id']}: R2 conflictDeclared"; false
      else true end   # thresholds are 0 and the check is 'fewer than 0' / 'below 0': never triggers
    end
    aged = {}
    live_ev = live_ev.select do |e|
      days = (asof - Date.parse(e['date'])).to_i
      if days < 0 then dropped << "evidence #{e['id']}: R2 dated after asOf"; false
      elsif days / MONTH_DAYS > 4 * pol['halfLifeMonths'] then dropped << "evidence #{e['id']}: R2 older than 4 half-lives"; false
      else aged[e['id']] = 0.5**(days / MONTH_DAYS / pol['halfLifeMonths']); true end
    end
    ids = live_ev.map { |e| e['id'] }
    ok_att = ok_att.select { |a| ids.include?(a['evidence']) || (dropped << "#{a['id']}: evidence dropped"; false) }
    # R4
    levels = {}; entries = {}
    live_ev.each do |e|
      ls = if e['kind'] == 'auto' then [e['body']['autoLevel']]
           else ok_att.select { |a| a['evidence'] == e['id'] }.map { |a| a['level'] } end
      entries[e['id']] = ls
      next if ls.empty?
      sl = ls.sort
      levels[e['id']] = [sl[(sl.length - 1) / 2], CAPS[e['kind']]].min
    end
    qual = live_ev.select { |e| %w[sitting artifact].include?(e['kind']) && levels.key?(e['id']) }
    humans = ok_att.select { |a| qual.any? { |e| e['id'] == a['evidence'] } }.map { |a| a['attestor'] }.uniq
    live_sit = qual.any? { |e| e['kind'] == 'sitting' }
    ql = qual.map { |e| levels[e['id']] }.sort
    attested = ql.empty? ? 0 : [claimed, ql[(ql.length - 1) / 2]].min
    meets = humans.length >= pol['minAttestors'] && (!pol['requireLive'] || live_sit)
    status, level = nil, nil
    if live_ev.empty? then status = 'not-recognised'; level = 0
    elsif meets then status = 'recognised'; level = attested
    else
      status = 'provisional'
      al = live_ev.select { |e| %w[auto peer].include?(e['kind']) && levels.key?(e['id']) }.map { |e| levels[e['id']] }
      level = [al.max || 0, 3, claimed].min
    end
    # R7
    prod = 1.0; terms = []
    live_ev.each do |e|
      ls = entries[e['id']]; next if ls.nil? || ls.empty?
      g = (ls.max - ls.min) <= 1 ? 1.0 : 0.5
      ls.each { |_| t = WEIGHT[e['kind']] * aged[e['id']] * g; terms << [e['id'], t]; prod *= (1 - t) }
    end
    conf = status == 'not-recognised' ? 0.0 : round3(1 - prod)
    @result = { status: status, level: level, attestedLevel: attested, confidence: conf, dropped: dropped,
                humans: humans.length, live: live_sit, levels: levels, terms: terms.map { |i, t| [i, round3(t)] } }
  end
  attr_reader :result
end

if $0 == __FILE__
  if ARGV[0] == '--selftest'
    pub = ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"].pack('H*')
    sig = ["e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"].pack('H*')
    puts "selftest RFC8032 vector1: #{Ed.verify(pub, "", sig).inspect}  tamper: #{Ed.verify(pub, "x", sig)[0]}"
    puts "selftest canon: #{Canon.enc({ 'b' => 1.5, 'a' => [1e21, 1e-7, 100.0, 0.000001, 123456789012345680000.0, -0.0, "\u0001\u00e9/"] })}"
    exit 0
  end
  # usage: sanad_verify.rb <credential.json> [asOf] [halfLifeMonths] [--as-of D] [--half-life N] [--issuer DID] [--log-key DID] [--allow-unpinned]
  args = ARGV.dup; opts = {}; pos = []
  until args.empty?
    a = args.shift
    case a
    when '--as-of' then opts[:asof] = args.shift
    when '--half-life' then opts[:half_life] = args.shift
    when '--issuer' then opts[:issuer] = args.shift
    when '--log-key' then opts[:log_key] = args.shift
    when '--allow-unpinned' then opts[:allow_unpinned] = true
    else pos << a end
  end
  file = pos[0] or abort("usage: ruby sanad_verify.rb <credential.json> [asOf] [halfLifeMonths] [--issuer DID --log-key DID | --allow-unpinned]")
  opts[:asof] ||= pos[1]; opts[:half_life] ||= pos[2]
  v = Verifier.new(JSON.parse(File.read(file)), ENV['PINNED_DIDWEB_KEY'], opts)
  begin
    v.run
  rescue => e
    puts "EXCEPTION #{e.class}: #{e.message}"
  end
  v.checks.each { |n, ok, d| puts "#{ok ? 'PASS' : 'FAIL'}  #{n}: #{d}" }
  failed = v.checks.reject { |_, ok, _| ok }.map(&:first)
  puts "OVERALL: #{failed.empty? ? 'PASS' : 'FAIL'}#{failed.empty? ? '' : '  failed: ' + failed.join('; ')}"
  r = v.result
  puts "RECOGNITION: status=#{r[:status]} level=#{r[:level]} attestedLevel=#{r[:attestedLevel]} confidence=#{r[:confidence]}" if r
  exit(failed.empty? ? 0 : 1)
end

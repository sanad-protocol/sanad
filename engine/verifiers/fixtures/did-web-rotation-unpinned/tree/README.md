# Sanad bundle <bundleHash>

This directory is a self-contained, static copy of one Sanad credential. Nothing in it is a video, a name or a score:
it holds hashes, signatures, the signed log checkpoint and the credential, and anyone may mirror it (a free public git repository is enough).

## URL scheme

    <base>/issuer.json                              issuer card (issuer DID, log key, log id), signed by the issuer key
    <base>/bundles/<bundleHash>/                    this directory; urn:sanad:bundle:<bundleHash> resolves here
    <base>/bundles/<bundleHash>/credential.json     the credential (verifiable on its own)
    <base>/bundles/<bundleHash>/manifest.json       SHA-256 of every other file here (integrity of a mirror, not trust)
    <base>/checkpoints/latest.json                  newest signed checkpoint, with a consistency proof from the previous one
    <base>/checkpoints/<size>.json, index.json      every published checkpoint, in order
    <base>/status/revocation.json                   Bitstring Status List credential (fetch it fresh; it expires)

Witnesses publish their cosignatures in their own static directories: <witnessBase>/<logId>/<size>.json.

## Files here

- credential.json: the credential; evidence.json, attestations.json, log.json, checkpoint.json, dids.json are the same data as parts of it, split for readers and indexers; verification checks that they agree.
- consistency.json: proofs that the log of the credential's checkpoint is a prefix of later signed checkpoints (RFC 9162).
- witnesses.json (if present): checkpoints cosigned by witnesses. status.json (if present): a snapshot of the status list at export time; fetch the list again to check revocation.

## Verify with no server and no network

    sanad-engine verify-bundle <this directory> --policy policy.json --issuer <issuer DID> --log-key <log key DID> [--witness <DID> --require-witnesses 1]

or open sanad-verifier.html in a browser and drop this directory (or a zip of it) on it. The issuer and log key must come from a source you trust; the directory cannot vouch for itself.
A policy is yours to choose: the issuer's recommendation is inside the credential, but it is only a recommendation.

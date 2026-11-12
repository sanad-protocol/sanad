# Testing roadmap for the Sanad engine (code version 0.2)

For the steward and colleagues who will try the engine before anything is called stable. Eight steps, each with who does it, what to do, and what counts as passed. Do them in order; do not skip step 4.

Anything you find, write down as an issue in the repository: what you did, what you expected, what happened. A confusing sentence in the documentation is a finding too.

## Step 0. Install and run the automated tests (any one person, 30 minutes)

```
git clone https://github.com/sanad-protocol/sanad && cd sanad
git checkout engine-v0.2
npm ci
npm run engine:test        # engine tests
npm run reference:verify   # the 20 conformance vectors
node engine/vectors/run.mjs # engine vectors
```

Passed when: everything is green on a machine that is not the author's. Record the operating system and Node version.

## Step 1. One person, whole path (1 hour)

Follow `engine/README.md`, using `engine/bin/sanad-engine` and the three example templates (maths oral, welding practical, code portfolio):
`init`, `template add`, `create-assessment`, `invite`, `commit`, `reveal`, `finalize`, `verify`.

Passed when: a credential is produced, `verify` passes with the issuer and log keys pinned and a policy given, and `verify` without a policy or pins refuses with a clear sentence.

## Step 2. Several people, several machines (half a day)

Roles: one **organiser** runs `sanad-engine serve`; three to five **attestors**, each on their own computer with their own key made by `keygen`; one **verifier** who is not the organiser.

1. The organiser creates the assessment and invites each attestor's `did:key`.
2. Each attestor commits a mark without talking to the others.
3. After all have committed, the organiser closes invitations; each attestor reveals.
4. The organiser finalizes and sends the credential file to the verifier.
5. The verifier checks it with their own policy and the organiser's public keys only.

Passed when: nobody could see another's mark before the reveals; the verifier needed nothing from the organiser except the credential and public keys; two verifiers with different policies get different results from the same credential, and both can read why.

## Step 3. Try to break it (half a day, two people)

One person tries; the other checks that the engine says so, in plain words.
- Edit one byte of the credential (level, attestor, evidence, date, subject).
- Remove the first or last log entry.
- Commit late, reveal late, never reveal, commit twice, replace an attestor after commit.
- Change the computer's clock by hours and by days.
- Stop the server in the middle of a commit and start it again.
- Use another engine's keys and see that the pins refuse it.

Passed when: every tampered credential fails with a named check, every refused action leaves the assessment unchanged, and a restart loses nothing.

## Step 4. A second verifier written from the text alone (one colleague, 1 to 2 weeks)

This is the most important step. A colleague who has not seen the engine's code writes a verifier from `spec/` and the conformance vectors only, in any language.

Passed when: it passes the 20 core vectors and agrees with the engine on every credential produced in steps 1 to 3. Every place where they disagree is either an engine bug or a spec gap; both go into issues. The clean-room Python and Ruby checkers in `engine/test/crosscheck/` are a start but were written by the same project; a colleague's version counts, theirs does not. The Ruby checker's earlier fault with credentials that are not first on their log was fixed in commit 4530dd6 and is covered by a test; a credential made on a shared log is a good case to include.

## Step 5. Policy workshop (2 hours, three or four people who would be verifiers)

Each writes a policy for their own context (a university department, an employer, a school). Run the same set of credentials through all policies.

Passed when: the policies produce visibly different results, each person can explain why in the output, and nobody needed to ask the organiser what to accept.

## Step 6. A real small sitting inside a host (Kamangir, with named conditions)

The Kamangir examination service reaches the engine through a port (pull request 245), in test mode. Its rehearsal report lists 42 scenarios and the open items.

Before real candidates: decide how level 6 is represented (it reads as 5 outside Kamangir today); decide what happens to a credential if its provider disappears; run the examiner-page end-to-end test in a tree where it can run; re-run the rehearsal against the current engine, since its report was written before the Ruby fix. Then run five to ten volunteer candidates, with examiners who know it is a trial and no fee.

Passed when: every candidate gets a credential that a verifier outside Kamangir can check, and no examiner could see another's mark before the reveal.

## Step 7. Settle the open decisions

Go through `docs/SPEC-DECISIONS-NEEDED.md` (25 items). Those that change a format (1, 2, 3 and related) should be decided before anything is called 1.0, in one format version. Rerun steps 0, 3 and 4 afterwards.

## Step 8. External review

Ask at least one cryptographer and one standards or assessment practitioner, who are not collaborators, to read the specification and the engine's signing, hashing and log code, with `docs/SPEC-DECISIONS-NEEDED.md` and this page as the starting list. Publish what they find, and what changed because of it.

## When to call it ready

- Steps 0 to 5 passed by people other than the author.
- An independent verifier (step 4) agrees on all vectors.
- The format decisions of step 7 are taken and the vectors regenerated.
- At least one external review is published.
- Only then: merge to `main`, tag a release, publish a package.

Until then the engine is a preview, and the Status page says exactly that.

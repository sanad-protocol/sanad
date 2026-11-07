# Governance charter (draft 0.1, 7 November 2026)

Published at <https://sanadprotocol.org/governance/>.

## Mission lock

1. Sanad is non-profit. It has no token, no securities, no advertising.
2. The specification text is open (CC BY 4.0) and the reference code is Apache-2.0, which includes a patent grant.
3. Verifying a credential is always free.
4. Any surplus is spent on the mission.

## Roles

- **Steward:** Dr. Arash Kermani Kolankeh, interim. Holds the name, domains and repositories in trust for the future foundation.
- **Editor:** writes and maintains the text. Interim: the steward.
- **Log operator:** serves the transparency log. Must not be the steward alone.
- **Implementers:** anyone who builds software to the specification.
- **Attestors:** independent assessors. They are never appointed by the steward.
- **Ombudsperson:** hears disputes about marks. To be appointed with the first real sittings.

## Decisions

- Proposals are made as public issues or requests for comments.
- A comment period of 14 days applies before a decision.
- Decisions are written down with their reasons.
- A change that alters the expected result of any test vector requires a new minor version.
- Vectors come before prose: where text and vectors disagree, the disagreement is a defect to be fixed.

## Safeguards against capture

A one-person start is a risk to the credibility of any standard. These rules reduce it:

- The steward does not hold the transparency-log signing keys alone. A key ceremony with at least two outside custodians (two of three) precedes the first public log.
- The log is operated by a second party.
- The steward declares in public every interest connected to organisations that take part, including assessment networks.
- No participating organisation receives special treatment in the specification or the vectors.

## Sunset clause

Before version 1.0 there must be at least **three independent stewards from at least two regions**. The steward then becomes one steward among equals. If this has not happened by **31 December 2028**, the specification remains marked draft and the steward will transfer the name and domains to a neutral host chosen by the stewards.

## Name and conformance mark

The name is to be held by the foundation (interim: the steward, in trust). Any implementation that passes the public vectors may say that it conforms to Sanad. The mark is free and never sold.

## Succession

A sealed instruction names a stand-by person who can transfer the domain, the repositories and the keys if the steward cannot act.

## Money

An annual public statement of income and spending. No pay-to-play: sponsors receive no influence over the text.

## Contributions

Contributions are signed off under the Developer Certificate of Origin. Contributions to the specification are made under the specification licence; code contributions under Apache-2.0.

## Dissolution

Assets pass to a non-profit organisation with a similar mission.

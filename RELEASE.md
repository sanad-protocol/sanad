# Release checklist

For a new version of the specification (`SANAD-SPEC-x.y`) or of the site.

## Before

1. All conformance vectors pass: `node reference/verify.mjs`; unit tests: `npx vitest run`.
2. A change that alters the expected result of any vector is a **new minor version**; update the version string (`sanad-x.y`), the document identifier and the vectors together.
3. The specification text, the governance charter and the intellectual property policy agree with each other; every claim is true on the day of release.
4. The comment period of 14 days has run for substantive changes; decisions and reasons are recorded.
5. Run `node build.mjs && node pdf.mjs && node build.mjs && node test.mjs` and check the tagged PDF (title, language, bookmarks).
6. Update `news.json` and the date of the document; check the legal notice, the privacy statement and the accessibility statement against the current state of the site.

## Release

7. Tag the commit `spec-x.y` and publish a release with the PDF and `reference/vectors.json` attached.
8. Deposit an archive copy with a persistent identifier (DOI) and add the identifier to `CITATION.cff` and the specification header.
9. Publish the announcement in the news.

## After

10. Check the live site: links, the security.txt expiry date (renew before it lapses), the feed, the sitemap.
11. Review the open issues and the dependency updates proposed by the bot; merge security updates promptly.

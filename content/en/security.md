---
key: security
lang: en
path: /security/
nav: security
title: Security
description: How to report a vulnerability in Sanad, and an honest account of the security measures of this website.
toc: true
---

<!-- glance -->
- Report to info@sanadprotocol.org with "Sanad security" in the subject.
- A reply is aimed for within 7 days; a fix or a plan within 90 days.
- The site sets its security policy in the page, not in a header, because GitHub Pages cannot set headers.
<!-- /glance -->

## Reporting a vulnerability

Write to info@sanadprotocol.org with what you found, how to reproduce it and the version affected. Please allow reasonable time before public disclosure. Good-faith research is welcome; do not access data of others and do not disrupt services. Scope: weaknesses in the protocol design (the recognition function, blind marking, hashing, the log), in the reference code and in this website. The machine-readable policy is at [/.well-known/security.txt](/.well-known/security.txt).

## Security measures of this website

- Static pages only: no scripts, no forms, no cookies, no database.
- A content security policy (`default-src 'none'`; styles and images only from this site) is delivered as a **meta element in each page**. GitHub Pages cannot set HTTP response headers, so protections that exist only as headers, such as frame-ancestors, a Permissions-Policy, HSTS preload and COOP/COEP, cannot be set today. Putting a content delivery front (such as Cloudflare) in front of the site to set them is planned.
- A referrer policy of "no-referrer" is set as a meta element, so that outgoing links do not send the address of the page.
- HTTPS is enforced by GitHub Pages for the custom domain.
- The build and the deployment run in GitHub Actions with pinned action versions; dependencies are updated by a dependency bot and reviewed.
- No third-party requests: no fonts, no analytics, no embeds.

## Known limits

The measures above are a baseline for a static site. They are not an audit. The reference implementation has not had an independent security review; a reviewer is one of the [roles needed](/support/).

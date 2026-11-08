// Chrome strings of the site (navigation, footer, labels) per language. Page text lives in content/<lang>/*.md.
export const SITE = { url: 'https://sanadprotocol.org', name: 'Sanad', stand: '2026-11-07' };
export const LANGS = {
  en: { code: 'en', dir: 'ltr', name: 'English', short: 'EN', og: 'en_GB' },
  de: { code: 'de', dir: 'ltr', name: 'Deutsch', short: 'DE', og: 'de_DE' },
};
export const DATE_LONG = { en: '7 November 2026', de: '7. November 2026' };
export const T = {
  en: {
    skip: 'Skip to main content', home: 'Home', menu: 'Main navigation', breadcrumb: 'Breadcrumb', onthispage: 'On this page', glance: 'At a glance',
    stand: 'As of', doc: 'Document', version: 'Version', status: 'Status', draft: 'Draft for discussion', date: 'Date', licence: 'Licence', steward: 'Steward',
    lang: 'Language', translation: 'Not yet reviewed by a native speaker. The English text is authoritative.', translationDe: 'Entwurf einer Übersetzung: noch nicht von Muttersprachlern geprüft.',
    notes: 'Notes', footerLegal: 'Legal notice', footerPrivacy: 'Privacy', footerAccess: 'Accessibility', footerContact: 'Contact', footerLicence: 'Licence',
    footerLine: 'Sanad is an open protocol (draft). It is not accreditation. The Open Sanad Foundation (UAE) is in preparation; until it exists the author acts as interim steward.',
    nav: [['spec', 'Specification', '/spec/'], ['conformance', 'Conformance', '/conformance/'], ['explainer', 'Explainer', '/explainer/'], ['governance', 'Governance', '/governance/'], ['participate', 'Participate', '/participate/'], ['roadmap', 'Roadmap', '/roadmap/'], ['support', 'Support', '/support/'], ['contact', 'Contact', '/contact/']],
    more: [['about', 'About', '/about/'], ['for', 'Who it is for', '/for/'], ['status', 'Status and limits', '/status/'], ['news', 'News', '/news/'], ['glossary', 'Glossary', '/glossary/'], ['faq', 'Clarifications', '/faq/'], ['name', 'The name', '/name-and-ip/'], ['ipr', 'Intellectual property policy', '/ipr/'], ['security', 'Security', '/security/']],
    moreLabel: 'More', printed: 'Printed from', next: 'Next', back: 'Back to top', external: 'external link', enonly: 'English', anchor: 'Link to this section', fnback: 'Back to the text, note', ennote: '', digits: '',
  },
  de: {
    skip: 'Zum Hauptinhalt springen', home: 'Startseite', menu: 'Hauptnavigation', breadcrumb: 'Brotkrumennavigation', onthispage: 'Auf dieser Seite', glance: 'Auf einen Blick',
    stand: 'Stand', doc: 'Dokument', version: 'Version', status: 'Status', draft: 'Entwurf zur Diskussion', date: 'Datum', licence: 'Lizenz', steward: 'Verantwortlich',
    lang: 'Sprache', translation: 'Noch nicht von Muttersprachlern geprüft. Maßgeblich ist der englische Text.', translationDe: '',
    notes: 'Anmerkungen', footerLegal: 'Impressum', footerPrivacy: 'Datenschutz', footerAccess: 'Barrierefreiheit', footerContact: 'Kontakt', footerLicence: 'Lizenz',
    footerLine: 'Sanad ist ein offenes Protokoll (Entwurf). Es ist keine Akkreditierung. Die Open Sanad Foundation (VAE) ist in Vorbereitung; bis zu ihrer Gründung handelt der Autor als kommissarischer Verantwortlicher.',
    nav: [['spec', 'Spezifikation', '/spec/'], ['conformance', 'Konformität', '/conformance/'], ['explainer', 'Erklärseite', '/explainer/'], ['governance', 'Governance', '/governance/'], ['participate', 'Mitmachen', '/de/mitmachen/'], ['roadmap', 'Fahrplan', '/roadmap/'], ['support', 'Unterstützen', '/support/'], ['contact', 'Kontakt', '/de/kontakt/']],
    more: [['about', 'Über', '/de/ueber/'], ['status', 'Status und Grenzen', '/de/status/'], ['news', 'Neuigkeiten', '/news/'], ['glossary', 'Glossar', '/glossary/'], ['faq', 'Fragen und Antworten', '/faq/'], ['name', 'Name und Schutzrechte', '/name-and-ip/']],
    moreLabel: 'Mehr', printed: 'Ausgedruckt von', next: 'Weiter', back: 'Nach oben', external: 'externer Link', enonly: 'englisch', anchor: 'Link zu diesem Abschnitt', fnback: 'Zurück zum Text, Anmerkung', ennote: 'Seiten mit der Kennzeichnung EN gibt es nur auf Englisch.', digits: '',
  },
};

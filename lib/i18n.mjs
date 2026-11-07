// Chrome strings of the site (navigation, footer, labels) per language. Page text lives in content/<lang>/*.md.
export const SITE = { url: 'https://sanadprotocol.org', name: 'Sanad', stand: '2026-11-07' };
export const LANGS = {
  en: { code: 'en', dir: 'ltr', name: 'English', short: 'EN', og: 'en_GB' },
  de: { code: 'de', dir: 'ltr', name: 'Deutsch', short: 'DE', og: 'de_DE' },
  ar: { code: 'ar', dir: 'rtl', name: 'العربية', short: 'AR', og: 'ar_AE' },
  fa: { code: 'fa', dir: 'rtl', name: 'فارسی', short: 'FA', og: 'fa_IR' },
};
export const DATE_LONG = { en: '7 November 2026', de: '7. November 2026', ar: '7 نوفمبر 2026', fa: '۱۶ آبان ۱۴۰۵' };
export const T = {
  en: {
    skip: 'Skip to main content', home: 'Home', menu: 'Main navigation', breadcrumb: 'Breadcrumb', onthispage: 'On this page', glance: 'At a glance',
    stand: 'As of', doc: 'Document', version: 'Version', status: 'Status', draft: 'Draft for discussion', date: 'Date', licence: 'Licence', steward: 'Steward',
    lang: 'Language', translation: 'Not yet reviewed by a native speaker. The English text is authoritative.', translationDe: 'Entwurf einer Übersetzung: noch nicht von Muttersprachlern geprüft.',
    notes: 'Notes', footerLegal: 'Legal notice', footerPrivacy: 'Privacy', footerAccess: 'Accessibility', footerContact: 'Contact', footerLicence: 'Licence',
    footerLine: 'Sanad is an open protocol (draft). It is not accreditation. The Open Sanad Foundation (UAE) is in preparation; until it exists the author acts as interim steward.',
    nav: [['spec', 'Specification', '/spec/'], ['conformance', 'Conformance', '/conformance/'], ['explainer', 'Explainer', '/explainer/'], ['governance', 'Governance', '/governance/'], ['participate', 'Participate', '/participate/'], ['roadmap', 'Roadmap', '/roadmap/']],
    more: [['for', 'Who it is for', '/for/'], ['status', 'Status and limits', '/status/'], ['support', 'Support the project', '/support/'], ['news', 'News', '/news/'], ['glossary', 'Glossary', '/glossary/'], ['faq', 'Questions and answers', '/faq/'], ['name', 'The name', '/name-and-ip/'], ['ipr', 'Intellectual property policy', '/ipr/'], ['security', 'Security', '/security/']],
    moreLabel: 'More', printed: 'Printed from', next: 'Next', back: 'Back to top', external: 'external link', enonly: 'English', anchor: 'Link to this section', fnback: 'Back to the text, note', ennote: '', digits: '',
  },
  de: {
    skip: 'Zum Hauptinhalt springen', home: 'Startseite', menu: 'Hauptnavigation', breadcrumb: 'Brotkrumennavigation', onthispage: 'Auf dieser Seite', glance: 'Auf einen Blick',
    stand: 'Stand', doc: 'Dokument', version: 'Version', status: 'Status', draft: 'Entwurf zur Diskussion', date: 'Datum', licence: 'Lizenz', steward: 'Verantwortlich',
    lang: 'Sprache', translation: 'Noch nicht von Muttersprachlern geprüft. Maßgeblich ist der englische Text.', translationDe: '',
    notes: 'Anmerkungen', footerLegal: 'Impressum', footerPrivacy: 'Datenschutz', footerAccess: 'Barrierefreiheit', footerContact: 'Kontakt', footerLicence: 'Lizenz',
    footerLine: 'Sanad ist ein offenes Protokoll (Entwurf). Es ist keine Akkreditierung. Die Open Sanad Foundation (VAE) ist in Vorbereitung; bis zu ihrer Gründung handelt der Autor als kommissarischer Verantwortlicher.',
    nav: [['spec', 'Spezifikation', '/spec/'], ['conformance', 'Konformität', '/conformance/'], ['explainer', 'Erklärseite', '/explainer/'], ['governance', 'Governance', '/governance/'], ['participate', 'Mitmachen', '/de/mitmachen/'], ['roadmap', 'Fahrplan', '/roadmap/']],
    more: [['status', 'Status und Grenzen', '/de/status/'], ['news', 'Neuigkeiten', '/news/'], ['glossary', 'Glossar', '/glossary/'], ['faq', 'Fragen und Antworten', '/faq/'], ['name', 'Name und Schutzrechte', '/name-and-ip/']],
    moreLabel: 'Mehr', printed: 'Ausgedruckt von', next: 'Weiter', back: 'Nach oben', external: 'externer Link', enonly: 'englisch', anchor: 'Link zu diesem Abschnitt', fnback: 'Zurück zum Text, Anmerkung', ennote: 'Seiten mit der Kennzeichnung EN gibt es nur auf Englisch.', digits: '',
  },
  ar: {
    skip: 'انتقل إلى المحتوى الرئيسي', home: 'الرئيسية', menu: 'التنقل الرئيسي', breadcrumb: 'مسار التنقل', onthispage: 'في هذه الصفحة', glance: 'نظرة سريعة',
    stand: 'التاريخ', doc: 'الوثيقة', version: 'الإصدار', status: 'الحالة', draft: 'مسودة للنقاش', date: 'التاريخ', licence: 'الترخيص', steward: 'المسؤول',
    lang: 'اللغة', translation: 'لم يراجعها بعد متحدث أصلي. النص الإنجليزي هو المرجع.', translationDe: '',
    notes: 'ملاحظات', footerLegal: 'الإشعار القانوني', footerPrivacy: 'الخصوصية', footerAccess: 'إمكانية الوصول', footerContact: 'التواصل', footerLicence: 'الترخيص',
    footerLine: 'سند بروتوكول مفتوح (مسودة). وهو ليس اعتماداً أكاديمياً. مؤسسة سند المفتوحة (الإمارات) قيد الإعداد، وإلى حين تأسيسها يتولى المؤلف الإشراف مؤقتاً.',
    nav: [['spec', 'المواصفة', '/spec/'], ['governance', 'الحَوكمة', '/governance/'], ['participate', 'المشاركة', '/participate/']],
    more: [['status', 'الحالة والحدود', '/ar/status/']], moreLabel: 'المزيد', printed: '', next: 'التالي', back: 'إلى الأعلى', external: 'رابط خارجي', enonly: 'بالإنجليزية', anchor: 'رابط إلى هذا القسم', fnback: 'العودة إلى النص، ملاحظة', ennote: 'الصفحات المعلَّمة بـ \u2066EN\u2069 متوفرة بالإنجليزية فقط. تُكتب الأرقام في هذه الصفحة بالأرقام الغربية (\u20660–9\u2069).', digits: 'western',
  },
  fa: {
    skip: 'پرش به محتوای اصلی', home: 'خانه', menu: 'پیمایش اصلی', breadcrumb: 'مسیر صفحه', onthispage: 'در این صفحه', glance: 'در یک نگاه',
    stand: 'تاریخ', doc: 'سند', version: 'نسخه', status: 'وضعیت', draft: 'پیش‌نویس برای گفتگو', date: 'تاریخ', licence: 'پروانه', steward: 'مسئول',
    lang: 'زبان', translation: 'هنوز توسط فارسی‌زبان بازبینی نشده است. متن انگلیسی مرجع است.', translationDe: '',
    notes: 'یادداشت‌ها', footerLegal: 'اطلاعات حقوقی', footerPrivacy: 'حریم خصوصی', footerAccess: 'دسترس‌پذیری', footerContact: 'تماس', footerLicence: 'پروانه',
    footerLine: 'سند یک پروتکل باز است (پیش‌نویس). اعتباردهی دانشگاهی نیست. بنیاد باز سند (امارات) در دست آماده‌سازی است و تا تأسیس آن نویسنده به‌طور موقت سرپرستی را بر عهده دارد.',
    nav: [['spec', 'مشخصات', '/spec/'], ['governance', 'حکمرانی', '/governance/'], ['participate', 'مشارکت', '/participate/']],
    more: [['status', 'وضعیت و محدودیت‌ها', '/fa/status/']], moreLabel: 'بیشتر', printed: '', next: 'بعدی', back: 'بالای صفحه', external: 'پیوند بیرونی', enonly: 'انگلیسی', anchor: 'پیوند به این بخش', fnback: 'بازگشت به متن، یادداشت', ennote: 'صفحه‌هایی که با \u2066EN\u2069 علامت خورده‌اند فقط به انگلیسی هستند. در این صفحه از رقم‌های فارسی (\u2066۰–۹\u2069) استفاده می‌شود.', digits: 'persian',
  },
};

function supportedCopyLocale(value) {
  if (typeof value !== 'string') return null;
  const primary = value.trim().toLowerCase().split(/[-_]/, 1)[0];
  return primary === 'en' || primary === 'my' ? primary : null;
}

export function resolveCopyLocale({
  choice,
  uiLocale,
  languages = globalThis.navigator?.languages || [],
} = {}) {
  if (choice === 'en' || choice === 'my') return choice;
  if (uiLocale === 'en' || uiLocale === 'my') return uiLocale;
  for (const language of languages) {
    const locale = supportedCopyLocale(language);
    if (locale) return locale;
  }
  return 'en';
}

// Burmese remains disabled until the catalog and its required evidence exist.
export const BURMESE_COPY_VERIFIED = false;
export const COPY_LOCALE_CHOICE_KEY = 'uiLocale';

export function displayedCopyLocale(preferences) {
  const locale = resolveCopyLocale(preferences);
  return locale === 'my' && !BURMESE_COPY_VERIFIED ? 'en' : locale;
}

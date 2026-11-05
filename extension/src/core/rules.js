// Site rules: the per-site routing capability the desktop apps do not have.
//
// THERE IS EXACTLY ONE RULE FORM, and that is a design decision rather than a
// shortcut:
//
//     example.com   means example.com and every subdomain of it
//
// No paths, no ports, no schemes, no wildcards, no exact-only form, no regular
// expressions. The reason is that a rule has to be honoured by two independent
// mechanisms with different matching languages: the PAC script that routes,
// and the declarativeNetRequest rule that blocks when routing is unavailable.
// `example.com` maps exactly onto PAC suffix comparison and exactly onto the
// declarativeNetRequest filter `||example.com^`. Every richer form is expressible
// in one and only approximately in the other, and an approximation in this
// direction means a site the user believes is covered is quietly not, or a site
// they excluded is quietly blocked. One form that both layers keep perfectly is
// worth more than five forms that mostly agree.
//
// A path-based rule is impossible in principle, not merely inconvenient:
// routing is chosen when the connection is made, before any path is sent.
// Offering a path field would let a user write a rule no browser can keep.

import { MODE_ALL, MODE_LISTED } from './constants.js';

const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const MAX_RULES = 200;

/**
 * Normalise user input into a rule, or explain why it cannot be one.
 * Accepts a bare host or a pasted URL and reduces it to the registrable host.
 * @returns {{ok: true, rule: string} | {ok: false, reason: string}}
 */
export function normaliseRule(input) {
  if (typeof input !== 'string') return { ok: false, reason: 'Enter a website address.' };
  let s = input.trim().toLowerCase();
  if (!s) return { ok: false, reason: 'Enter a website address.' };

  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  s = s.split('/')[0].split('?')[0].split('#')[0]; // path, query, fragment
  s = s.split('@').pop(); // credentials
  if (s.startsWith('[')) {
    return { ok: false, reason: 'Addresses are not supported here. Use the website name.' };
  }
  s = s.split(':')[0]; // port
  s = s.replace(/^\*\./, ''); // a pasted *. prefix means the same thing here
  s = s.replace(/\.$/, ''); // trailing root dot

  if (!s) return { ok: false, reason: 'Enter a website address.' };
  if (/[^\x00-\x7f]/.test(s)) {
    if (/[\s\\%]/.test(s)) {
      return {
        ok: false,
        reason: 'That does not look like a website address.',
      };
    }
    try {
      // A file: URL runs the same WHATWG host parser (domain to ASCII) as
      // https: does, and is not a network address, so the bundle's remote-URL
      // gate (tools/leakscan.py) stays exact.
      s = new URL(`file://${s}/`).hostname.toLowerCase().replace(/\.$/, '');
    } catch {
      return {
        ok: false,
        reason: 'That does not look like a website address.',
      };
    }
  }
  if (s.length > 253) return { ok: false, reason: 'That address is too long.' };
  if (/^\d+(\.\d+)*$/.test(s)) {
    // Refused deliberately. A rule written as a numeric address is an address
    // written into the browser profile, and this extension is built so that no
    // routable address is ever recorded by it: not in the bundle, not at
    // runtime, and not by the user. Website names only.
    return { ok: false, reason: 'Addresses are not supported here. Use the website name.' };
  }
  const labels = s.split('.');
  if (labels.length < 2) {
    return { ok: false, reason: 'Use a full address, for example example.com' };
  }
  for (const label of labels) {
    if (!HOST_LABEL.test(label)) {
      return { ok: false, reason: 'That does not look like a website address.' };
    }
  }
  return { ok: true, rule: s };
}

/** Does `host` match `rule`? Pure string work: this never resolves anything. */
export function ruleMatches(rule, host) {
  if (!rule || !host) return false;
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return h === rule || h.endsWith(`.${rule}`);
}

export function anyRuleMatches(rules, host) {
  for (const r of rules) if (ruleMatches(r, host)) return true;
  return false;
}

/**
 * Should `host` be routed through the tunnel under these settings?
 * The PAC generator, the fail-closed block list and the popup all derive from
 * this one definition of "in scope" so that they cannot drift apart.
 */
export function isInScope(settings, host) {
  if (settings.mode === MODE_LISTED) return anyRuleMatches(settings.listed, host);
  return !anyRuleMatches(settings.excluded, host);
}

export function defaultSettings() {
  return {
    // Armed means the user wants protection. Being armed while the desktop app
    // is down is not an error: it is the state in which traffic is blocked
    // rather than leaked, which is the entire point of the extension.
    armed: false,
    // ALL is the default because its default configuration records nothing
    // about the user: an untouched profile holds two empty arrays. Shipping a
    // starter list of sites would make the bundle a document about what this
    // software is for, and the bundle is readable by anyone.
    mode: MODE_ALL,
    listed: [],
    excluded: [],
  };
}

export function sanitiseSettings(raw) {
  if (!raw || typeof raw !== 'object') return defaultSettings();
  const clean = (arr) => {
    if (!Array.isArray(arr)) return [];
    const out = [];
    for (const item of arr) {
      const n = normaliseRule(typeof item === 'string' ? item : '');
      if (n.ok && !out.includes(n.rule)) out.push(n.rule);
      if (out.length >= MAX_RULES) break;
    }
    return out;
  };
  return {
    armed: raw.armed === true,
    mode: raw.mode === MODE_LISTED ? MODE_LISTED : MODE_ALL,
    listed: clean(raw.listed),
    excluded: clean(raw.excluded),
  };
}

export { MODE_ALL, MODE_LISTED };

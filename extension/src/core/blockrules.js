// The fail-closed enforcement layer.
//
// WHY THIS EXISTS AT ALL, given that the PAC script already has no DIRECT
// fallback: because relying on proxy semantics alone means relying on three
// browsers' undocumented edge cases to keep the single most important promise
// this extension makes.
//
// Concrete known hazards that the PAC alone does not cover:
//
//   - Firefox has a preference, network.proxy.failover_direct, which is on by
//     default and falls back to a direct connection when all proxies fail. An
//     extension cannot change a preference. On Firefox the PAC is therefore not
//     sufficient on its own, and this layer is load-bearing rather than
//     belt-and-braces.
//   - A proxy setting is browser-global state that another extension, an
//     enterprise policy, or the user can take away between the moment we set it
//     and the moment a request is made.
//   - The service worker can be terminated mid-transition, leaving the proxy
//     set to a stale endpoint.
//
// declarativeNetRequest rules are evaluated by the network stack itself, persist
// across service-worker death, persist across browser restart, and disappear the
// moment the extension is disabled or removed. That last property is what makes
// blocking safe to ship: the user can always get their browser back by turning
// the extension off, and they cannot end up with a browser bricked by rules
// belonging to software they have uninstalled.
//
// Blocking is limited to what the user asked to route. Sites they deliberately
// left outside the tunnel keep working, because nothing ever claimed those were
// protected.

import {
  DNR_BLOCK_RULE_ID,
  DNR_EXEMPT_RULE_ID_BASE,
  DNR_MAX_EXEMPT_RULES,
  DNR_PRIORITY_BLOCK,
  DNR_PRIORITY_EXEMPT,
  DNR_PROBE_RULE_ID,
  DNR_RESOURCE_TYPES,
  MODE_LISTED,
} from './constants.js';

/**
 * The declarativeNetRequest filter for one rule. `||example.com^` matches
 * example.com and its subdomains and nothing else: the `^` separator does not
 * match a dot, so example.com.evil.example does not match. This is exactly the
 * semantics of the single rule form in rules.js, which is why there is only one
 * rule form.
 */
function filterFor(rule) {
  return `||${rule}^`;
}

/**
 * @param {{mode: string, listed: string[], excluded: string[]}} settings
 * @param {boolean} failClosed  true when in-scope traffic must not leave
 * @param {string[]} [resourceTypes]  the types THIS browser accepts, negotiated
 *   by the adapter. Defaults to the full wanted list so that a caller with no
 *   browser in front of it -- the unit tests, for instance -- still gets the
 *   shape the design asks for. The adapter passes the intersection, because a
 *   value the running browser's schema does not know discards every rule in the
 *   call rather than just itself.
 * @returns {Array<object>} declarativeNetRequest dynamic rules
 */
export function buildBlockRules(settings, failClosed, resourceTypes = DNR_RESOURCE_TYPES) {
  if (!failClosed) return [];
  const types = Array.isArray(resourceTypes) && resourceTypes.length
    ? resourceTypes
    : DNR_RESOURCE_TYPES;

  const rules = [];

  if (settings.mode === MODE_LISTED) {
    // Only the listed sites were ever going to be routed, so only they are
    // blocked. The rest of the browser is untouched: blocking it would punish
    // the user for a failure that has nothing to do with the sites they chose.
    const listed = (settings.listed || []).slice(0, DNR_MAX_EXEMPT_RULES);
    listed.forEach((rule, i) => {
      rules.push({
        id: DNR_EXEMPT_RULE_ID_BASE + i,
        priority: DNR_PRIORITY_BLOCK,
        action: { type: 'block' },
        condition: { urlFilter: filterFor(rule), resourceTypes: types },
      });
    });
    return rules;
  }

  // Mode ALL: block everything, then re-permit exactly the hosts the user put
  // outside the tunnel. The exemptions carry the higher priority, because in
  // declarativeNetRequest an `allow` beats a `block` of lower priority.
  rules.push({
    id: DNR_BLOCK_RULE_ID,
    priority: DNR_PRIORITY_BLOCK,
    action: { type: 'block' },
    condition: { urlFilter: '*', resourceTypes: types },
  });

  const excluded = (settings.excluded || []).slice(0, DNR_MAX_EXEMPT_RULES);
  excluded.forEach((rule, i) => {
    rules.push({
      id: DNR_EXEMPT_RULE_ID_BASE + i,
      priority: DNR_PRIORITY_EXEMPT,
      action: { type: 'allow' },
      condition: { urlFilter: filterFor(rule), resourceTypes: types },
    });
  });

  return rules;
}

/** Every id this module may ever use, so an update can remove all of them. */
export function allRuleIds() {
  // The probe id is swept here as well as by the probe itself. A background
  // context killed between the probe's add and its remove would otherwise leave
  // a rule nothing else knows how to clear, and an orphan block rule is the one
  // kind of leftover a user experiences as a browser that stopped working.
  const ids = [DNR_BLOCK_RULE_ID, DNR_PROBE_RULE_ID];
  for (let i = 0; i < DNR_MAX_EXEMPT_RULES; i++) ids.push(DNR_EXEMPT_RULE_ID_BASE + i);
  return ids;
}

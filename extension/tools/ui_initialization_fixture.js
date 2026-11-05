function checkUiInitialization(sources, page, scenario) {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const strip = (source) => source
    .replace(/^import[\s\S]*?;\s*/gm, '')
    .replace(/^export\s*\{[^}]*\};?\s*/gm, '')
    .replace(/^export\s+(?=(?:const|let|var|function|class|async)\b)/gm, '');
  const bindings = {};
  const load = (name) => {
    const source = sources[name];
    const names = Array.from(source.matchAll(/^export\s+(?:const|let|var|function|class)\s+(\w+)/gm), (match) => match[1]);
    Object.assign(bindings, new Function(...Object.keys(bindings), strip(source) + '\nreturn {' + names.join(',') + '};')(...Object.values(bindings)));
  };
  load('constants');
  load('rules');
  load('copy');
  if (sources.locale) load('locale');
  const nodes = new Map();
  const element = () => ({
    disabled: false, hidden: false, textContent: '', value: '', checked: false,
    dataset: {}, children: [], events: {}, attributes: {},
    addEventListener(type, callback) { this.events[type] = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
    append(...children) { this.children.push(...children); },
    appendChild(child) { this.children.push(child); },
    click() { return this.events.click?.(); },
  });
  const document = {
    documentElement: {}, title: '',
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
    createElement: element,
  };
  const good = {
    state: bindings.STATE.OFF,
    settings: { armed: false, mode: 'all', listed: [], excluded: [] },
    routingSurface: { ok: true }, privacy: {},
  };
  let calls = 0;
  let fail = scenario !== 'mutation' && scenario !== 'stale' && scenario !== 'recovery';
  const api = {
    runtime: { async sendMessage() {
      calls += 1;
      if (!fail) return good;
      if (scenario === 'rejection') throw new Error('R'.repeat(300));
      if (scenario === 'resolved') return { error: 'E'.repeat(300) };
      return { settings: { armed: false, mode: 'all', listed: {}, excluded: [] } };
    }, openOptionsPage() {} },
    storage: { local: { async get() { return {}; }, async set() {}, async remove() {} } },
    tabs: { async query() { return [{ url: 'https://example.org/' }]; } },
    permissions: { async request() { return false; } },
  };
  let body = strip(sources[page]);
  body = body.replace(/\nrefresh\(\);\s*$/, '\n');
  const exposed = '\nreturn { refresh, render, setSnapshot(value) { snapshot = value; }, getSnapshot() { return snapshot; }, getActiveHost() { return typeof activeHost === "undefined" ? null : activeHost; } };';
  const ui = new Function(...Object.keys(bindings), 'api', 'isSafariRuntime', 'document', body + exposed)(...Object.values(bindings), api, () => false, document);
  return (async () => {
    await ui.refresh();
    if (scenario === 'mutation' || scenario === 'stale' || scenario === 'recovery') {
      check(ui.getSnapshot() === good, 'positive control did not initialize');
      fail = true;
      ui.setSnapshot({ error: 'mutation error' });
      ui.render();
    }
    const headline = nodes.get(page === 'popup' ? 'stateHeadline' : 'liveHeadline');
    const detail = nodes.get(page === 'popup' ? 'stateDetail' : 'liveDetail');
    check(headline.textContent === 'Not routing: this proxy extension could not start', 'failure headline absent');
    check(detail.textContent.length <= 200, 'failure detail is unbounded');
    check(ui.getSnapshot() === null, 'stale snapshot remains');
    if (page === 'popup') check(ui.getActiveHost() === null, 'active host remains');
    for (const id of page === 'popup' ? ['toggle', 'siteAction'] : ['modeAll', 'modeListed', 'ruleInput', 'addRule', 'panic']) {
      check(nodes.get(id).disabled, id + ' remains enabled');
    }
    if (scenario === 'stale') {
      const before = calls;
      await nodes.get(page === 'popup' ? 'toggle' : 'modeAll').events[page === 'popup' ? 'click' : 'change']();
      check(calls === before, 'stale handler sent a mutation');
    }
    if (scenario === 'recovery') {
      fail = false;
      await ui.refresh();
      check(ui.getSnapshot() === good, 'snapshot did not recover');
      const control = nodes.get(page === 'popup' ? 'siteAction' : 'panic');
      check(!control.disabled, 'control remains disabled after recovery');
    }
    return { page, scenario, passed: true };
  })();
}

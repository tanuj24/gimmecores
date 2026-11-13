'use strict';
// GimmeCores desktop UI. Everything another device chooses (names, reasons) is inserted as
// text, never as HTML. Approvals are checked again by gmcd with Touch ID / your password.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let snap = null;
let service = { start_at_login: false, bundled: false, cli_installed: false, homebrew_service: false };
const busy = new Set();
let localPrefs = null;        // protection choices made while lending is off
let confirmUnpair = null;     // fingerprint awaiting a second click
let ticketCloses = 0;

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'disabled') e.disabled = !!v;
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function toast(message, error = false) {
  const t = $('toast');
  t.textContent = message;
  t.className = error ? 'toast error' : 'toast';
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, error ? 7000 : 3500);
}

const gib = (x) => `${x >= 10 ? x.toFixed(0) : x.toFixed(1)} GiB`;
const cores = (c) => `${Number.isInteger(c) ? c : c.toFixed(1)} ${c === 1 ? 'core' : 'cores'}`;
function until(sec) {
  if (!sec) return '';
  const d = new Date(sec * 1000);
  const left = Math.max(0, sec - Date.now() / 1000);
  const h = Math.floor(left / 3600), m = Math.floor((left % 3600) / 60);
  const span = h >= 24 ? `${Math.floor(h / 24)} d` : h ? `${h} h ${m} min` : `${m} min`;
  return `until ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} (${span} left)`;
}
const shortFp = (fp) => fp.split('-').slice(0, 2).join('-');
const presenceHint = () =>
  snap?.status?.presence_required ? `Confirm with ${snap.status.presence_method} on this computer…` : 'Working…';

async function refresh() {
  try {
    snap = await invoke('snapshot');
  } catch (e) {
    snap = { running: false, error: String(e) };
  }
  try {
    service = await invoke('service_state');
  } catch {
    // keep the last known state
  }
  render();
}

async function act(key, fn, okMessage) {
  if (busy.has(key)) return;
  busy.add(key);
  render();
  try {
    await fn();
    if (okMessage) toast(okMessage);
  } catch (e) {
    toast(String(e), true);
  } finally {
    busy.delete(key);
    await refresh();
  }
}

// ------------------------------------------------------------------ rendering

function render() {
  const online = !!snap?.running;
  $('offline').hidden = online;
  $('online').hidden = !online;
  const brew = service.homebrew_service;
  $('start-bundled').hidden = !service.bundled || brew;
  $('start-homebrew').hidden = !brew;
  $('start-terminal').hidden = service.bundled || brew;
  $('start-daemon').disabled = busy.has('service');
  $('settings-section').hidden = !online;
  for (const id of ['opt-login', 'install-cli']) {
    $(id).closest('.row').hidden = !service.bundled;
  }
  // A `brew services` login item is Homebrew's to manage, not this switch's.
  $('opt-login').checked = service.start_at_login || brew;
  $('opt-login').disabled = busy.has('service') || brew;
  $('login-note').textContent = brew
    ? 'Managed by Homebrew: brew services stop gimmecores'
    : 'Turning this off also stops it now.';
  $('cli-state').textContent = service.cli_installed
    ? 'Installed: type gmc in Terminal.'
    : 'Lets you use GimmeCores from Terminal (asks for your password once).';
  $('install-cli').hidden = service.cli_installed;
  if (online) {
    $('opt-discovery').checked = snap.status.discovery;
    $('opt-discovery').disabled = busy.has('discovery');
  }
  $('install-cli').disabled = busy.has('cli');
  if (!online) {
    $('offline-reason').textContent = service.bundled ? '' : (snap?.error || '');
    $('pill').textContent = 'Not running';
    $('pill').className = 'pill';
    $('device-name').textContent = 'GimmeCores';
    $('fingerprint').textContent = '';
    return;
  }
  const s = snap.status;
  $('device-name').textContent = s.device_name;
  $('fingerprint').textContent = s.fingerprint;
  const pill = $('pill');
  if (!s.lending) { pill.textContent = 'Lending off'; pill.className = 'pill'; }
  else if (s.pause_reason) { pill.textContent = 'Paused'; pill.className = 'pill paused'; }
  else { pill.textContent = 'Lending on'; pill.className = 'pill on'; }

  renderLending(s);
  renderRequests();
  renderPairings();
  renderGrants();
  renderPeers();
}

function renderLending(s) {
  const toggle = $('lend-toggle');
  toggle.setAttribute('aria-checked', String(s.lending));
  toggle.disabled = busy.has('lend');
  const prefs = localPrefs || { battery: s.pause_on_battery, idle: s.idle_only };
  $('opt-battery').checked = prefs.battery;
  $('opt-idle').checked = prefs.idle;
  $('opt-battery').disabled = $('opt-idle').disabled = busy.has('lend');
  $('lending-sub').textContent = busy.has('lend')
    ? presenceHint()
    : s.lending
      ? 'Paired devices may ask to use this computer. You approve every request.'
      : 'Off: no device can use this computer.';
  const paused = $('paused');
  paused.hidden = !(s.lending && s.pause_reason);
  paused.textContent = `Paused: ${s.pause_reason}. Running tasks are frozen until this clears.`;
  $('presence').textContent = s.presence_required
    ? `Approvals need ${s.presence_method}.`
    : 'Warning: approvals do not need Touch ID or your password on this machine.';
  $('presence').className = s.presence_required ? 'small muted' : 'small warnline';
  $('machine').textContent =
    `${cores(s.cpu_cores)}, ${gib(s.memory_gib)} · ${s.running_for_others} task(s) running for others`;
  $('stop-all').disabled = busy.has('stop') || (!s.lending && snap.lent.length === 0);
  for (const m of ['container', 'sandbox']) {
    const box = $(`rt-${m}`);
    box.checked = s.lend_modes.includes(m);
    box.disabled = busy.has('modes');
    const state = $(`rt-${m}-state`);
    const works = s.available_modes.includes(m);
    state.textContent = works
      ? ' Works on this computer.'
      : m === 'container' ? ' Not running here (start Docker).' : ' Not available on this computer yet.';
    state.className = works ? 'small ok-text' : 'small warn-text';
  }
}

const MODE_TEXT = {
  container: 'Runs in a container: it cannot see your files or other apps.',
  sandbox: "Runs in this computer's sandbox, as you: only its own folder, no network, your installed tools.",
  native: 'Runs directly as you, WITHOUT a sandbox.',
};

function limitsLine(g) {
  return `${cores(g.cores)} · ${gib(g.memory_gib)} memory · ${gib(g.disk_gib)} disk`;
}

function renderRequests() {
  const box = $('requests');
  box.replaceChildren();
  $('requests-section').hidden = snap.requests.length === 0;
  for (const r of snap.requests) {
    const accepting = busy.has(`accept:${r.id}`);
    const declining = busy.has(`decline:${r.id}`);
    box.append(el('div', { class: 'item request' },
      el('div', { class: 'title', text: `${r.peer_name} asks to use this computer` }),
      el('div', { class: 'limits', text: limitsLine(r) }),
      el('div', { class: 'small muted', text: until(r.expires_at) }),
      r.detail ? el('div', { class: 'reason', text: `“${r.detail}”` }) : null,
      ...r.modes.map((m) => el('div', { class: 'small muted', text: MODE_TEXT[m] || m })),
      el('div', { class: 'small muted', text: 'No network while running. You can revoke it at any time.' }),
      accepting ? el('div', { class: 'waiting', text: presenceHint() }) : null,
      el('div', { class: 'actions' },
        el('button', {
          text: 'Decline', disabled: accepting || declining,
          onclick: () => act(`decline:${r.id}`, () => invoke('respond', { grantId: r.id, accept: false }), 'Declined'),
        }),
        el('button', {
          class: 'primary', text: 'Accept', disabled: accepting || declining,
          onclick: () => act(`accept:${r.id}`, () => invoke('respond', { grantId: r.id, accept: true }), `Accepted: ${r.peer_name} can use this computer`),
        }),
      ),
    ));
  }
}

function renderPairings() {
  const box = $('pairing-compare');
  box.replaceChildren();
  const live = snap.pairings.filter((p) => p.state === 'compare' || p.state === 'waiting');
  $('pairing-compare-section').hidden = live.length === 0;
  for (const p of live) {
    if (p.state === 'waiting') {
      box.append(el('div', { class: 'item' },
        el('div', { class: 'title', text: `Connecting to ${p.peer_name || 'the other device'}…` })));
      continue;
    }
    const key = `pair:${p.session}`;
    const confirming = busy.has(key);
    box.append(el('div', { class: 'item request' },
      el('div', { class: 'title', text: `Pairing with ${p.peer_name}` }),
      el('div', { class: 'small muted', text: 'Both devices must show exactly this code:' }),
      el('div', { class: 'code', text: p.code }),
      p.name_warning
        ? el('div', { class: 'warnline', text: `A device called “${p.peer_name}” paired before with a different key. Only continue if you just set it up again.` })
        : null,
      confirming ? el('div', { class: 'waiting', text: presenceHint() }) : null,
      el('div', { class: 'actions' },
        el('button', {
          class: 'danger', text: "Codes don't match", disabled: confirming,
          onclick: () => act(`no:${p.session}`, () => invoke('confirm_pairing', { session: p.session, codesMatch: false }), 'Pairing cancelled'),
        }),
        el('button', {
          class: 'primary', text: 'Codes match', disabled: confirming,
          onclick: () => act(key, () => invoke('confirm_pairing', { session: p.session, codesMatch: true }), `Paired with ${p.peer_name}`),
        }),
      ),
    ));
  }
}

function renderGrants() {
  const lent = $('lent');
  lent.replaceChildren();
  if (snap.lent.length === 0) {
    lent.append(el('div', { class: 'empty', text: 'No device can use this computer right now.' }));
  }
  for (const g of snap.lent) {
    const key = `revoke:${g.id}`;
    lent.append(el('div', { class: 'item' },
      el('div', { class: 'row between' },
        el('span', { class: 'title', text: g.peer_name }),
        g.state === 'paused' ? el('span', { class: 'pill paused', text: 'Paused' }) : null),
      el('div', { class: 'limits', text: limitsLine(g) }),
      el('div', { class: 'small muted', text: `${until(g.expires_at)} · ${g.detail} · in ${g.modes.join(' or ')}` }),
      el('div', { class: 'actions' },
        el('button', {
          class: 'danger', text: 'Revoke', disabled: busy.has(key),
          onclick: () => act(key, () => invoke('revoke', { grantId: g.id }), `Revoked: ${g.peer_name} can no longer use this computer`),
        })),
    ));
  }
  const borrowed = $('borrowed');
  borrowed.replaceChildren();
  $('borrowed-section').hidden = snap.borrowed.length === 0;
  for (const g of snap.borrowed) {
    borrowed.append(el('div', { class: 'item' },
      el('div', { class: 'title', text: g.peer_name }),
      el('div', { class: 'limits', text: limitsLine(g) }),
      el('div', { class: 'small muted', text: until(g.expires_at) }),
      el('div', { class: 'small muted', text: `Runs in: ${g.modes.join(' or ')}. Use gmc run --peer … -- <command>` }),
    ));
  }
}

function renderNearby() {
  const near = snap.peers.filter((p) => !p.paired);
  $('nearby-box').hidden = near.length === 0;
  const box = $('nearby');
  box.replaceChildren();
  for (const p of near) {
    const key = `near:${p.fingerprint}`;
    box.append(el('div', { class: 'item row between' },
      el('span', {},
        el('span', { class: 'title', text: p.name }),
        el('span', { class: 'mono muted small', text: `  ${shortFp(p.fingerprint)}` })),
      el('button', {
        class: 'primary small-btn', text: 'Pair', disabled: busy.has(key),
        onclick: () => act(key, () => invoke('start_pairing_nearby', { fingerprint: p.fingerprint }),
          'Connecting… compare the code when it appears'),
      })));
  }
}

function renderPeers() {
  renderNearby();
  const box = $('peers');
  box.replaceChildren();
  const paired = snap.peers.filter((p) => p.paired);
  if (paired.length === 0) {
    box.append(el('div', { class: 'empty', text: 'No paired devices yet. Pair one to lend or borrow.' }));
  }
  for (const p of paired) {
    const asking = confirmUnpair === p.fingerprint;
    const key = `unpair:${p.fingerprint}`;
    box.append(el('div', { class: 'item' },
      el('div', { class: 'row between' },
        el('span', { class: 'title', text: p.name }),
        el('span', { class: 'mono muted small', text: shortFp(p.fingerprint) })),
      p.link ? el('div', { class: 'small muted', text: `Last link test: ${p.link}` }) : null,
      el('div', { class: 'actions' },
        asking ? el('button', { text: 'Keep', onclick: () => { confirmUnpair = null; render(); } }) : null,
        el('button', {
          class: asking ? 'danger solid' : 'danger', disabled: busy.has(key),
          text: asking ? 'Unpair: revokes everything' : 'Unpair',
          onclick: () => {
            if (!asking) { confirmUnpair = p.fingerprint; render(); return; }
            confirmUnpair = null;
            act(key, () => invoke('unpair', { fingerprint: p.fingerprint }), `Unpaired ${p.name}`);
          },
        })),
    ));
  }
}

// ------------------------------------------------------------------ controls

function prefsFromBoxes() {
  return { battery: $('opt-battery').checked, idle: $('opt-idle').checked };
}

$('lend-toggle').addEventListener('click', () => {
  const s = snap?.status;
  if (!s) return;
  const p = prefsFromBoxes();
  const enable = !s.lending;
  act('lend', async () => {
    await invoke('set_lending', { enabled: enable, idleOnly: p.idle, allowOnBattery: !p.battery });
    localPrefs = null;
  }, enable ? 'Lending is on' : 'Lending is off; every grant was revoked');
});

for (const id of ['opt-battery', 'opt-idle']) {
  $(id).addEventListener('change', () => {
    const p = prefsFromBoxes();
    if (!snap?.status?.lending) { localPrefs = p; return; }
    act('lend', () => invoke('set_lending', { enabled: true, idleOnly: p.idle, allowOnBattery: !p.battery }));
  });
}

for (const m of ['container', 'sandbox']) {
  $(`rt-${m}`).addEventListener('change', () => {
    const modes = ['container', 'sandbox'].filter((x) => $(`rt-${x}`).checked);
    const adding = modes.some((x) => !snap.status.lend_modes.includes(x));
    if (adding) toast(presenceHint());
    act('modes', () => invoke('set_lend_modes', { modes }),
      modes.length ? `Lending tasks in: ${modes.join(', ')}` : 'Lending no way of running tasks');
  });
}

$('stop-all').addEventListener('click', () =>
  act('stop', () => invoke('stop_all'), 'Stopped: every grant revoked, running tasks stopped'));

async function openMyTicket() {
  $('my-ticket').value = 'Opening…';
  try {
    const t = await invoke('open_pairing');
    $('my-ticket').value = t.ticket;
    ticketCloses = t.closes_at;
  } catch (e) {
    $('my-ticket').value = '';
    toast(String(e), true);
  }
}

function showTab(name) {
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === name);
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== name;
  if (name === 'mine') openMyTicket();
}

$('pair-open').addEventListener('click', () => {
  const panel = $('pair-panel');
  panel.hidden = !panel.hidden;
  $('pair-open').textContent = panel.hidden ? 'Pair a device' : 'Close';
  if (!panel.hidden) showTab('mine');
});
for (const b of document.querySelectorAll('.tab')) b.addEventListener('click', () => showTab(b.dataset.tab));

$('copy-ticket').addEventListener('click', async () => {
  const text = $('my-ticket').value;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    $('my-ticket').select();
    document.execCommand('copy');
  }
  toast('Ticket copied');
});

$('start-pair').addEventListener('click', () => {
  const ticket = $('their-ticket').value.trim();
  if (!ticket) return;
  act('start-pair', async () => {
    await invoke('start_pairing', { ticket });
    $('their-ticket').value = '';
  }, 'Connecting… compare the code when it appears');
});

setInterval(() => {
  if (ticketCloses && !$('pair-panel').hidden) {
    const left = Math.max(0, Math.round(ticketCloses - Date.now() / 1000));
    $('ticket-timer').textContent = left > 0 ? `Open for ${left} s` : 'Closed. Switch tabs to open it again.';
  }
}, 1000);

$('start-daemon').addEventListener('click', () =>
  act('service', () => invoke('set_start_at_login', { enabled: true }), 'GimmeCores is starting'));
$('opt-login').addEventListener('change', () => {
  const enabled = $('opt-login').checked;
  act('service', () => invoke('set_start_at_login', { enabled }),
    enabled ? 'GimmeCores starts at login' : 'GimmeCores stopped and will not start at login');
});
$('opt-discovery').addEventListener('change', () => {
  const on = $('opt-discovery').checked;
  act('discovery', () => invoke('set_discovery', { on }),
    on ? 'Your paired devices can find this one' : 'Discovery is off');
});
$('install-cli').addEventListener('click', () =>
  act('cli', () => invoke('install_cli'), 'Installed: type gmc in Terminal'));

refresh();
setInterval(refresh, 2000);

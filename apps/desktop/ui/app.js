'use strict';
// GimmeCores desktop UI. Everything another device chooses (names, reasons, commands) is
// inserted as text, never as HTML. Approvals are checked again by gmcd with Touch ID / your
// password. No inline styles (the Content-Security-Policy forbids them): bar widths are set
// through element.style, which the policy allows.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let snap = null;
let activity = null;          // the latest activity listing
let service = { start_at_login: false, bundled: false, cli_installed: false, homebrew_service: false, reduced: false };
const busy = new Set();
let localPrefs = null;        // protection choices made while lending is off
let confirmUnpair = null;     // fingerprint awaiting a second click
let confirmTrust = null;
let ticketCloses = 0;
let view = 'activity';
try { view = localStorage.getItem('gmc-view') || 'activity'; } catch { /* storage unavailable */ }

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'disabled') e.disabled = !!v;
    else if (k === 'style') throw new Error('no inline styles');
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

// A section is rebuilt only when what it shows changed (its data, the actions in progress, the
// minute for "… left" texts). Tasks starting and ending many times a second must never
// replace a button under the pointer.
const memo = new Map();
function changed(key, ...inputs) {
  const s = JSON.stringify([Math.floor(Date.now() / 60000), [...busy].sort(), ...inputs]);
  if (memo.get(key) === s) return false;
  memo.set(key, s);
  return true;
}

function toast(message, error = false) {
  const t = $('toast');
  t.textContent = message;
  t.className = error ? 'toast error' : 'toast';
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, error ? 7000 : 3500);
}

// ------------------------------------------------------------------ formatting

const GIB = 1024 ** 3;
const MIB = 1024 ** 2;
const gib = (x) => `${x >= 10 ? x.toFixed(0) : x.toFixed(1)} GiB`;
function bytes(b) {
  if (b === null || b === undefined) return null;
  if (b >= GIB) return `${(b / GIB).toFixed(b >= 10 * GIB ? 0 : 1)} GiB`;
  if (b >= 10 * MIB) return `${Math.round(b / MIB)} MiB`;
  return `${(b / MIB).toFixed(1)} MiB`;
}
const cores = (c) => `${Number.isInteger(c) ? c : c.toFixed(1)} ${c === 1 ? 'core' : 'cores'}`;
function dur(ms) {
  if (ms < 1000) return 'under 1 s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`;
  return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min`;
}
function ago(sec) {
  const d = Math.max(0, Date.now() / 1000 - sec);
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return new Date(sec * 1000).toLocaleDateString();
}
const clock = (sec) => new Date(sec * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
function until(sec) {
  if (!sec) return '';
  const left = Math.max(0, sec - Date.now() / 1000);
  const h = Math.floor(left / 3600), m = Math.floor((left % 3600) / 60);
  const span = h >= 24 ? `${Math.floor(h / 24)} d` : h ? `${h} h ${m} min` : `${m} min`;
  return `until ${clock(sec)} (${span} left)`;
}
const shortFp = (fp) => fp.split('-').slice(0, 2).join('-');
const presenceHint = () =>
  snap?.status?.presence_required ? `Confirm with ${snap.status.presence_method} on this computer…` : 'Working…';
const MODE = { sandbox: 'Sandbox', container: 'Container', native: 'As you, no sandbox' };
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// ------------------------------------------------------------------ data

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
  await refreshActivity();
  render();
}

async function refreshActivity() {
  if (!snap?.running) { activity = null; return; }
  try {
    activity = await invoke('activity');
  } catch {
    activity = null; // an older gmcd: the rest of the window still works
  }
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

  renderAttention(s);
  renderViews();
  renderActivity();
  renderPeers();
  renderSettings(s);
}

function renderViews() {
  for (const b of document.querySelectorAll('.view-tab')) {
    b.setAttribute('aria-selected', String(b.dataset.view === view));
  }
  for (const p of document.querySelectorAll('[data-panel-view]')) p.hidden = p.dataset.panelView !== view;
  const running = activity?.running?.length || 0;
  $('count-activity').hidden = running === 0;
  $('count-activity').textContent = String(running);
  const paired = snap.peers.filter((p) => p.paired).length;
  $('count-devices').hidden = paired === 0;
  $('count-devices').textContent = String(paired);
}

function showView(name) {
  view = name;
  try { localStorage.setItem('gmc-view', name); } catch { /* storage unavailable */ }
  render();
  if (name === 'activity') pollSoon();
}

// --------------------------------------------- what needs you now (on every view)

const MODE_TEXT = {
  container: 'Runs in a container: it cannot see your files or other apps.',
  sandbox: "Runs in this computer's sandbox, as you: only its own folder, no network, your installed tools.",
  native: 'Runs directly as you, WITHOUT a sandbox.',
};

function limitsLine(g) {
  return `${cores(g.cores)} · ${gib(g.memory_gib)} memory · ${gib(g.disk_gib)} disk`;
}

function renderAttention(s) {
  renderRequests();
  renderPairings();
  // A service the system holds back runs tasks several times slower: never leave that hidden.
  const mine = service.bundled && service.start_at_login && !service.homebrew_service;
  const heldBack = !!s.performance_note || (mine && service.reduced);
  $('slow').hidden = !heldBack;
  if (heldBack) {
    $('slow-text').textContent = mine
      ? 'An earlier version started the background service at reduced priority. Restarting it '
        + 'fixes that (running tasks are stopped).'
      : s.performance_note;
    $('slow-fix').hidden = !mine;
    $('slow-fix').disabled = busy.has('service');
  }
  const paused = $('paused');
  paused.hidden = !(s.lending && s.pause_reason);
  const frozen = (activity?.running || []).filter((r) => r.phase === 'frozen').length;
  paused.textContent = `Lending is paused: ${s.pause_reason}. `
    + (frozen ? `${plural(frozen, 'task')} frozen until it clears; ` : '')
    + 'new tasks are refused.';
}

function renderRequests() {
  if (!changed('requests', snap.requests, snap.status.presence_required)) return;
  const box = $('requests');
  box.replaceChildren();
  $('requests-section').hidden = snap.requests.length === 0;
  for (const r of snap.requests) {
    const accepting = busy.has(`accept:${r.id}`);
    const declining = busy.has(`decline:${r.id}`);
    box.append(el('div', { class: 'item request' },
      el('div', { class: 'title', text: `${r.peer_name} asks to use this computer` }),
      el('div', { class: 'meta', text: `${limitsLine(r)} · ${until(r.expires_at)}` }),
      r.detail ? el('div', { class: 'reason', text: `“${r.detail}”` }) : null,
      ...r.modes.map((m) => el('div', { class: 'meta', text: MODE_TEXT[m] || m })),
      r.trusted ? el('div', { class: 'warnline', text: 'TRUSTED: Python objects (pickles) may be '
        + 'exchanged both ways. Tasks still run in the sandbox or a container here.' }) : null,
      el('div', { class: 'meta', text: 'No network while running. You can stop any task, or revoke this, at any time.' }),
      accepting ? el('div', { class: 'waiting', text: presenceHint() }) : null,
      el('div', { class: 'actions' },
        el('button', {
          type: 'button', text: 'Decline', disabled: accepting || declining,
          onclick: () => act(`decline:${r.id}`, () => invoke('respond', { grantId: r.id, accept: false }), 'Declined'),
        }),
        el('button', {
          type: 'button', class: 'primary', text: 'Accept', disabled: accepting || declining,
          onclick: () => act(`accept:${r.id}`, () => invoke('respond', { grantId: r.id, accept: true }), `Accepted: ${r.peer_name} can use this computer`),
        }),
      ),
    ));
  }
}

function renderPairings() {
  if (!changed('pairings', snap.pairings)) return;
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
      el('div', { class: 'meta', text: 'Both devices must show exactly this code:' }),
      el('div', { class: 'code', text: p.code }),
      p.name_warning
        ? el('div', { class: 'warnline', text: `A device called “${p.peer_name}” paired before with a different key. Only continue if you just set it up again.` })
        : null,
      confirming ? el('div', { class: 'waiting', text: presenceHint() }) : null,
      el('div', { class: 'actions' },
        el('button', {
          type: 'button', class: 'danger', text: "Codes don't match", disabled: confirming,
          onclick: () => act(`no:${p.session}`, () => invoke('confirm_pairing', { session: p.session, codesMatch: false }), 'Pairing cancelled'),
        }),
        el('button', {
          type: 'button', class: 'primary', text: 'Codes match', disabled: confirming,
          onclick: () => act(key, () => invoke('confirm_pairing', { session: p.session, codesMatch: true }), `Paired with ${p.peer_name}`),
        }),
      ),
    ));
  }
}

// --------------------------------------------- activity

function renderActivity() {
  const s = snap.status;
  // Who may use this computer, one line each.
  const lent = $('lent-summary');
  // The grant's running-task count is shown on the task cards, not here: leave it out.
  if (changed('lent', snap.lent.map(({ detail, ...g }) => g))) {
    lent.replaceChildren();
    for (const g of snap.lent) {
      const key = `revoke:${g.id}`;
      lent.append(el('div', { class: 'item compact grant-line' },
        el('div', { class: 'what' },
          el('div', {}, el('b', { text: g.peer_name }), ` may use ${cores(g.cores)} · ${gib(g.memory_gib)}`),
          el('div', { class: 'muted', text: [until(g.expires_at), g.state === 'paused' ? 'paused' : null, g.trusted ? 'Trusted' : null].filter(Boolean).join(' · ') })),
        el('button', {
          type: 'button', class: 'danger small', text: 'Revoke', disabled: busy.has(key),
          onclick: () => act(key, () => invoke('revoke', { grantId: g.id }), `Revoked: ${g.peer_name} can no longer use this computer`),
        })));
    }
  }
  $('stop-all').disabled = busy.has('stop') || (!s.lending && snap.lent.length === 0);
  renderRunning();
  renderBorrowed();
  renderRecent();
}

const rows = new Map();   // task id -> {root, refs}: live rows are updated in place

const PHASE = {
  preparing: ['Preparing', 'running'], starting: ['Starting', 'running'], running: ['Running', 'running'],
  frozen: ['Frozen', 'frozen'], stopping: ['Stopping', 'stopping'], collecting: ['Saving results', 'running'],
};
const FROZEN_WHY = { on_battery: 'on battery', hot: 'the computer is hot', owner_active: "you're using this computer", other: 'paused' };

function commandText(r) {
  return r.argv.map((a) => (a === '' || /\s/.test(a) ? `'${a}'` : a)).join(' ');
}

function meterRow(label, cls) {
  const fill = el('div', { class: 'meter-fill' });
  const meter = el('div', { class: `meter ${cls}` }, fill);
  const value = el('span', { class: 'v' });
  return { nodes: [el('span', { class: 'k', text: label }), meter, value], meter, fill, value };
}

function setMeter(m, now, asked, text) {
  m.value.textContent = text;
  m.value.classList.toggle('na', now === null || now === undefined);
  if (now === null || now === undefined || !asked) {
    m.meter.classList.add('none');
    return;
  }
  m.meter.classList.remove('none');
  m.meter.classList.toggle('over', now > asked * 1.05);
  m.fill.style.width = `${Math.min(100, (now / asked) * 100).toFixed(1)}%`;
}

function buildRow(r) {
  const refs = {};
  const row = { refs, last: r };
  refs.state = el('span', { class: 'state' });
  refs.time = el('span', { class: 'task-time' });
  refs.cmd = el('div', { class: 'cmd' });
  refs.meta = el('div', { class: 'meta' });
  refs.cpu = meterRow('CPU', 'cpu');
  refs.mem = meterRow('Memory', 'mem');
  refs.disk = el('span', { class: 'v' });
  refs.note = el('div', { class: 'task-note', hidden: true });
  refs.facts = el('dl', { class: 'facts', hidden: true, id: `facts-${r.id}` });
  refs.toggle = el('button', {
    type: 'button', class: 'link disclosure', text: 'Details', 'aria-expanded': 'false', 'aria-controls': `facts-${r.id}`,
    onclick: () => {
      const open = refs.facts.hidden;
      refs.facts.hidden = !open;
      refs.toggle.setAttribute('aria-expanded', String(open));
      if (open) renderFacts(refs.facts, row.last);
    },
  });
  refs.stop = el('button', {
    type: 'button', class: 'danger small', text: 'Stop task',
    onclick: () => act(`stop:${r.id}`, () => invoke('stop_task', { task: r.id }),
      `Stopped: ${r.label || r.argv[0] || 'the task'} for ${r.peer_name}. Its grant is unchanged.`),
  });
  const root = el('div', { class: 'item task', 'data-id': r.id },
    el('div', { class: 'task-head' }, refs.state, refs.time),
    refs.cmd,
    refs.meta,
    el('div', { class: 'figures' },
      ...refs.cpu.nodes, ...refs.mem.nodes,
      el('span', { class: 'k', text: 'Disk' }), el('span', {}), refs.disk),
    refs.note,
    el('div', { class: 'task-foot' }, refs.toggle, refs.stop),
    refs.facts);
  row.root = root;
  return row;
}

function fact(dl, k, ...v) {
  dl.append(el('dt', { text: k }), el('dd', {}, ...v));
}

function updateRow(row, r) {
  const { refs } = row;
  row.last = r;
  const [word, cls] = PHASE[r.phase] || ['Running', 'running'];
  refs.state.textContent = word;
  refs.state.className = `state ${cls}`;
  refs.time.textContent = r.run_ms ? dur(r.run_ms) : '';
  refs.cmd.replaceChildren(
    ...[r.label ? el('span', { class: 'cmd-label', text: r.label }) : null,
      commandText(r) || '(no command)'].filter(Boolean));
  refs.cmd.title = commandText(r);
  refs.meta.textContent = [`for ${r.peer_name}`, MODE[r.mode] || r.mode, `id ${r.short}`].join(' · ');

  const measured = r.measured_by !== 'none';
  setMeter(refs.cpu, r.cpu_now_cores, r.asked_cores,
    r.cpu_now_cores !== null ? `${cores(+r.cpu_now_cores.toFixed(1))} of ${cores(r.asked_cores)}` : 'not measured');
  setMeter(refs.mem, r.memory_now, r.asked_memory,
    r.memory_now !== null ? `${bytes(r.memory_now)} of ${bytes(r.asked_memory)}` : 'not measured');
  refs.disk.textContent = r.disk !== null ? `${bytes(r.disk)} in its folder` : 'not measured';
  refs.disk.classList.toggle('na', r.disk === null);

  let note = '';
  let info = false;
  if (r.phase === 'frozen') note = `Frozen: ${FROZEN_WHY[r.frozen_why] || 'lending is paused'}.`;
  else if (r.speed === 'background' || r.speed === 'reduced') note = 'Running slower than this computer can: see the warning above.';
  else if (r.cpu_now_cores !== null && !r.cpu_limit_enforced && r.cpu_now_cores > r.asked_cores * 1.05) {
    note = 'Using more CPU than it asked for: the sandbox monitors CPU, it does not cap it.';
  } else if (!measured) {
    note = 'Container figures are not measured yet; Docker caps its CPU and memory.';
    info = true;
  }
  refs.note.hidden = !note;
  refs.note.textContent = note;
  refs.note.className = info ? 'task-note info' : 'task-note';

  refs.stop.disabled = !r.can_stop || busy.has(`stop:${r.id}`);
  refs.stop.textContent = r.phase === 'stopping' ? 'Stopping…' : 'Stop task';

  // Details are rebuilt only while open (an open panel stays open across updates).
  if (!refs.facts.hidden) renderFacts(refs.facts, r);
}

function renderFacts(dl, r) {
  dl.replaceChildren();
  const chips = el('div', { class: 'chips' }, ...r.argv.map((a) =>
    el('span', { class: a.startsWith('[hidden') || a.includes('=[hidden') ? 'chip hidden-arg' : 'chip', text: a })));
  const argNotes = [];
  if (r.argv_total > r.argv.length) argNotes.push(`${r.argv.length} of ${r.argv_total} arguments shown.`);
  if (r.argv_cut) argNotes.push('Long arguments are cut at 64 characters.');
  if (r.argv_hidden) argNotes.push('Arguments that look like secrets are hidden (best effort).');
  fact(dl, 'Command', chips, argNotes.length ? el('div', { class: 'muted', text: argNotes.join(' ') }) : null);
  if (r.image) fact(dl, 'Image', r.image);
  if (r.env_total) {
    fact(dl, 'Variables', `${r.env_names.join(', ')}${r.env_total > r.env_names.length ? ` and ${r.env_total - r.env_names.length} more` : ''} (names only)`);
  }
  fact(dl, 'CPU time', r.cpu_time_ms !== null ? `${dur(r.cpu_time_ms)}${r.measured_by === 'process_tree' ? ' (at least: very short processes can be missed)' : ''}` : el('span', { class: 'na', text: 'not measured' }));
  fact(dl, 'Peak memory', r.memory_peak !== null ? bytes(r.memory_peak) : el('span', { class: 'na', text: 'not measured' }));
  if (r.processes !== null) fact(dl, 'Processes', String(r.processes));
  if (r.frozen_ms) fact(dl, 'Frozen', dur(r.frozen_ms));
  const limit = r.effective_timeout_secs ?? r.timeout_secs;
  fact(dl, 'Asked for', `${cores(r.asked_cores)} · ${bytes(r.asked_memory)}${limit ? ` · stop after ${dur(limit * 1000)}` : ''}`);
  fact(dl, 'Grant', `${cores(r.grant_cores)} · ${bytes(r.grant_memory)} · ${bytes(r.grant_disk)} disk, ${until(r.grant_until)}`);
  if (r.started_at) fact(dl, 'Started', clock(r.started_at));
  fact(dl, 'Measured', r.measured_by === 'process_tree'
    ? 'From its processes, twice a second, by this computer.'
    : 'Not measured for this way of running yet.');
}

function renderRunning() {
  const box = $('running');
  const list = activity?.running || [];
  const seen = new Set();
  for (const r of list) {
    seen.add(r.id);
    let row = rows.get(r.id);
    if (!row) {
      row = buildRow(r);
      rows.set(r.id, row);
    }
    updateRow(row, r);
  }
  for (const [id, row] of rows) {
    if (!seen.has(id)) { row.root.remove(); rows.delete(id); }
  }
  for (const n of box.querySelectorAll('.empty, .footnote')) n.remove();
  if (!list.length) {
    box.append(emptyRunning());
    return;
  }
  // Keep order (oldest first) without re-creating nodes.
  list.forEach((r, i) => {
    const node = rows.get(r.id).root;
    if (box.children[i] !== node) box.insertBefore(node, box.children[i] || null);
  });
  if (activity?.omitted) {
    box.append(el('div', { class: 'footnote', text: `…and ${activity.omitted} more (see gmc tasks).` }));
  }
}

function emptyRunning() {
  const s = snap.status;
  const why = !s.lending
    ? 'Lending is off, so no other device can use this computer.'
    : snap.lent.length
      ? 'Tasks from the devices above show here, with what they use.'
      : 'No device can use this computer right now. Requests appear at the top when one asks.';
  return el('div', { class: 'empty' }, 'Nothing is running here.', el('span', { class: 'hint', text: why }));
}

function renderBorrowed() {
  if (!changed('borrowed', snap.borrowed)) return;
  const box = $('borrowed');
  box.replaceChildren();
  $('borrowed-section').hidden = snap.borrowed.length === 0;
  for (const g of snap.borrowed) {
    box.append(el('div', { class: 'item compact grant-line' },
      el('div', { class: 'what' },
        el('div', {}, el('b', { text: g.peer_name }), `: ${cores(g.cores)} · ${gib(g.memory_gib)}`),
        el('div', { class: 'muted', text: `${g.modes.map((m) => MODE[m] || m).join(' or ')} · ${until(g.expires_at)}${g.trusted ? ' · Trusted' : ''}` }))));
  }
  if (snap.borrowed.length) {
    box.append(el('div', { class: 'footnote' }, 'Run something there from Terminal: ', el('code', { text: 'gmc run -- <command>' })));
  }
}

const OUTCOME = {
  succeeded: ['Done', 'done'], failed: ['Failed', 'failed'], timed_out: ['Timed out', 'stopped'],
  cancelled: ['Stopped', 'stopped'], revoked: ['Stopped', 'stopped'], limit_exceeded: ['Over limit', 'stopped'],
  rejected: ['Not run', 'failed'],
};

function renderRecent() {
  if (!changed('recent', activity?.recent ?? null, activity?.since ?? null)) return;
  const box = $('recent');
  box.replaceChildren();
  const groups = activity?.recent || [];
  if (!groups.length) {
    box.append(el('div', { class: 'empty' }, activity ? 'Nothing has finished here yet.' : 'Activity needs a newer GimmeCores service.'));
  }
  for (const g of groups) {
    const last = g.last;
    const end = last.ending || {};
    const allFine = g.failed + g.stopped + g.not_run === 0;
    const [word, cls] = g.count > 1 ? (allFine ? ['Done', 'done'] : ['Mixed', 'failed']) : (OUTCOME[end.status] || ['Ended', '']);
    const title = commandText(last);
    const outcome = g.count > 1
      ? [`${g.count} runs`, `${g.succeeded} finished`, g.failed ? `${g.failed} failed` : null,
        g.stopped ? `${g.stopped} stopped` : null, g.not_run ? `${g.not_run} not run` : null].filter(Boolean).join(' · ')
      : end.words;
    const figures = [
      `ran ${dur(g.run_ms_total)}${g.frozen_ms_total ? ` (${dur(g.frozen_ms_total)} frozen)` : ''}`,
      g.cpu_time_total_ms !== null ? `CPU ${dur(g.cpu_time_total_ms)}` : 'CPU not measured',
      g.memory_peak_max !== null ? `peak ${bytes(g.memory_peak_max)}` : null,
      g.slowest_speed === 'background' || g.slowest_speed === 'reduced' ? 'ran at reduced speed' : null,
    ].filter(Boolean).join(' · ');
    box.append(el('div', { class: 'item task' },
      el('div', { class: 'task-head' }, el('span', { class: `state ${cls}`, text: word }), el('span', { class: 'task-time', text: ago(g.last_at) })),
      el('div', { class: 'cmd', title }, last.label ? el('span', { class: 'cmd-label', text: last.label }) : null, title, g.count > 1 ? ` ×${g.count}` : null),
      el('div', { class: 'meta', text: `for ${g.peer_name} · ${outcome}` }),
      el('div', { class: 'meta', text: figures }),
      g.count > 1 && g.last_problem?.ending
        ? el('div', { class: 'task-note', text: `Last problem: ${g.last_problem.ending.words}` }) : null,
      end.message && g.count === 1 ? el('div', { class: 'task-note', text: end.message }) : null));
  }
  $('recent-note').textContent = activity?.since
    ? `Since GimmeCores started at ${clock(activity.since)}. Kept in memory only.` : '';
}

// --------------------------------------------- devices

// Shown before Trusted mode is turned on (threat model, section 6).
const TRUSTED_WARNING = 'Trusted mode lets this device run any code on your machine through '
  + 'returned results. Only enable it between your own devices or someone you trust completely. '
  + 'It lets Python code send functions and results as pickles (lambdas, notebooks), lasts 30 '
  + 'days, and both devices must turn it on.';

function renderNearby() {
  const near = snap.peers.filter((p) => !p.paired);
  $('nearby-box').hidden = near.length === 0;
  const box = $('nearby');
  box.replaceChildren();
  for (const p of near) {
    const key = `near:${p.fingerprint}`;
    box.append(el('div', { class: 'item compact grant-line' },
      el('div', { class: 'what' }, el('b', { text: p.name }), el('span', { class: 'mono muted', text: `  ${shortFp(p.fingerprint)}` })),
      el('button', {
        type: 'button', class: 'primary small', text: 'Pair', disabled: busy.has(key),
        onclick: () => act(key, () => invoke('start_pairing_nearby', { fingerprint: p.fingerprint }),
          'Connecting… compare the code when it appears'),
      })));
  }
}

function useBlock(title, g, running, action) {
  return el('div', { class: 'use' },
    el('h4', { text: title }),
    el('div', { class: 'line', text: limitsLine(g) }),
    el('div', { class: 'sub', text: [g.modes.map((m) => MODE[m] || m).join(' or '), until(g.expires_at), g.state === 'paused' ? 'paused' : null, g.trusted ? 'Trusted' : null].filter(Boolean).join(' · ') }),
    running !== null ? el('div', { class: 'sub', text: running ? `${plural(running, 'task')} running now` : 'Nothing running now' }) : null,
    action ? el('div', { class: 'device-actions' }, action) : null);
}

function renderPeers() {
  const running = (activity?.running || []).map((r) => r.peer_name);
  const lent = snap.lent.map(({ detail, ...g }) => g);
  if (!changed('peers', snap.peers, lent, snap.borrowed, running, confirmUnpair, confirmTrust)) return;
  renderNearby();
  const box = $('peers');
  box.replaceChildren();
  const paired = snap.peers.filter((p) => p.paired);
  if (paired.length === 0) {
    box.append(el('div', { class: 'empty' }, 'No paired devices yet.', el('span', { class: 'hint', text: 'Pair one to lend or borrow.' })));
  }
  for (const p of paired) {
    const asking = confirmUnpair === p.fingerprint;
    const key = `unpair:${p.fingerprint}`;
    const trustKey = `trust:${p.fingerprint}`;
    const trusted = p.trusted_until != null;
    const askingTrust = confirmTrust === p.fingerprint;
    const lentTo = snap.lent.filter((g) => g.peer_fingerprint === p.fingerprint);
    const borrowedFrom = snap.borrowed.filter((g) => g.peer_fingerprint === p.fingerprint);
    const runningHere = (activity?.running || []).filter((r) => r.peer_name === p.name).length;
    box.append(el('div', { class: 'card device-card' },
      el('div', { class: 'device-head' },
        el('span', { class: 'device-name', text: p.name }),
        trusted ? el('span', { class: 'pill trusted', text: 'Trusted' }) : el('span', { class: 'mono muted small', text: shortFp(p.fingerprint) })),
      ...lentTo.map((g) => {
        const rk = `revoke:${g.id}`;
        return useBlock(`${p.name} may use this computer`, g, runningHere,
          el('button', {
            type: 'button', class: 'danger small', text: 'Revoke', disabled: busy.has(rk),
            onclick: () => act(rk, () => invoke('revoke', { grantId: g.id }), `Revoked: ${g.peer_name} can no longer use this computer`),
          }));
      }),
      ...borrowedFrom.map((g) => useBlock(`You may use ${p.name}`, g, null, null)),
      !lentTo.length && !borrowedFrom.length
        ? el('div', { class: 'muted small', text: 'No grants either way. Ask from the other device, or from Terminal with gmc grants request.' }) : null,
      p.link ? el('div', { class: 'muted small', text: `Last link test: ${p.link}` }) : null,
      trusted ? el('div', { class: 'warnline', text:
        `Trusted mode is on here until ${new Date(p.trusted_until * 1000).toLocaleDateString()}`
        + (p.trusted_remote ? ' (and on that device).' : '. It must be on there too.') }) : null,
      askingTrust ? el('div', { class: 'banner warn', text: TRUSTED_WARNING }) : null,
      busy.has(trustKey) && !trusted ? el('div', { class: 'waiting', text: presenceHint() }) : null,
      el('div', { class: 'device-actions' },
        askingTrust ? el('button', { type: 'button', class: 'small', text: 'Cancel', onclick: () => { confirmTrust = null; render(); } }) : null,
        el('button', {
          type: 'button', class: askingTrust ? 'danger solid small' : 'small', disabled: busy.has(trustKey),
          text: trusted ? 'Turn off Trusted mode' : askingTrust ? 'Turn on for 30 days' : 'Trusted mode…',
          onclick: () => {
            // Turning it off only reduces access: no questions.
            if (trusted) {
              act(trustKey, () => invoke('set_trusted_mode', { fingerprint: p.fingerprint, enabled: false }),
                `Trusted mode with ${p.name} is off`);
              return;
            }
            if (!askingTrust) { confirmTrust = p.fingerprint; render(); return; }
            confirmTrust = null;
            act(trustKey, () => invoke('set_trusted_mode', { fingerprint: p.fingerprint, enabled: true }),
              `Trusted mode with ${p.name} is on for 30 days`);
          },
        }),
        asking ? el('button', { type: 'button', class: 'small', text: 'Keep', onclick: () => { confirmUnpair = null; render(); } }) : null,
        el('button', {
          type: 'button', class: asking ? 'danger solid small' : 'danger small', disabled: busy.has(key),
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

// --------------------------------------------- settings

function renderSettings(s) {
  const toggle = $('lend-toggle');
  toggle.setAttribute('aria-checked', String(s.lending));
  toggle.disabled = busy.has('lend');
  const prefs = localPrefs || { battery: s.pause_on_battery, idle: s.idle_only, hot: s.pause_when_hot };
  $('opt-battery').checked = prefs.battery;
  $('opt-idle').checked = prefs.idle;
  $('opt-hot').checked = prefs.hot;
  $('opt-battery').disabled = $('opt-idle').disabled = $('opt-hot').disabled = busy.has('lend');
  $('lending-sub').textContent = busy.has('lend')
    ? presenceHint()
    : s.lending
      ? 'Paired devices may ask to use this computer. You approve every request.'
      : 'Off: no device can use this computer.';
  $('presence').textContent = s.presence_required
    ? `Approvals need ${s.presence_method}`
    : 'Approvals do NOT need Touch ID or your password here';
  $('presence').className = s.presence_required ? 'muted small' : 'small warn-text';
  $('machine').textContent = `${cores(s.cpu_cores)} · ${gib(s.memory_gib)}`;
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
  // This computer.
  const brew = service.homebrew_service;
  $('settings-section').hidden = false;
  for (const id of ['opt-login', 'install-cli']) $(id).closest('.setting').hidden = !service.bundled;
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
  $('install-cli').disabled = busy.has('cli');
  $('opt-discovery').checked = s.discovery;
  $('opt-discovery').disabled = busy.has('discovery');
}

// ------------------------------------------------------------------ controls

for (const b of document.querySelectorAll('.view-tab')) b.addEventListener('click', () => showView(b.dataset.view));
$('pill').addEventListener('click', () => showView('settings'));

function prefsFromBoxes() {
  return { battery: $('opt-battery').checked, idle: $('opt-idle').checked, hot: $('opt-hot').checked };
}

$('lend-toggle').addEventListener('click', () => {
  const s = snap?.status;
  if (!s) return;
  const p = prefsFromBoxes();
  const enable = !s.lending;
  act('lend', async () => {
    await invoke('set_lending', { enabled: enable, idleOnly: p.idle, allowOnBattery: !p.battery, allowWhenHot: !p.hot });
    localPrefs = null;
  }, enable ? 'Lending is on' : 'Lending is off; every grant was revoked');
});

for (const id of ['opt-battery', 'opt-idle', 'opt-hot']) {
  $(id).addEventListener('change', () => {
    const p = prefsFromBoxes();
    if (!snap?.status?.lending) { localPrefs = p; return; }
    act('lend', () => invoke('set_lending', { enabled: true, idleOnly: p.idle, allowOnBattery: !p.battery, allowWhenHot: !p.hot }));
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
// Installs this version's login item and starts the service again (see service.rs).
$('slow-fix').addEventListener('click', () =>
  act('service', () => invoke('set_start_at_login', { enabled: true }), 'Restarted: tasks now run at full speed'));
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

// ------------------------------------------------------------------ live figures

// While the Activity view is visible and something runs, figures are read once a second (a
// plain call: nothing is pushed). Rows update in place.
let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    if (!document.hidden && view === 'activity' && snap?.running && activity?.running?.length) {
      const before = activity.revision;
      await refreshActivity();
      if (activity?.revision !== before) {
        // A task started, ended or changed phase: everything else may have changed too.
        await refresh();
      } else {
        // Figures only: the live rows update in place; nothing else is rebuilt, so a click
        // on another button is never lost.
        renderRunning();
      }
    }
  } finally {
    polling = false;
  }
}
function pollSoon() { setTimeout(poll, 50); }
setInterval(poll, 1000);

// The tab bar sticks right under the header, whatever the header's height.
new ResizeObserver(() => {
  document.documentElement.style.setProperty('--top-h', `${document.querySelector('.top').offsetHeight}px`);
}).observe(document.querySelector('.top'));

refresh();
// The app's background task says when the daemon reports a change; the timer is a fallback.
window.__TAURI__.event.listen('gmc-changed', () => refresh());
setInterval(refresh, 10000);

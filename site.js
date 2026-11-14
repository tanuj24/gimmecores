'use strict';
// Downloads come from the latest published GitHub release of tanuj24/gimmecores, and only
// files that release really holds are offered (nothing is guessed). Text from GitHub is
// inserted as text, never as HTML.

const REPO = 'tanuj24/gimmecores';
const RELEASES = `https://github.com/${REPO}/releases`;
const FILES_FROM = `https://github.com/${REPO}/releases/download/`;
const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) if (c) e.append(c);
  return e;
}

// ------------------------------------------------------------ which computer

function visitorOs() {
  const p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
  const ua = navigator.userAgent || '';
  if (/android|iphone|ipad|ipod/i.test(ua)) return 'phone';
  if (/win/i.test(p) || /windows/i.test(ua)) return 'windows';
  if (/mac/i.test(p) || /mac os x/i.test(ua)) return 'mac';
  if (/linux|x11|cros/i.test(p) || /linux|x11/i.test(ua)) return 'linux';
  return 'other';
}

const TABS = ['mac', 'linux', 'windows'];
function showTab(name) {
  for (const t of TABS) {
    const selected = t === name;
    $(`tab-${t}`).setAttribute('aria-selected', String(selected));
    $(`tab-${t}`).tabIndex = selected ? 0 : -1;
    $(`panel-${t}`).hidden = !selected;
  }
}
for (const t of TABS) $(`tab-${t}`).addEventListener('click', () => showTab(t));
document.querySelector('.tabs').addEventListener('keydown', (e) => {
  const i = TABS.findIndex((t) => $(`tab-${t}`).getAttribute('aria-selected') === 'true');
  const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
  if (!step) return;
  const next = TABS[(i + step + TABS.length) % TABS.length];
  showTab(next);
  $(`tab-${next}`).focus();
});

const os = visitorOs();
showTab(TABS.includes(os) ? os : 'mac');
const HERO = { mac: 'Download for Mac', linux: 'Download for Linux', windows: 'Downloads', phone: 'Downloads', other: 'Downloads' };
$('hero-download').textContent = HERO[os];

// ------------------------------------------------------------ the latest release

// Release files this page knows how to describe. Anything else is left to the release page.
const KNOWN = [
  { re: /^GimmeCores\.dmg$/, os: 'mac', main: true, what: 'GimmeCores for Mac', detail: 'Apple silicon · the app, with gmc and gmcd inside' },
  { re: /^gimmecores-aarch64-apple-darwin\.tar\.gz$/, os: 'mac', what: 'Command line only', detail: 'Apple silicon · gmc, gmcd' },
  { re: /^gimmecores_[0-9.]+_amd64\.deb$/, os: 'linux', main: true, what: 'Debian and Ubuntu (x86-64)', detail: 'the app, gmc and gmcd' },
  { re: /^gimmecores_[0-9.]+_arm64\.deb$/, os: 'linux', main: true, what: 'Debian and Ubuntu (ARM64)', detail: 'the app, gmc and gmcd' },
  { re: /^gimmecores-x86_64-unknown-linux-gnu\.tar\.gz$/, os: 'linux', what: 'Command line only (x86-64)', detail: 'gmc, gmcd · any distribution' },
  { re: /^gimmecores-aarch64-unknown-linux-gnu\.tar\.gz$/, os: 'linux', what: 'Command line only (ARM64)', detail: 'gmc, gmcd · any distribution' },
];

const size = (b) => (b >= 1048576 ? `${(b / 1048576).toFixed(0)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);
const day = (iso) => {
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
};

function released(release) {
  const files = { mac: [], linux: [] };
  for (const a of release.assets || []) {
    const url = String(a.browser_download_url || '');
    if (!url.startsWith(FILES_FROM) || url.includes('..')) continue;
    const k = KNOWN.find((x) => x.re.test(String(a.name)));
    if (k) files[k.os].push({ ...k, name: String(a.name), url, bytes: Number(a.size) || 0 });
  }
  const sums = (release.assets || []).some((a) => /^SHA256SUMS/.test(String(a.name)));
  const version = String(release.tag_name || '').replace(/^v/, '');
  const line = $('release-line');
  line.textContent = '';
  line.append(
    `GimmeCores ${version}${release.published_at ? `, released ${day(release.published_at)}` : ''} · `,
    el('a', { href: String(release.html_url || RELEASES).startsWith('https://github.com/') ? release.html_url : RELEASES, text: 'release notes' }),
  );
  for (const osName of ['mac', 'linux']) {
    const box = document.querySelector(`.files[data-os="${osName}"]`);
    box.replaceChildren(...files[osName]
      .sort((x, y) => Number(!!y.main) - Number(!!x.main))
      .map((f) => el('div', { class: f.main ? 'file main' : 'file' },
        el('div', { class: 'what' }, el('b', { text: f.what }), el('span', { text: `${f.detail} · ${f.name} · ${size(f.bytes)}` })),
        el('a', { class: f.main ? 'button primary' : 'button', href: f.url, text: 'Download' }))));
    const panel = $(`panel-${osName}`);
    const has = files[osName].length > 0;
    panel.querySelector('.released-help').hidden = !has;
    panel.querySelector('.when-released').hidden = !has;
  }
  $('verify').hidden = !sums;
}

function notYet() {
  $('release-line').textContent =
    'No release to download yet: the first one is on its way. Until then, build GimmeCores from source in a few commands.';
}

function unknown() {
  const line = $('release-line');
  line.textContent = '';
  line.append('Could not reach GitHub to look for the latest release. See ', el('a', { href: RELEASES, text: 'all releases' }), ', or build it from source:');
}

async function latest() {
  try {
    const r = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers: { Accept: 'application/vnd.github+json' },
      cache: 'no-cache',
    });
    if (r.status === 404) return notYet();
    if (!r.ok) return unknown();
    released(await r.json());
  } catch {
    unknown();
  }
}
latest();

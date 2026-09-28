/**
 * Encrypts content/deck.html into a self-contained index.html that asks for a
 * password and decrypts in the browser (PBKDF2-SHA256 -> AES-256-GCM).
 *
 * Referenced content/* media are encrypted separately (AES-256-GCM) into
 * media/<key-prefix>/<name>.enc. The prefix changes every build so a CDN that
 * cached an older .enc under Cache-Control: immutable cannot pair it with a
 * new HTML key. The media key is injected into the HTML *before* the HTML is
 * password-encrypted, so after unlock the deck decrypts every photo and video
 * immediately — without reading the password from sessionStorage (document.write
 * has already destroyed the gate).
 *
 *   node powerbee/build.mjs "<password>"
 *   PAGE_PASSWORD="<password>" node powerbee/build.mjs
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';

const ITERATIONS = 310000;

// Link previews need absolute URLs. Vercel serves this directory at /powerbee on
// the canonical host; override SITE_URL to check a preview deployment.
const SITE_URL = (process.env.SITE_URL ?? 'https://powerbee.tech/powerbee').replace(/\/$/, '');

// Preview metadata below carries the company name only — the hostname already
// reveals it. Never put figures, patents or technical claims there: previews are
// fetched by third-party servers and shown to anyone holding the link, password
// or not.

const password = process.argv[2] ?? process.env.PAGE_PASSWORD;
if (!password) {
  console.error('Password required:  node powerbee/build.mjs "<password>"');
  process.exit(1);
}

const looksLikeMedia = (buf) => {
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'PNG';
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'JPEG';
  if (buf.length >= 12 && buf.subarray(4, 8).toString() === 'ftyp') return 'MP4';
  return null;
};

const mediaDir = new URL('media/', import.meta.url);
await rm(mediaDir, { recursive: true, force: true });
await mkdir(mediaDir, { recursive: true });

let html = await readFile(new URL('content/deck.html', import.meta.url), 'utf8');
const mediaRef = /(src|poster)=["']content\/([^"'?]+)(?:\?[^"']*)?["']/g;
const mediaFiles = [...new Set([...html.matchAll(mediaRef)].map((match) => match[2]))];

const mediaKey = crypto.getRandomValues(new Uint8Array(32));
const mediaPrefix = Buffer.from(mediaKey).toString('hex').slice(0, 8);
const mediaCryptoKey = await crypto.subtle.importKey('raw', mediaKey, 'AES-GCM', false, ['encrypt']);
const outDir = new URL(`${mediaPrefix}/`, mediaDir);
await mkdir(outDir, { recursive: true });

for (const name of mediaFiles) {
  const plain = await readFile(new URL(`content/${name}`, import.meta.url));
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, mediaCryptoKey, plain));
  const packed = new Uint8Array(12 + cipher.byteLength);
  packed.set(fileIv, 0);
  packed.set(cipher, 12);
  const leak = looksLikeMedia(packed);
  if (leak) {
    console.error(`Refusing to write media/${mediaPrefix}/${name}.enc — output looks like ${leak}`);
    process.exit(1);
  }
  await writeFile(new URL(`${name}.enc`, outDir), packed);
}

html = html.replace(mediaRef, (_, attr, name) => {
  const url = `media/${mediaPrefix}/${name}.enc`;
  return attr === 'poster' ? `data-poster-enc="${url}"` : `data-enc="${url}"`;
});

const mediaKeyB64 = Buffer.from(mediaKey).toString('base64');
const loader = `<script>
(function () {
  var KEY = "${mediaKeyB64}";
  var bytes = function (b64) { return Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); }); };
  var keyP = crypto.subtle.importKey('raw', bytes(KEY), 'AES-GCM', false, ['decrypt']);
  var cache = Object.create(null);
  function mimeOf(name, buf) {
    if (/\\.mp4(\\.enc)?$/i.test(name)) return 'video/mp4';
    if (/\\.png(\\.enc)?$/i.test(name)) return 'image/png';
    if (/\\.jpe?g(\\.enc)?$/i.test(name)) return 'image/jpeg';
    if (buf[0] === 0x89) return 'image/png';
    if (buf[0] === 0xff) return 'image/jpeg';
    return 'application/octet-stream';
  }
  function resolve(rel) {
    var path = location.pathname;
    if (!/\\/$/.test(path)) {
      var last = path.split('/').pop();
      path = /\\.[a-z0-9]+$/i.test(last) ? path.replace(/[^/]+$/, '') : path + '/';
    }
    return path + rel;
  }
  function decrypt(url) {
    var abs = resolve(url);
    if (cache[abs]) return cache[abs];
    cache[abs] = (function attempt(n) {
      return fetch(abs).then(function (r) {
        if (!r.ok) throw new Error(String(r.status));
        return r.arrayBuffer();
      }).then(function (buf) {
        var u8 = new Uint8Array(buf);
        return keyP.then(function (key) {
          return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.subarray(0, 12) }, key, u8.subarray(12));
        });
      }).then(function (plain) {
        var u8 = new Uint8Array(plain);
        return URL.createObjectURL(new Blob([u8], { type: mimeOf(url, u8) }));
      }).catch(function () {
        if (n < 3) {
          return new Promise(function (ok) { setTimeout(ok, 350 * n); }).then(function () { return attempt(n + 1); });
        }
        delete cache[abs];
        throw new Error(url);
      });
    })(1);
    return cache[abs];
  }
  function attach(el, source, blob) {
    if (source.tagName === 'SOURCE') {
      source.src = blob;
      try { el.load(); } catch (e) {}
      if (el.hasAttribute('autoplay') && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        var play = el.play();
        if (play && play.catch) play.catch(function () {});
      }
    } else {
      el.src = blob;
    }
  }
  function fill(el) {
    if (el.dataset.mediaReady === '1') return;
    var poster = el.getAttribute('data-poster-enc');
    var source = el.tagName === 'VIDEO' ? el.querySelector('[data-enc]') : el;
    var enc = source && source.getAttribute('data-enc');
    if (poster) decrypt(poster).then(function (url) { el.poster = url; }).catch(function () {});
    if (!enc) return;
    decrypt(enc).then(function (url) {
      attach(el, source, url);
      el.dataset.mediaReady = '1';
      el.removeAttribute('data-media-error');
    }).catch(function () {
      el.setAttribute('data-media-error', '');
    });
  }
  document.querySelectorAll('video, img[data-enc]').forEach(fill);
})();
</script>`;

if (!html.includes('</body>')) {
  console.error('content/deck.html has no </body> — cannot inject the media loader.');
  process.exit(1);
}
html = html.replace('</body>', `${loader}\n</body>`);

const plaintext = new TextEncoder().encode(html);

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));

const baseKey = await crypto.subtle.importKey(
  'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt']
);
const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

const b64 = (buf) => Buffer.from(buf).toString('base64');

const shell = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>PowerBee &mdash; Investor Deck</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#000000">
<link rel="canonical" href="${SITE_URL}/">
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">

<meta name="description" content="PowerBee investor deck. Confidential — a password is required to view this presentation.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="PowerBee">
<meta property="og:title" content="PowerBee &mdash; Investor Deck">
<meta property="og:description" content="Confidential investor presentation. A password is required to view it.">
<meta property="og:url" content="${SITE_URL}/">
<meta property="og:image" content="${SITE_URL}/assets/og.png?v=2">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="PowerBee — Investor Deck. Confidential, password required.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="PowerBee &mdash; Investor Deck">
<meta name="twitter:description" content="Confidential investor presentation. A password is required to view it.">
<meta name="twitter:image" content="${SITE_URL}/assets/og.png?v=2">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }

:root {
  --black:   #000000;
  --slate:   #4C5A66;
  --white:   #F7FFFF;
  --white-2: #E6F5F5;
  --gray:    #AABBBD;
  --red:     #FF073A;
  --red-3:   #A60525;
  --line:      rgba(76, 90, 102, .38);
  --line-soft: rgba(76, 90, 102, .18);
}

:focus { outline: none; }
:focus-visible { outline: 2px solid var(--red); outline-offset: 3px; }

body {
  position: relative;
  min-height: 100vh;
  min-height: 100dvh;
  display: grid;
  place-items: center;
  padding: max(28px, env(safe-area-inset-top)) max(24px, env(safe-area-inset-right)) max(28px, env(safe-area-inset-bottom)) max(24px, env(safe-area-inset-left));
  background: var(--black);
  color: var(--white-2);
  font-family: 'Sora', -apple-system, BlinkMacSystemFont, sans-serif;
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(52% 42% at 92% -6%, rgba(255, 7, 58, .08), transparent 68%),
    radial-gradient(44% 38% at -4% 104%, rgba(166, 5, 37, .09), transparent 70%);
}

.corner {
  position: fixed;
  width: 18px;
  height: 18px;
  border-style: solid;
  border-color: var(--red);
  z-index: 4;
  pointer-events: none;
}
.corner.tl { top: max(22px, env(safe-area-inset-top)); left: max(22px, env(safe-area-inset-left)); border-width: 2px 0 0 2px; }
.corner.br { bottom: max(22px, env(safe-area-inset-bottom)); right: max(22px, env(safe-area-inset-right)); border-width: 0 2px 2px 0; }

.gate {
  position: relative;
  z-index: 2;
  width: 100%;
  max-width: 420px;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  transition: opacity .55s cubic-bezier(.22, .7, .2, 1), transform .55s cubic-bezier(.22, .7, .2, 1);
}

.mark {
  width: 72px;
  height: 36px;
  margin-bottom: 28px;
}
.mark circle {
  fill: none;
  stroke-width: 3.2;
  transform-origin: center;
}
body.is-busy .mark { animation: mark-turn 1.8s linear infinite; }
@keyframes mark-turn { to { transform: rotate(360deg); } }

.eyebrow {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  font-size: .58rem;
  font-weight: 600;
  letter-spacing: .3em;
  text-transform: uppercase;
  color: var(--slate);
  margin-bottom: 16px;
}
.eyebrow::before {
  content: "";
  width: 0; height: 0;
  border-left: 5px solid var(--red);
  border-top: 4px solid transparent;
  border-bottom: 4px solid transparent;
}

.word {
  font-size: clamp(1.7rem, 1.3rem + 1.6vw, 2.15rem);
  font-weight: 400;
  letter-spacing: .22em;
  text-transform: uppercase;
  color: var(--white);
  line-height: 1;
}
.word span { color: var(--red); }

.tag {
  margin: 14px 0 0;
  font-size: .72rem;
  font-weight: 300;
  letter-spacing: .08em;
  color: rgba(246, 248, 250, .62);
}

h1 {
  margin-top: 28px;
  font-size: .68rem;
  font-weight: 400;
  letter-spacing: .28em;
  text-transform: uppercase;
  color: var(--slate);
}

.hint {
  margin-top: 12px;
  max-width: 36ch;
  font-size: .84rem;
  font-weight: 300;
  line-height: 1.7;
  color: var(--gray);
}

form {
  width: 100%;
  margin-top: 32px;
  display: grid;
  gap: 12px;
}

input {
  width: 100%;
  min-height: 48px;
  font: inherit;
  font-size: .92rem;
  letter-spacing: .12em;
  color: var(--white);
  text-align: center;
  background: transparent;
  border: 0;
  border-bottom: 1px solid var(--line);
  padding: 14px 8px 12px;
  transition: border-color .16s;
}

input::placeholder { color: var(--slate); letter-spacing: .22em; text-transform: uppercase; font-size: .68rem; }

input:focus { border-bottom-color: var(--red); }

button {
  min-height: 48px;
  font: inherit;
  font-size: .68rem;
  font-weight: 600;
  letter-spacing: .28em;
  text-transform: uppercase;
  color: var(--white);
  background: transparent;
  border: 1px solid var(--red);
  padding: 13px 16px;
  cursor: pointer;
  transition: background .16s, color .16s;
}

button:hover { background: var(--red); }
button:disabled { opacity: .45; cursor: default; }

.msg {
  min-height: 1.3em;
  font-size: .66rem;
  font-weight: 600;
  letter-spacing: .16em;
  text-transform: uppercase;
  color: var(--red);
}

.msg[data-busy] { color: var(--slate); }

footer {
  position: fixed;
  left: 0;
  right: 0;
  bottom: max(22px, env(safe-area-inset-bottom));
  z-index: 3;
  font-size: .58rem;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--slate);
  text-align: center;
  pointer-events: none;
}

.veil {
  position: fixed;
  inset: 0;
  z-index: 30;
  pointer-events: none;
  display: grid;
  place-items: center;
}
.veil .rings {
  position: relative;
  width: 80px;
  height: 40px;
  transform: scale(0);
}
.veil i {
  position: absolute;
  top: 6px;
  left: 14px;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 2.4px solid #F7FFFF;
  background: transparent;
}
.veil i + i {
  left: 38px;
  border-color: var(--red);
}

body.is-opening .gate,
body.is-opening footer,
body.is-opening .corner { opacity: 0; transform: translate3d(0, -10px, 0); }
body.is-opening .veil .rings {
  animation: open-rings .92s cubic-bezier(.22, .68, .2, 1) forwards;
}
body.is-opening .veil i {
  animation: open-fill .92s cubic-bezier(.22, .68, .2, 1) forwards;
}

@keyframes open-rings {
  0%   { transform: rotate(0deg) scale(1); }
  32%  { transform: rotate(130deg) scale(4.6); }
  100% { transform: rotate(390deg) scale(86); }
}
@keyframes open-fill {
  0%, 36% { background: transparent; }
  100% { background: #000; }
}

@media (prefers-reduced-motion: reduce) {
  body.is-busy .mark,
  body.is-opening .veil .rings,
  body.is-opening .veil i { animation: none; }
  .gate, footer, .corner { transition: none; }
}
</style>
</head>
<body>

<span class="corner tl"></span>
<span class="corner br"></span>

<div class="gate">
  <svg class="mark" viewBox="0 0 80 40" aria-hidden="true">
    <circle cx="28" cy="20" r="13.5" stroke="#F7FFFF"/>
    <circle cx="52" cy="20" r="13.5" stroke="#FF073A"/>
  </svg>

  <div class="eyebrow">Confidential</div>
  <p class="word">Power<span>Bee</span></p>
  <p class="tag">Ultra efficient energy generation</p>
  <h1>Investor deck</h1>
  <p class="hint">Shared by invitation only. Enter the password to continue.</p>

  <form id="f">
    <input id="p" type="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <button id="b" type="submit">Enter</button>
    <p class="msg" id="m" role="status" aria-live="polite"></p>
  </form>
</div>

<footer>PowerBee P.S.A. &middot; Do not forward</footer>
<div class="veil" aria-hidden="true"><span class="rings"><i></i><i></i></span></div>

<script>
const PAYLOAD = {
  salt: "${b64(salt)}",
  iv: "${b64(iv)}",
  data: "${b64(ciphertext)}",
  iterations: ${ITERATIONS}
};

const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const form = document.getElementById('f');
const input = document.getElementById('p');
const button = document.getElementById('b');
const msg = document.getElementById('m');

async function unlock(password) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytes(PAYLOAD.salt), iterations: PAYLOAD.iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes(PAYLOAD.iv) }, key, bytes(PAYLOAD.data)
  );
  return new TextDecoder().decode(plain);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  document.body.classList.add('is-busy');
  msg.dataset.busy = '';
  msg.textContent = 'Opening\\u2026';

  try {
    const html = await unlock(input.value);
    sessionStorage.setItem('unlocked', input.value);
    await render(html);
  } catch {
    document.body.classList.remove('is-busy');
    delete msg.dataset.busy;
    msg.textContent = 'Wrong password.';
    button.disabled = false;
    input.select();
  }
});

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function render(html, instant) {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!instant && !reduce) {
    document.body.classList.remove('is-busy');
    document.body.classList.add('is-opening');
    await wait(920);
  }
  document.open();
  document.write(html);
  document.close();
  fitToScreen();
  window.addEventListener('load', containWideTables);
}

// document.write() replaces this page with the decrypted one, head and all, so
// nothing the gate declared reaches the document the reader actually ends up
// on. Restate the mobile metrics there: a viewport for the phone to lay the
// document out against, no text inflation on top of it, and nothing wide enough
// to push the layout past the screen. Any of the three opens the document
// zoomed in, with the full width a pinch away.
function fitToScreen() {
  const head = document.head || document.documentElement;

  // A viewport that was parsed out of the written markup is inert — only
  // inserting the element now makes the browser act on it.
  for (const stale of document.querySelectorAll('meta[name="viewport"]')) stale.remove();

  const viewport = document.createElement('meta');
  viewport.name = 'viewport';
  viewport.content = 'width=device-width, initial-scale=1, viewport-fit=cover';
  head.appendChild(viewport);

  const style = document.createElement('style');
  style.textContent = [
    'html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }',
    'body { overflow-wrap: break-word; }',
    'img, video, canvas, iframe { max-width: 100%; height: auto; }',
    '.duo-still, .inn-stage video, .inn-stage svg, .evo-art img, .tl-photo img, .team-photo img, .cmp-ico img, .pat-sheet img { height: unset; }',
    'pre { overflow-x: auto; }',
    '[data-fit-scroll] { max-width: 100%; overflow-x: auto; }'
  ].join(' ');
  head.appendChild(style);

  containWideTables();
}

// A table too wide for the screen widens the whole layout with it, so give it
// its own scroll box — but only once it really does not fit, so that nothing
// moves on a screen with room for it.
function containWideTables() {
  for (const table of document.querySelectorAll('table')) {
    const parent = table.parentElement;
    if (!parent || parent.hasAttribute('data-fit-scroll')) continue;
    if (table.getBoundingClientRect().width <= parent.clientWidth + 1) continue;

    const box = document.createElement('div');
    box.setAttribute('data-fit-scroll', '');
    parent.insertBefore(box, table);
    box.appendChild(table);
  }
}

// Stay unlocked while the tab is open.
const remembered = sessionStorage.getItem('unlocked');
if (remembered) {
  unlock(remembered).then((html) => render(html, true)).catch(() => sessionStorage.removeItem('unlocked'));
}
</script>

</body>
</html>
`;

await writeFile(new URL('index.html', import.meta.url), shell);

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`powerbee/index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);
console.log(`powerbee/media/ written — ${mediaFiles.length} encrypted file${mediaFiles.length === 1 ? '' : 's'}`);

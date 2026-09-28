/**
 * Encrypts content/deck.html into a self-contained index.html that asks for a
 * password and decrypts in the browser (PBKDF2-SHA256 -> AES-256-GCM).
 *
 * Referenced content/* media are encrypted separately (AES-256-GCM) into
 * media/<name>.enc. A random media key is injected into the HTML *before* the
 * HTML is password-encrypted, so after unlock the deck can lazy-decrypt blobs
 * without reading the password from sessionStorage (document.write has already
 * destroyed the gate).
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
const mediaCryptoKey = await crypto.subtle.importKey('raw', mediaKey, 'AES-GCM', false, ['encrypt']);

for (const name of mediaFiles) {
  const plain = await readFile(new URL(`content/${name}`, import.meta.url));
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, mediaCryptoKey, plain));
  const packed = new Uint8Array(12 + cipher.byteLength);
  packed.set(fileIv, 0);
  packed.set(cipher, 12);
  const leak = looksLikeMedia(packed);
  if (leak) {
    console.error(`Refusing to write media/${name}.enc — output looks like ${leak}`);
    process.exit(1);
  }
  await writeFile(new URL(`${name}.enc`, mediaDir), packed);
}

html = html.replace(mediaRef, (_, attr, name) => {
  const url = `media/${name}.enc`;
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
  function decrypt(url) {
    if (cache[url]) return cache[url];
    cache[url] = fetch(url).then(function (r) {
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
    });
    return cache[url];
  }
  function fill(el) {
    if (el.dataset.mediaReady) return;
    el.dataset.mediaReady = '1';
    var poster = el.getAttribute('data-poster-enc');
    var source = el.tagName === 'VIDEO' ? el.querySelector('[data-enc]') : el;
    var enc = source && source.getAttribute('data-enc');
    var jobs = [];
    if (poster) jobs.push(decrypt(poster).then(function (url) { el.poster = url; }));
    if (enc) {
      jobs.push(decrypt(enc).then(function (url) {
        if (source.tagName === 'SOURCE') {
          source.src = url;
          el.load();
          if (el.hasAttribute('autoplay') && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            var play = el.play();
            if (play && play.catch) play.catch(function () {});
          }
        } else {
          el.src = url;
        }
      }));
    }
    Promise.all(jobs).catch(function () {
      delete el.dataset.mediaReady;
      el.setAttribute('data-media-error', '');
    });
  }
  function watch(el) {
    if (!('IntersectionObserver' in window)) { fill(el); return; }
    var slide = el.closest('.slide') || el;
    var seen = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) fill(el);
      });
    }, { rootMargin: '80% 0px', threshold: 0.01 });
    seen.observe(slide);
  }
  document.querySelectorAll('img[data-enc], video').forEach(watch);
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PowerBee &mdash; Investor Deck</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0B0D0F">
<link rel="canonical" href="${SITE_URL}/">
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">

<meta name="description" content="PowerBee investor deck. Confidential — a password is required to view this presentation.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="PowerBee">
<meta property="og:title" content="PowerBee &mdash; Investor Deck">
<meta property="og:description" content="Confidential investor presentation. A password is required to view it.">
<meta property="og:url" content="${SITE_URL}/">
<meta property="og:image" content="${SITE_URL}/assets/og.png">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="PowerBee — Investor Deck. Confidential, password required.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="PowerBee &mdash; Investor Deck">
<meta name="twitter:description" content="Confidential investor presentation. A password is required to view it.">
<meta name="twitter:image" content="${SITE_URL}/assets/og.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }

:root {
  --black:   #0B0D0F;
  --black-2: #131619;
  --slate:   #4C5A66;
  --white:   #F7FFFF;
  --white-2: #E6F5F5;
  --gray:    #AABBBD;
  --red:     #FF073A;
  --red-3:   #A60525;
  --line:      rgba(76, 90, 102, .38);
  --line-soft: rgba(76, 90, 102, .18);
}

body {
  position: relative;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  background: var(--black);
  color: var(--white-2);
  font-family: 'Sora', -apple-system, BlinkMacSystemFont, sans-serif;
  -webkit-font-smoothing: antialiased;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(55% 40% at 85% -5%, rgba(255, 7, 58, .12), transparent 70%),
    radial-gradient(45% 35% at -5% 100%, rgba(166, 5, 37, .14), transparent 70%);
}

.gate {
  position: relative;
  width: 100%;
  max-width: 410px;
  background: linear-gradient(180deg, var(--black-2), rgba(19, 22, 25, .5));
  border: 1px solid var(--line-soft);
  padding: 38px 36px;
}

.gate::before,
.gate::after {
  content: "";
  position: absolute;
  width: 16px; height: 16px;
  border-style: solid;
  border-color: var(--red);
}

.gate::before { top: -1px;    left: -1px;  border-width: 1px 0 0 1px; }
.gate::after  { bottom: -1px; right: -1px; border-width: 0 1px 1px 0; }

.eyebrow {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: .6rem;
  font-weight: 600;
  letter-spacing: .3em;
  text-transform: uppercase;
  color: var(--slate);
  margin-bottom: 22px;
}

.eyebrow::before {
  content: "";
  width: 0; height: 0;
  border-left: 5px solid var(--red);
  border-top: 4px solid transparent;
  border-bottom: 4px solid transparent;
  flex: none;
}

h1 {
  font-size: 1.16rem;
  font-weight: 400;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--white);
}

.hint {
  margin-top: 14px;
  font-size: .83rem;
  line-height: 1.75;
  color: var(--gray);
}

form { margin-top: 26px; display: grid; gap: 12px; }

input {
  width: 100%;
  font: inherit;
  font-size: .9rem;
  letter-spacing: .1em;
  color: var(--white);
  background: rgba(11, 13, 15, .7);
  border: 1px solid var(--line);
  padding: 13px 15px;
  transition: border-color .16s, box-shadow .16s;
}

input::placeholder { color: var(--slate); letter-spacing: .18em; text-transform: uppercase; font-size: .74rem; }

input:focus {
  outline: none;
  border-color: var(--red);
  box-shadow: 0 0 0 2px rgba(255, 7, 58, .16);
}

button {
  font: inherit;
  font-size: .72rem;
  font-weight: 600;
  letter-spacing: .24em;
  text-transform: uppercase;
  color: var(--white);
  background: var(--red-3);
  border: 1px solid var(--red);
  padding: 13px 16px;
  cursor: pointer;
  transition: background .16s;
}

button:hover { background: var(--red); }
button:disabled { opacity: .5; cursor: default; }

.msg {
  min-height: 1.3em;
  font-size: .72rem;
  font-weight: 600;
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--red);
}

.msg[data-busy] { color: var(--slate); }

footer {
  margin-top: 26px;
  padding-top: 20px;
  border-top: 1px solid var(--line-soft);
  font-size: .68rem;
  line-height: 1.8;
  letter-spacing: .02em;
  color: var(--slate);
}
</style>
</head>
<body>

<div class="gate">
  <div class="eyebrow">Confidential</div>

  <h1>Investor deck</h1>
  <p class="hint">This presentation is confidential and shared by invitation only. Enter the password to continue.</p>

  <form id="f">
    <input id="p" type="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <button id="b" type="submit">Unlock</button>
    <p class="msg" id="m" role="status" aria-live="polite"></p>
  </form>

  <footer>PowerBee P.S.A. &middot; All rights reserved. Do not forward or duplicate without consent.</footer>
</div>

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
  msg.dataset.busy = '';
  msg.textContent = 'Decrypting\\u2026';

  try {
    const html = await unlock(input.value);
    sessionStorage.setItem('unlocked', input.value);
    render(html);
  } catch {
    delete msg.dataset.busy;
    msg.textContent = 'Wrong password.';
    button.disabled = false;
    input.select();
  }
});

function render(html) {
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
    '.duo-still, .inn-stage video { height: unset; }',
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
  unlock(remembered).then(render).catch(() => sessionStorage.removeItem('unlocked'));
}
</script>

</body>
</html>
`;

await writeFile(new URL('index.html', import.meta.url), shell);

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`powerbee/index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);
console.log(`powerbee/media/ written — ${mediaFiles.length} encrypted file${mediaFiles.length === 1 ? '' : 's'}`);

/**
 * Encrypts content/deck.html into a self-contained index.html that asks for a
 * password and decrypts in the browser (PBKDF2-SHA256 -> AES-256-GCM).
 *
 * The published index.html contains only ciphertext, so it is safe in a public
 * repository. content/deck.html must stay out of git.
 *
 *   node polishengine/build.mjs "<password>"
 *   PAGE_PASSWORD="<password>" node polishengine/build.mjs
 *   node polishengine/build.mjs -           # read the password from stdin
 *   node polishengine/build.mjs - --rotate  # and change the password
 *
 * A rebuild keeps the deck's password: the build refuses to run unless the
 * password opens the page it is about to replace, so a mistyped or mangled one
 * cannot lock readers out. Changing it has to be asked for with --rotate.
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

import { confirmWritten, keepPassword, readPassword } from '../lib/password.mjs';

const ITERATIONS = 310000;

// Link previews need absolute URLs. Vercel serves this directory at
// /polishengine on the canonical host; override SITE_URL to check a
// preview deployment.
const SITE_URL = (process.env.SITE_URL ?? 'https://powerbee.tech/polishengine').replace(/\/$/, '');

// Preview metadata below carries the project name only — the hostname already
// reveals it. Never put figures, patents or technical claims there: previews are
// fetched by third-party servers and shown to anyone holding the link, password
// or not.

const target = new URL('index.html', import.meta.url);
const argv = process.argv.slice(2);

const password = await readPassword({
  args: argv.filter((arg) => !arg.startsWith('--')),
  usage: 'node polishengine/build.mjs "<password>"',
});

await keepPassword({
  published: await readFile(target, 'utf8').catch(() => null),
  password,
  rotate: argv.includes('--rotate'),
  source: 'polishengine/index.html',
});

const plaintext = await readFile(new URL('content/deck.html', import.meta.url));

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
<title>Polish Engine &mdash; Project Deck</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0B0D0F">
<link rel="canonical" href="${SITE_URL}/">
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">

<meta name="description" content="Polish Engine project deck. Confidential — a password is required to view this presentation.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Polish Engine">
<meta property="og:title" content="Polish Engine &mdash; Project Deck">
<meta property="og:description" content="Confidential project presentation. A password is required to view it.">
<meta property="og:url" content="${SITE_URL}/">
<meta property="og:image" content="${SITE_URL}/assets/og.png">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Polish Engine — Project Deck. Confidential, password required.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Polish Engine &mdash; Project Deck">
<meta name="twitter:description" content="Confidential project presentation. A password is required to view it.">
<meta name="twitter:image" content="${SITE_URL}/assets/og.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

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

  <h1>Polish Engine &mdash; project deck</h1>
  <p class="hint">This presentation is confidential and shared by invitation only. Enter the password to continue.</p>

  <form id="f">
    <input id="p" type="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <button id="b" type="submit">Unlock</button>
    <p class="msg" id="m" role="status" aria-live="polite"></p>
  </form>

  <footer>Ingenieurb&uuml;ro Sadlak (IBS) &middot; All rights reserved. Do not forward or duplicate without consent.</footer>
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
    sessionStorage.setItem('unlocked-pe', input.value);
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
  if (location.hash) {
    const target = document.querySelector(location.hash);
    if (target) target.scrollIntoView();
  }
}

// Stay unlocked while the tab is open.
const remembered = sessionStorage.getItem('unlocked-pe');
if (remembered) {
  unlock(remembered).then(render).catch(() => sessionStorage.removeItem('unlocked-pe'));
}
</script>

</body>
</html>
`;

await writeFile(target, shell);
await confirmWritten({ page: shell, password, source: 'polishengine/index.html' });

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`polishengine/index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);

/**
 * Encrypts content/page.html into a self-contained index.html that asks for a
 * password and decrypts in the browser (PBKDF2-SHA256 -> AES-256-GCM).
 *
 * The published index.html contains only ciphertext, so it is safe in a public
 * repository. content/page.html must stay out of git.
 *
 *   node build.mjs "<password>"
 *   PAGE_PASSWORD="<password>" node build.mjs
 *   node build.mjs -           # read the password from stdin
 *   node build.mjs - --rotate  # and change the password
 *
 * A rebuild keeps the document's password: the build refuses to run unless the
 * password opens the page it is about to replace, so a mistyped or mangled one
 * cannot lock readers out. Changing it has to be asked for with --rotate.
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

import { confirmWritten, keepPassword, readPassword } from './lib/password.mjs';

const ITERATIONS = 310000;

// Link previews need absolute URLs. Point this at whichever host is canonical.
const SITE_URL = (process.env.SITE_URL ?? 'https://powerbee.tech').replace(/\/$/, '');

// Everything outside the encrypted payload is public: the gate markup, the
// metadata below and the link preview. It is deliberately limited to the project
// name, the one-line description and the country, so that the page can be
// indexed and found under "Polish Engine" without disclosing anything else.
// Never put figures, patents, acronyms or technical claims there.

const target = new URL('index.html', import.meta.url);
const argv = process.argv.slice(2);

const password = await readPassword({
  args: argv.filter((arg) => !arg.startsWith('--')),
  usage: 'node build.mjs "<password>"',
});

await keepPassword({
  published: await readFile(target, 'utf8').catch(() => null),
  password,
  rotate: argv.includes('--rotate'),
  source: 'index.html',
});

const plaintext = await readFile(new URL('content/page.html', import.meta.url));

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
<title>Polish Engine | Polish R&amp;D Project</title>
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<meta name="theme-color" content="#0B0D0F">
<link rel="canonical" href="${SITE_URL}/">
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">

<meta name="description" content="Polish Engine is a Polish research and development project focused on innovative engine technology.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Polish Engine">
<meta property="og:locale" content="en_US">
<meta property="og:title" content="Polish Engine | Polish R&amp;D Project">
<meta property="og:description" content="Polish Engine is a Polish research and development project focused on innovative engine technology.">
<meta property="og:url" content="${SITE_URL}/">
<meta property="og:image" content="${SITE_URL}/assets/og.png">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Polish Engine — Polski Silnik. A Polish research and development project.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Polish Engine | Polish R&amp;D Project">
<meta name="twitter:description" content="Polish Engine is a Polish research and development project focused on innovative engine technology.">
<meta name="twitter:image" content="${SITE_URL}/assets/og.png">
<meta name="twitter:image:alt" content="Polish Engine — Polski Silnik. A Polish research and development project.">
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "ResearchProject",
      "@id": "${SITE_URL}/#project",
      "name": "Polish Engine",
      "alternateName": "Polski Silnik",
      "description": "Polish research and development project focused on innovative engine technology.",
      "url": "${SITE_URL}/",
      "location": { "@type": "Country", "name": "Poland" }
    },
    {
      "@type": "WebSite",
      "@id": "${SITE_URL}/#website",
      "name": "Polish Engine",
      "alternateName": "Polski Silnik",
      "url": "${SITE_URL}/",
      "inLanguage": "en",
      "about": { "@id": "${SITE_URL}/#project" }
    }
  ]
}
</script>
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
  max-width: 440px;
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
  font-size: 1.62rem;
  font-weight: 400;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--white);
}

.lede {
  margin-top: 16px;
  font-size: .88rem;
  line-height: 1.75;
  color: var(--white-2);
}

.origin {
  margin-top: 12px;
  font-size: .68rem;
  font-weight: 600;
  letter-spacing: .22em;
  text-transform: uppercase;
  color: var(--slate);
}

.protected {
  margin-top: 30px;
  padding-top: 24px;
  border-top: 1px solid var(--line-soft);
}

h2 {
  font-size: .72rem;
  font-weight: 600;
  letter-spacing: .24em;
  text-transform: uppercase;
  color: var(--gray);
}

.hint {
  margin-top: 12px;
  font-size: .83rem;
  line-height: 1.75;
  color: var(--gray);
}

form { margin-top: 22px; display: grid; gap: 12px; }

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

<main class="gate">
  <div class="eyebrow">Polish R&amp;D Project</div>

  <h1>Polish Engine</h1>
  <p class="lede">Polish research and development project focused on innovative engine technology.</p>
  <p class="origin"><span lang="pl">Polski Silnik</span> &mdash; Poland</p>

  <section class="protected" aria-labelledby="protected-title">
    <h2 id="protected-title">Protected project area</h2>
    <p class="hint">Enter the password to continue.</p>

    <form id="f">
      <input id="p" type="password" placeholder="Password" autocomplete="current-password" required>
      <button id="b" type="submit">Unlock</button>
      <p class="msg" id="m" role="status" aria-live="polite"></p>
    </form>
  </section>

  <footer>Exclusive intangible and intellectual property of IBS. All rights reserved.</footer>
</main>

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
  if (location.hash) {
    const target = document.querySelector(location.hash);
    if (target) target.scrollIntoView();
  }
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

await writeFile(target, shell);
await confirmWritten({ page: shell, password, source: 'index.html' });

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);

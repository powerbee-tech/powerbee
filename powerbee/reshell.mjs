/**
 * Re-renders the published index.html from shell.html around the ciphertext it
 * already carries.
 *
 *   node powerbee/reshell.mjs
 *
 * The gate is the page's skin; the deck is the payload underneath. Fixing the
 * skin should not require the password, a copy of the plaintext, or a fresh
 * encryption of a deck that has not changed — so this lifts the payload out of
 * the built page, puts the current shell around it, and writes it back. The
 * salt, IV, ciphertext and iteration count come through byte for byte, which
 * the script checks before it saves anything: the same password opens the
 * result, and media/ is left alone because its key lives in the payload.
 *
 * Use build.mjs instead whenever the deck itself has changed.
 */

import { readFile, writeFile } from 'node:fs/promises';

import { readPayload, renderShell } from './shell.mjs';

const target = new URL('index.html', import.meta.url);
const published = await readFile(target, 'utf8');

const payload = readPayload(published, 'powerbee/index.html');
const page = await renderShell(payload);

const rebuilt = readPayload(page, 'the rebuilt page');
for (const field of ['salt', 'iv', 'data', 'iterations']) {
  if (rebuilt[field] !== payload[field]) {
    console.error(`The ${field} did not survive the rewrite. Nothing written.`);
    process.exit(1);
  }
}

if (page === published) {
  console.log('powerbee/index.html is already the current shell — nothing to do.');
  process.exit(0);
}

await writeFile(target, page);

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(
  `powerbee/index.html re-shelled — ${size(page.length)} ` +
  `(payload unchanged, ${payload.iterations} PBKDF2 iterations)`
);

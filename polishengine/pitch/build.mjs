/**
 * Encrypts content/pitch.html into a self-contained index.html that asks for a
 * password and decrypts in the browser (PBKDF2-SHA256 -> AES-256-GCM).
 *
 * The published index.html contains only ciphertext, so it is safe in a public
 * repository. content/pitch.html must stay out of git.
 *
 *   node polishengine/pitch/build.mjs "<password>"
 *   PAGE_PASSWORD="<password>" node polishengine/pitch/build.mjs
 *   node polishengine/pitch/build.mjs -           # read the password from stdin
 *   node polishengine/pitch/build.mjs - --rotate  # and change the password
 *
 * A rebuild keeps the book's password: the build refuses to run unless the
 * password opens the page it is about to replace, so a mistyped or mangled one
 * cannot lock readers out. Changing it has to be asked for with --rotate.
 *
 * The page around the ciphertext — the gate and the slide viewer — is
 * shell.html. Changing it needs no password: see reshell.mjs.
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

import { confirmWritten, keepPassword, readPassword } from '../../lib/password.mjs';
import { renderShell } from './shell.mjs';

const ITERATIONS = 310000;

const target = new URL('index.html', import.meta.url);
const argv = process.argv.slice(2);

const password = await readPassword({
  args: argv.filter((arg) => !arg.startsWith('--')),
  usage: 'node polishengine/pitch/build.mjs "<password>"',
});

await keepPassword({
  published: await readFile(target, 'utf8').catch(() => null),
  password,
  rotate: argv.includes('--rotate'),
  source: 'polishengine/pitch/index.html',
});

const plaintext = await readFile(new URL('content/pitch.html', import.meta.url));

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

const shell = await renderShell({
  salt: b64(salt),
  iv: b64(iv),
  data: b64(ciphertext),
  iterations: ITERATIONS,
});

await writeFile(target, shell);
await confirmWritten({ page: shell, password, source: 'polishengine/pitch/index.html' });

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`polishengine/pitch/index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);

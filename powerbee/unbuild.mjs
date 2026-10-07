/**
 * Recovers content/deck.html from the published index.html — the inverse of
 * build.mjs. The ciphertext in the repository is the only copy of the deck, so
 * this is how you get an editable source on a machine that has never held it
 * (a fresh clone, a cloud agent, a phone).
 *
 *   node powerbee/unbuild.mjs "<password>"
 *   PAGE_PASSWORD="<password>" node powerbee/unbuild.mjs
 *   node powerbee/unbuild.mjs -          # read the password from stdin
 *
 * Refuses to overwrite an existing content/deck.html unless --force is passed.
 *
 *   --check     say whether the password opens the page; write nothing
 *   --history   say which past builds of the page the password opens
 *
 * --history answers the question a locked-out reader cannot: whether the
 * password stopped matching, and if so which build stopped accepting it. The
 * ciphertext of every build is still in git, so the newest one the password
 * opens is the one to recover the deck from — and the commits after it say in
 * their subjects what to re-apply.
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

import { readPassword } from './password.mjs';

const flags = new Set(process.argv.slice(2).filter((arg) => arg.startsWith('--')));
const args = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));

const force = flags.has('--force');
const check = flags.has('--check');
const history = flags.has('--history');

const password = await readPassword({
  args,
  usage: 'node powerbee/unbuild.mjs "<password>"',
});

const target = new URL('content/deck.html', import.meta.url);
const writing = !check && !history;

if (writing && !force) {
  const exists = await access(target).then(() => true, () => false);
  if (exists) {
    console.error('content/deck.html already exists. Pass --force to overwrite it.');
    process.exit(1);
  }
}

/** Pulls the payload out of a built page. Returns null if it is not one. */
function payloadOf(page) {
  const field = (name) => {
    const match = page.match(new RegExp(name + ':\\s*"([A-Za-z0-9+/=]+)"'));
    return match ? Uint8Array.from(Buffer.from(match[1], 'base64')) : null;
  };

  const salt = field('salt');
  const iv = field('iv');
  const data = field('data');
  const iterations = Number(page.match(/iterations:\s*(\d+)/)?.[1]);

  return salt && iv && data && iterations ? { salt, iv, data, iterations } : null;
}

/** Decrypts a payload, or returns null when the password does not open it. */
async function decrypt({ salt, iv, data, iterations }) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  try {
    return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  } catch {
    return null;
  }
}

const size = (n) => `${(n / 1024).toFixed(1)} kB`;

if (history) {
  // Paths are resolved against this directory, so index.html and ./index.html
  // mean the published page wherever the repository is checked out.
  const git = (...argv) => execFileSync('git', argv, { cwd: new URL('.', import.meta.url), maxBuffer: 1e9 });
  const log = git('log', '--format=%h%x09%s', '--', 'index.html').toString().trim();
  if (!log) {
    console.error('git knows no history for powerbee/index.html.');
    process.exit(1);
  }

  let newestOpened = null;
  let newest = null;
  let refused = 0;

  for (const line of log.split('\n')) {
    const [sha, subject] = line.split('\t');
    const payload = payloadOf(git('show', `${sha}:./index.html`).toString());
    const plaintext = payload && await decrypt(payload);

    newest ??= { sha, subject };
    if (plaintext) newestOpened ??= { sha, subject };
    else if (payload) refused += 1;

    console.log(`${sha}  ${(plaintext ? 'opens' : payload ? 'refused' : 'not a built page').padEnd(15)}  ${subject}`);
  }

  const builds = (n) => `${n} build${n === 1 ? '' : 's'}`;

  console.log();
  if (!newestOpened) {
    console.log('This password opens no build of the page. It is not the deck password.');
  } else if (newestOpened.sha === newest.sha) {
    console.log('This password opens the published page.');
    if (refused) console.log(`${builds(refused)} in between refuse it, so the deck was at some point rebuilt with another password.`);
  } else {
    console.log('This password does not open the published page.');
    console.log(`The newest build it opens is ${newestOpened.sha} — "${newestOpened.subject}".`);
    console.log('Recover the deck from there and re-apply the commits after it; their subjects say what each one changed.');
  }
  process.exit(0);
}

const published = await readFile(new URL('index.html', import.meta.url), 'utf8');
const payload = payloadOf(published);
if (!payload) {
  console.error('Could not find a payload in powerbee/index.html — is it a built page?');
  process.exit(1);
}

const plaintext = await decrypt(payload);
if (!plaintext) {
  console.error('Wrong password — could not decrypt powerbee/index.html.');
  console.error('Run with --history to see whether it opens an earlier build, and which one stopped accepting it.');
  process.exit(1);
}

if (check) {
  console.log(`This password opens powerbee/index.html — ${size(plaintext.byteLength)} of deck behind it.`);
  process.exit(0);
}

await writeFile(target, Buffer.from(plaintext));

console.log(`powerbee/content/deck.html restored — ${size(plaintext.byteLength)}. It is gitignored; keep it that way.`);

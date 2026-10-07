/**
 * How the build scripts take a password, and the two rules that keep a rebuild
 * from quietly locking everyone out.
 *
 * Each encrypted page has its own password and none of them is stored anywhere:
 * the ciphertext is the only copy of the document, so the string a build
 * received is the only thing that will ever open what it published. A build
 * that encrypted a mistyped or shell-mangled password therefore looks exactly
 * like a deliberate rotation, and nothing notices until a reader is locked out.
 * /powerbee lost its password that way once already.
 *
 * So:
 *
 * 1. A password that the gate would normalise away is refused outright, because
 *    nobody could type it back (see reject below).
 * 2. A rebuild must open the page it is replacing. Changing a password has to
 *    be asked for with --rotate.
 */

import { webcrypto as crypto } from 'node:crypto';

// Zero-width characters the gate drops outright.
const REMOVED = /[\u200B-\u200D\u2060\uFEFF]/;

// Spaces the gate turns into an ordinary space, which trimming then removes at
// either end.
const FLATTENED = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/;

async function fromStdin() {
  let text = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) text += chunk;
  return text.replace(/\r?\n$/, '');
}

/**
 * A password shared over chat, mail or a PDF picks up characters nobody typed:
 * a newline from the copy, a non-breaking space from formatted text, a
 * zero-width character from a link preview. Every gate removes those from what
 * the reader enters so that a pasted password still works, which means a build
 * must never encrypt a password carrying them — the gate would strip them off
 * every attempt and the page could not be opened with the password it was built
 * with.
 */
function reject(password) {
  if (password !== password.trim()) {
    return 'The password starts or ends with whitespace. The gate trims what the reader types, so this one could never be entered back.';
  }
  if (REMOVED.test(password)) {
    return 'The password contains a zero-width character, most likely picked up from a formatted message. The gate strips those from what the reader types, so this one could never be entered back.';
  }
  if (FLATTENED.test(password)) {
    return 'The password contains a non-breaking or typographic space, most likely picked up from a formatted message. The gate turns those into ordinary spaces, so this one could never be entered back.';
  }
  return null;
}

/**
 * Reads the password from the first argument, from PAGE_PASSWORD, or — when the
 * argument is `-` — from stdin.
 *
 * Prefer `-`. An argv literal has already been through the shell, which expands
 * `$`, a backtick and a backslash inside double quotes, and the build cannot
 * tell the mangled result from the password you meant.
 */
export async function readPassword({ args, usage }) {
  let password = args[0] ?? process.env.PAGE_PASSWORD;
  if (password === '-') password = await fromStdin();

  if (!password) {
    console.error(`Password required:  ${usage}`);
    process.exit(1);
  }

  const problem = reject(password);
  if (problem) {
    console.error(`${problem}\nNothing written. Pass it without them, or pipe it in with \`-\` if the shell is adding them.`);
    process.exit(1);
  }

  return password;
}

// The built pages carry their payload as four fields in a script tag. Parsed
// here rather than borrowed from a shell module, so that this stays usable by
// every page's build regardless of how that page renders its gate.
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

/** True when the password decrypts the payload of an already-built page. */
export async function opens(page, password) {
  const payload = payloadOf(page);
  if (!payload) return null;

  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: payload.salt, iterations: payload.iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: payload.iv }, key, payload.data);
    return true;
  } catch {
    return false;
  }
}

/**
 * Refuses a rebuild that would change the password, before anything is written.
 *
 * `published` is the page about to be replaced, or null when there is none yet.
 */
export async function keepPassword({ published, password, rotate, source }) {
  if (rotate) {
    console.log(`Rotating the password on ${source}. The old one will not open what this writes.`);
    return;
  }

  if (published === null) return;

  const verdict = await opens(published, password);

  if (verdict === null) {
    console.warn(`${source} carries no readable payload, so the password could not be checked against it. Continuing.`);
    return;
  }

  if (!verdict) {
    console.error(`This password does not open ${source}.

Rebuilding with it would change that page's password. Nobody would notice until
a reader was locked out, so nothing has been written.

If you meant to keep the current password, look at what you passed: a password
in double quotes has been through the shell, which expands $, a backtick and a
backslash. Pipe it in with \`-\` instead.

If you really do mean to change the password, pass --rotate.`);
    process.exit(1);
  }

  console.log(`Password unchanged — it opens the ${source} being replaced.`);
}

/**
 * Proves the page just written opens with the password it was built from, so a
 * build never leaves behind a page nobody can open.
 */
export async function confirmWritten({ page, password, source }) {
  if (await opens(page, password) !== true) {
    console.error(`${source} was written but does not decrypt with the password it was built from. Do not push it.`);
    process.exit(1);
  }
  console.log(`${source} opens with the password it was built from.`);
}

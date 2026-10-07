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
 *   node powerbee/build.mjs -               # read the password from stdin
 *   node powerbee/build.mjs - --rotate      # and change the password
 *
 * A rebuild keeps the deck's password: the build refuses to run unless the
 * password opens the page it is about to replace, so a mistyped or mangled one
 * cannot lock readers out. Changing it has to be asked for with --rotate.
 *
 * The page around the ciphertext — the password gate — is shell.html. Fixing
 * the gate needs no password: see reshell.mjs.
 */

import { webcrypto as crypto } from 'node:crypto';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';

import { confirmWritten, keepPassword, readPassword } from '../lib/password.mjs';
import { renderShell } from './shell.mjs';

const ITERATIONS = 310000;

const target = new URL('index.html', import.meta.url);
const argv = process.argv.slice(2);

const password = await readPassword({
  args: argv.filter((arg) => !arg.startsWith('--')),
  usage: 'node powerbee/build.mjs "<password>"',
});

await keepPassword({
  published: await readFile(target, 'utf8').catch(() => null),
  password,
  rotate: argv.includes('--rotate'),
  source: 'powerbee/index.html',
});

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

const shell = await renderShell({
  salt: b64(salt),
  iv: b64(iv),
  data: b64(ciphertext),
  iterations: ITERATIONS,
});

await writeFile(target, shell);
await confirmWritten({ page: shell, password, source: 'powerbee/index.html' });

const size = (n) => `${(n / 1024).toFixed(1)} kB`;
console.log(`powerbee/index.html written — ${size(shell.length)} (payload ${size(ciphertext.byteLength)}, ${ITERATIONS} PBKDF2 iterations)`);
console.log(`powerbee/media/ written — ${mediaFiles.length} encrypted file${mediaFiles.length === 1 ? '' : 's'}`);

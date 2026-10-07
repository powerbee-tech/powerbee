/**
 * The published page is a shell — the password gate — wrapped around an
 * encrypted payload. The shell is plaintext and carries nothing confidential,
 * so it is kept in shell.html where it can be read and edited like the HTML it
 * is.
 *
 * Two scripts fill it in: build.mjs, which encrypts a fresh source, and
 * reshell.mjs, which re-renders the shell around the payload that is already
 * published and therefore needs no password.
 */

import { readFile } from 'node:fs/promises';

// Link previews need absolute URLs. Vercel serves this directory at /powerbee
// on the canonical host; override SITE_URL to check a preview deployment.
export const SITE_URL = (process.env.SITE_URL ?? 'https://powerbee.tech/powerbee').replace(/\/$/, '');

// Preview metadata in shell.html carries the company name only — the hostname
// already reveals it. Never put figures, patents or technical claims there:
// previews are fetched by third-party servers and shown to anyone holding the
// link, password or not.

export async function renderShell({ salt, iv, data, iterations, siteUrl = SITE_URL }) {
  const template = await readFile(new URL('shell.html', import.meta.url), 'utf8');

  const fields = {
    __SITE_URL__: siteUrl,
    __SALT__: salt,
    __IV__: iv,
    __DATA__: data,
    __ITERATIONS__: String(iterations),
  };

  let page = template;
  for (const [placeholder, value] of Object.entries(fields)) {
    if (!page.includes(placeholder)) {
      throw new Error(`shell.html has no ${placeholder} placeholder — the template and the build have drifted.`);
    }
    page = page.split(placeholder).join(value);
  }
  return page;
}

/** Reads the four payload fields back out of a built page. */
export function readPayload(page, source) {
  const field = (name) => {
    const match = page.match(new RegExp(name + ':\\s*"([A-Za-z0-9+/=]+)"'));
    if (!match) throw new Error(`Could not find "${name}" in ${source} — is it a built page?`);
    return match[1];
  };

  const iterations = Number(page.match(/iterations:\s*(\d+)/)?.[1]);
  if (!iterations) throw new Error(`Could not find "iterations" in ${source} — is it a built page?`);

  return { salt: field('salt'), iv: field('iv'), data: field('data'), iterations };
}

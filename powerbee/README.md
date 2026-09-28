# Investor deck

Password-protected deck served at `powerbee.tech/powerbee`. `index.html` is generated
and contains only AES-256-GCM ciphertext; the key is derived from the password in
the browser with PBKDF2-SHA256 (310 000 iterations). Nothing readable ships in
this repository.

## Build

The plaintext source lives in `content/deck.html`, which is gitignored and must
never be committed. After editing it, regenerate the published page:

```sh
node powerbee/build.mjs "<password>"
```

That rewrites `powerbee/index.html`. Commit and push it; Vercel serves this
directory at `/powerbee`, so it goes live on the next push to `main`, and a branch
push gets a preview deployment first. Changing the password is the same command
with a new value.

The deck was served at `/deck` until the directory was renamed. That address and
everything under it 301s here in `vercel.json`, so the links already shared —
including the `assets/og.png` a cached link preview points at — keep working.

This is one of three encrypted pages in the repository: `build.mjs` at the root
builds the document served at `/`, this one builds the deck served at
`/powerbee`, and `polishengine/build.mjs` builds the Polish Engine project deck
served at `/polishengine`. They share nothing but the scheme, and each has its
own password.

## Editing from a machine that has no source

`powerbee/index.html` is the only copy of the deck in the repository, so recover
an editable source from it:

```sh
node powerbee/unbuild.mjs "<password>"   # writes content/deck.html
# edit content/deck.html
node powerbee/build.mjs "<password>"     # rewrites index.html
```

That round trip is what makes it possible to iterate from a fresh clone, a cloud
agent or a phone with nothing but the password.

## Relationship to the source presentation

The deck is a restyled web version of `PowerBee-mini-power-generator.pdf` (18
slides, kept in Google Drive). The wording is transcribed verbatim, with one
exception: the raise figures are withheld until the round is settled, because the
PDF's own slides 11 and 17 contradict each other on them.

Characters the PDF's subset fonts mangle on extraction (`€`, `CO₂`, apostrophes,
Polish diacritics in surnames) are restored, and every such repair is listed in
`content/DEVIATIONS.md` — gitignored, because naming a deviation means quoting
the deck. Read it before concluding that something on the page is a
transcription error.

## Notes

- Requires Node 18+ (uses the built-in Web Crypto API). No dependencies.
- The ciphertext is public, so an attacker can brute-force offline. Use a
  high-entropy password and share it out of band, never in this repository or in
  commit messages.
- Decryption needs a secure context: `https://` or `localhost`. Opening the file
  over `file://` will not work.
- While iterating, open `content/deck.html` directly instead of rebuilding — it
  is the same markup, unencrypted.
- `assets/` is served unencrypted, so it holds only the favicon and the link
  preview card. Anything confidential belongs inside `content/deck.html` or
  `content/` media — never in `assets/`.
- Photos and videos referenced as `content/…` are encrypted at build time into
  `media/<key-prefix>/<name>.enc` so a cached ciphertext cannot outlive its key.
  The media key lives inside the password-encrypted HTML.
  A direct `.enc` URL returns ciphertext (HTTP 200), not a playable file.
  Plaintext `/powerbee/content/*.mp4` is not deployed.
- `og.png` is a screenshot of `og-template.html` at exactly 1200x630.
- `/powerbee-1` 301s here. Rollback is a git revert of the published
  `powerbee/index.html` and `powerbee/media/`.

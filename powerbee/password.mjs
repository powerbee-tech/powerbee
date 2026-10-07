/**
 * How build.mjs and unbuild.mjs take the password, and the one rule the gate
 * and the build have to agree on.
 *
 * A password shared over chat, mail or a PDF picks up characters nobody typed:
 * a newline from the copy, a non-breaking space from formatted text, a
 * zero-width character from a link preview. The gate in shell.html removes
 * those from what the reader enters, so that a pasted password still opens the
 * deck. The build therefore must never encrypt a password that carries them —
 * the gate would strip them off every attempt and the deck could not be opened
 * with the password it was built with. Such a password is refused here instead
 * of being published.
 *
 * Keep REMOVED and FLATTENED in step with the gate's own two expressions.
 */

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
 * Prefer `-` for anything but a throwaway password. An argv literal has already
 * been through the shell, which expands `$`, a backtick and a backslash inside
 * double quotes; a build that encrypted the mangled result is indistinguishable
 * from a build that rotated the password, and nothing notices until a reader is
 * locked out.
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

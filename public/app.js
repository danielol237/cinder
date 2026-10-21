// Cinder client.
//
// Everything here runs in the browser. The server is a dumb encrypted-blob
// locker: it never receives the plaintext and never receives the key.
//
//   secret --AES-GCM(key)--> ciphertext --> POST /api/secrets
//   key -----------------------------------> URL fragment (#k=...)
//
// The fragment is the one part of a URL that browsers never put on the wire,
// so the key stays with the link and out of every proxy log on the path.

import { encryptSecret, decryptSecret, exportKey, generateKey, importKey } from './crypto.js';

/* ---------------------------------------------------------------------- api */

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw Object.assign(new Error(data.error ?? 'request_failed'), { status: response.status, data });
  }
  return data;
}

/* --------------------------------------------------------------------- dom */

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'html') node.innerHTML = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child) node.append(child);
  }
  return node;
}

const app = document.getElementById('app');

function screen(...nodes) {
  app.replaceChildren(...nodes);
  app.scrollIntoView({ block: 'start' });
}

function notice(message, tone = 'error') {
  return el('p', { class: `notice notice--${tone}`, role: tone === 'error' ? 'alert' : 'status', text: message });
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = 'copied';
    button.classList.add('is-done');
    setTimeout(() => {
      button.textContent = original;
      button.classList.remove('is-done');
    }, 1600);
  } catch {
    button.textContent = 'press ctrl+c';
  }
}

/* ------------------------------------------------------------------ create */

const TTL_OPTIONS = [
  { label: '5 minutes', value: 5 * 60_000 },
  { label: '1 hour', value: 60 * 60_000 },
  { label: '24 hours', value: 24 * 60 * 60_000 },
  { label: '7 days', value: 7 * 24 * 60 * 60_000 },
];

function createView() {
  const textarea = el('textarea', {
    id: 'secret',
    class: 'field field--area',
    rows: '6',
    placeholder: 'Paste the password, key, or note…',
    spellcheck: 'false',
    autocomplete: 'off',
    maxlength: '32000',
  });

  const counter = el('span', { class: 'counter', text: '0 / 32000' });
  textarea.addEventListener('input', () => {
    counter.textContent = `${textarea.value.length} / 32000`;
  });

  const ttl = el(
    'select',
    { id: 'ttl', class: 'field field--select' },
    TTL_OPTIONS.map((option) => el('option', { value: String(option.value), text: option.label })),
  );
  ttl.value = String(24 * 60 * 60_000);

  const passphrase = el('input', {
    id: 'passphrase',
    class: 'field',
    type: 'password',
    placeholder: 'Optional — adds a second gate',
    autocomplete: 'new-password',
    minlength: '8',
    maxlength: '256',
  });

  const errorSlot = el('div', { class: 'slot' });
  const submit = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Create one-time link' });

  const form = el('form', { class: 'card', novalidate: 'true' }, [
    el('label', { class: 'label', for: 'secret', text: 'The secret' }),
    textarea,
    el('div', { class: 'row row--between' }, [counter]),
    el('div', { class: 'grid' }, [
      el('div', { class: 'stack' }, [
        el('label', { class: 'label', for: 'ttl', text: 'Self-destructs in' }),
        ttl,
      ]),
      el('div', { class: 'stack' }, [
        el('label', { class: 'label', for: 'passphrase', text: 'Passphrase' }),
        passphrase,
      ]),
    ]),
    errorSlot,
    submit,
  ]);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorSlot.replaceChildren();

    const plaintext = textarea.value;
    if (plaintext.trim().length === 0) {
      errorSlot.replaceChildren(notice('Nothing to encrypt yet.'));
      textarea.focus();
      return;
    }

    submit.disabled = true;
    submit.textContent = 'Encrypting…';

    try {
      const key = await generateKey();
      const ciphertext = await encryptSecret(plaintext, key);
      const keyFragment = await exportKey(key);

      const body = { ciphertext, ttlMs: Number(ttl.value) };
      if (passphrase.value.length > 0) body.passphrase = passphrase.value;

      const { id, expiresAt } = await api('/api/secrets', {
        method: 'POST',
        body: JSON.stringify(body),
      });

      // Wipe the plaintext from the field as soon as it is safely encrypted.
      textarea.value = '';
      const link = `${location.origin}/s/${id}#k=${keyFragment}`;
      resultView({ link, expiresAt, hasPassphrase: Boolean(body.passphrase) });
    } catch (err) {
      errorSlot.replaceChildren(notice(friendlyError(err)));
      submit.disabled = false;
      submit.textContent = 'Create one-time link';
    }
  });

  screen(
    el('section', { class: 'hero' }, [
      el('h1', { html: 'Share a secret.<br><em>Once.</em>' }),
      el('p', {
        class: 'lede',
        text: 'Encrypted in your browser before it leaves the page. The link works a single time, then the ciphertext is gone.',
      }),
    ]),
    form,
    el('section', { class: 'facts' }, [
      fact('Zero-knowledge', 'The key rides in the URL fragment, which browsers never transmit. The server stores a locked box it cannot open.'),
      fact('Single use', 'First successful read destroys the record. There is no undo and no copy.'),
      fact('No accounts', 'No email, no signup, no tracking pixels. Nothing to leak later.'),
    ]),
  );
}

function fact(title, body) {
  return el('article', { class: 'fact' }, [
    el('h2', { text: title }),
    el('p', { text: body }),
  ]);
}

function friendlyError(err) {
  if (err?.status === 429) return 'Too many requests. Give it a minute.';
  if (err?.status === 413) return 'That secret is too large for a single link.';
  if (err?.data?.error === 'invalid_passphrase') return 'Passphrase needs to be 8 characters or more.';
  if (err?.message === 'request_failed') return 'Something went wrong on the way out. Try again.';
  return 'Could not create the link. Try again.';
}

/* ------------------------------------------------------------------ result */

function resultView({ link, expiresAt, hasPassphrase }) {
  const input = el('input', { class: 'field field--mono', readonly: 'readonly', value: link });
  input.addEventListener('focus', () => input.select());

  const copy = el('button', { class: 'btn btn--primary', type: 'button', text: 'Copy link' });
  copy.addEventListener('click', () => copyText(link, copy));

  const when = new Date(expiresAt).toLocaleString();

  screen(
    el('section', { class: 'hero hero--tight' }, [
      el('h1', { html: 'Link is live.<br><em>Send it once.</em>' }),
      el('p', { class: 'lede', text: 'Whoever opens it gets one shot. After that the ciphertext is deleted.' }),
    ]),
    el('div', { class: 'card' }, [
      el('label', { class: 'label', for: 'link', text: 'One-time link' }),
      input,
      el('div', { class: 'row' }, [copy]),
      el('ul', { class: 'warn-list' }, [
        el('li', { text: `Expires ${when} if nobody opens it first.` }),
        el('li', { text: hasPassphrase ? 'Passphrase required — send it over a different channel.' : 'No passphrase set. The link alone is enough.' }),
        el('li', { text: 'Anything that fetches the link preview could burn it. Paste it raw where you can.' }),
      ]),
      el('button', { class: 'btn btn--ghost', type: 'button', text: 'Make another', onclick: createView }),
    ]),
  );
}

/* ------------------------------------------------------------------ reveal */

async function revealView(id) {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const keyFragment = fragment.get('k');

  const errorSlot = el('div', { class: 'slot' });
  const submit = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Reveal secret' });

  const passphrase = el('input', {
    id: 'passphrase',
    class: 'field',
    type: 'password',
    placeholder: 'Passphrase',
    autocomplete: 'current-password',
  });

  const passphraseBlock = el('div', { class: 'stack is-hidden' }, [
    el('label', { class: 'label', for: 'passphrase', text: 'This one is also locked with a passphrase' }),
    passphrase,
  ]);

  const form = el('form', { class: 'card', novalidate: 'true' }, [
    el('p', { class: 'lede lede--tight', text: 'Someone left you something. It can only be read once.' }),
    passphraseBlock,
    errorSlot,
    submit,
  ]);

  screen(
    el('section', { class: 'hero hero--tight' }, [
      el('h1', { html: 'A secret,<br><em>for you.</em>' }),
    ]),
    form,
  );

  if (!keyFragment) {
    form.replaceChildren(
      notice('This link is missing its decryption key. Ask the sender to resend the full link — nothing was lost, the key simply never reached this page.'),
    );
    return;
  }

  // Ask the server for metadata only. This does not consume the secret.
  try {
    const meta = await api(`/api/secrets/${encodeURIComponent(id)}`);
    if (meta.requiresPassphrase) passphraseBlock.classList.remove('is-hidden');
  } catch (err) {
    form.replaceChildren(
      notice(
        err?.status === 404
          ? 'This secret has already been read, or it expired.'
          : 'Could not reach the vault. Check your connection.',
      ),
    );
    return;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorSlot.replaceChildren();
    submit.disabled = true;
    submit.textContent = 'Opening…';

    try {
      const body = {};
      if (!passphraseBlock.classList.contains('is-hidden') && passphrase.value.length > 0) {
        body.passphrase = passphrase.value;
      }

      const { ciphertext } = await api(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
        method: 'POST',
        body: JSON.stringify(body),
      });

      const key = await importKey(keyFragment);
      const plaintext = await decryptSecret(ciphertext, key);

      // The secret is now gone server-side. Drop the key from the address bar
      // so a screenshot or a shared tab does not carry it.
      history.replaceState(null, '', `/s/${id}`);

      revealedView(plaintext);
    } catch (err) {
      submit.disabled = false;
      submit.textContent = 'Reveal secret';
      if (err?.status === 403) {
        errorSlot.replaceChildren(notice('Wrong passphrase. The secret is still there.'));
        passphrase.select();
      } else if (err?.status === 404) {
        form.replaceChildren(notice('This secret has already been read, or it expired.'));
      } else if (err?.name === 'OperationError') {
        errorSlot.replaceChildren(notice('The key in this link does not match the secret.'));
      } else {
        errorSlot.replaceChildren(notice('Could not open it. Try again.'));
      }
    }
  });
}

function revealedView(plaintext) {
  const output = el('pre', { class: 'reveal', text: plaintext });
  const copy = el('button', { class: 'btn btn--primary', type: 'button', text: 'Copy' });
  copy.addEventListener('click', () => copyText(plaintext, copy));

  screen(
    el('section', { class: 'hero hero--tight' }, [
      el('h1', { html: 'Here it is.<br><em>Now it\u2019s gone.</em>' }),
    ]),
    el('div', { class: 'card' }, [
      output,
      el('div', { class: 'row' }, [copy]),
      el('p', { class: 'fineprint', text: 'The server deleted this the moment it was read. Reloading will not bring it back.' }),
    ]),
  );
}

/* ------------------------------------------------------------------ router */

function route() {
  const match = /^\/s\/([A-Za-z0-9_-]{1,64})$/.exec(location.pathname);
  if (match) revealView(match[1]);
  else createView();
}

route();

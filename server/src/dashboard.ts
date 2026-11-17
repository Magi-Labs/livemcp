import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

type Credentials = {
  id: string;
  agentToken: string;
  browserToken: string;
};

const entriesLimit = 200;
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest();
const escape = (value: string) => value.replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]!);

export function createDashboard(password: string, accounts: readonly Credentials[]) {
  const expected = digest(`admin:${password}`);
  const entries: { at: string; message: string }[] = [];

  function log(message: string) {
    entries.push({ at: new Date().toISOString(), message });
    if (entries.length > entriesLimit) entries.shift();
  }

  function handle(req: IncomingMessage, res: ServerResponse) {
    const path = req.url?.split('?')[0];
    if (path !== '/' && path !== '/dashboard') return false;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.method !== 'GET') {
      res.writeHead(405, { Allow: 'GET' }).end();
      return true;
    }
    if (path === '/') {
      res.writeHead(302, { Location: '/dashboard' }).end();
      return true;
    }
    const authorization = req.headers.authorization ?? '';
    const credentials = authorization.length <= 1024 && /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(authorization);
    if (!credentials || !timingSafeEqual(digest(Buffer.from(credentials[1], 'base64')), expected)) {
      res.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="LiveMCP dashboard", charset="UTF-8"',
        'Content-Type': 'text/plain; charset=utf-8',
      }).end('Dashboard sign-in required');
      return true;
    }
    const nonce = randomBytes(18).toString('base64');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
      'Cross-Origin-Resource-Policy': 'same-origin',
    }).end(renderDashboard(nonce, accounts, entries));
    return true;
  }

  return { handle, log };
}

function renderDashboard(nonce: string, accounts: readonly Credentials[], entries: readonly { at: string; message: string }[]) {
  const tokens = accounts.map((account, index) => `
    <fieldset>
      <legend>${escape(account.id)}</legend>
      ${tokenField(`agent-${index}`, 'Agent bearer token', account.agentToken)}
      ${tokenField(`browser-${index}`, 'Browser extension token', account.browserToken)}
    </fieldset>`).join('');
  const logs = [...entries].reverse().map(({ at, message }) => `${at}  ${message}`).join('\n');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LiveMCP dashboard</title>
  <style nonce="${nonce}">
    :root { color-scheme: dark; font: 16px/1.5 Geist, Inter, system-ui, sans-serif; }
    body { margin: 0; background: #101313; color: #edf2f0; }
    main { max-width: 52rem; margin: auto; padding: 3rem 1.25rem 4rem; }
    h1 { font-size: clamp(2rem, 5vw, 3rem); line-height: 1.1; margin: 0; letter-spacing: -.04em; }
    h2 { font-size: 1.1rem; margin: 0; }
    p { color: #a7b6b0; margin: .35rem 0 0; }
    section { margin-top: 2rem; background: #191e1d; border: 1px solid #34443f; border-radius: .8rem; padding: clamp(1rem, 4vw, 1.5rem); }
    fieldset { min-width: 0; border: 0; margin: 1.1rem 0 0; padding: 0; }
    fieldset + fieldset { padding-top: .75rem; border-top: 1px solid #34443f; }
    legend { font-weight: 650; color: #a6eacb; padding: 0; overflow-wrap: anywhere; }
    label { display: block; font-size: .86rem; margin: .6rem 0 .28rem; }
    .row, .bar { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
    .bar { justify-content: space-between; }
    input, pre { font: .85rem/1.5 ui-monospace, monospace; background: #0f1312; color: #d9e9e1; border: 1px solid #34443f; border-radius: .45rem; padding: .6rem .75rem; }
    input { flex: 1 1 12rem; min-width: 0; }
    button, .button { font: inherit; font-size: .85rem; font-weight: 650; padding: .5rem .75rem; border-radius: .45rem; border: 1px solid #4e6860; background: #232e2a; color: #edf2f0; cursor: pointer; text-decoration: none; }
    .copy { color: #a6eacb; }
    button:hover, .button:hover { background: #2b3e36; }
    :focus-visible { outline: 2px solid #a6eacb; outline-offset: 3px; }
    pre { max-height: 23rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 1rem 0 0; }
    #notice { min-height: 1.5em; color: #a6eacb; font-size: .86rem; margin-top: .75rem; }
  </style>
</head>
<body>
  <main>
    <h1>LiveMCP dashboard</h1>
    <section aria-labelledby="tokens-heading">
      <h2 id="tokens-heading">Connection tokens</h2>
      ${tokens || '<p>No connection tokens are configured.</p>'}
      <p id="notice" role="status" aria-live="polite"></p>
    </section>
    <section aria-labelledby="logs-heading">
      <div class="bar">
        <h2 id="logs-heading">Recent hub logs</h2>
        <div class="row">
          <a class="button" href="/dashboard">Refresh logs</a>
          <button class="copy" type="button" data-copy="logs" data-copied="Logs copied.">Copy logs</button>
        </div>
      </div>
      <p>Last ${entriesLimit} events since the hub started. Timestamps are UTC.</p>
      <pre id="logs" tabindex="0" aria-label="Hub activity">${escape(logs || 'No events yet.')}</pre>
    </section>
  </main>
  <script nonce="${nonce}">
    const notice = document.getElementById('notice');
    document.querySelectorAll('[data-copy]').forEach(button => {
      button.addEventListener('click', async () => {
        const source = document.getElementById(button.dataset.copy);
        try {
          await navigator.clipboard.writeText(source instanceof HTMLInputElement ? source.value : source.textContent);
          const original = button.textContent;
          if (original === 'Copied') return;
          button.textContent = 'Copied';
          notice.textContent = button.dataset.copied;
          setTimeout(() => { button.textContent = original; }, 1500);
        } catch {
          notice.textContent = 'Clipboard unavailable. Select the text to copy it manually.';
        }
      });
    });
    document.querySelectorAll('[data-toggle]').forEach(button => {
      button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.toggle);
        const reveal = input.type === 'password';
        input.type = reveal ? 'text' : 'password';
        button.textContent = reveal ? 'Hide' : 'Show';
        button.setAttribute('aria-pressed', String(reveal));
      });
    });
  </script>
</body>
</html>`;
}

function tokenField(id: string, label: string, value: string) {
  const type = id.startsWith('agent-') ? 'Agent' : 'Browser';
  return `
    <label for="${id}">${label}</label>
    <div class="row">
      <input id="${id}" type="password" value="${escape(value)}" readonly autocomplete="off" spellcheck="false">
      <button type="button" data-toggle="${id}" aria-label="Show or hide ${label.toLowerCase()}" aria-pressed="false">Show</button>
      <button class="copy" type="button" data-copy="${id}" data-copied="${type} token copied." aria-label="Copy ${type.toLowerCase()} token">Copy</button>
    </div>`;
}

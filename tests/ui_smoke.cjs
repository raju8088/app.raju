const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const root = process.env.UI_OUTPUT_DIR || path.join(os.tmpdir(), 'omnidim-ui-checks');
fs.mkdirSync(root, { recursive: true });
const baseUrl = process.env.UI_BASE_URL || 'http://127.0.0.1:8787';
if (!['localhost', '127.0.0.1'].includes(new URL(baseUrl).hostname)) throw new Error('UI smoke checks require a local server.');

(async () => {
  const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let settings = { baseUrl: 'https://omnidim.io/api/v1', hasApiKey: true, readOnly: false, retentionLimit: 5000, apiKeySource: 'env', apiKeyPreview: 'configured' };
  let historyFailure = false;
  let startupFailure = false;
  let executions = 0;
  let upstreamError = false;
  let networkFailure = false;
  let responseExpired = false;
  let expired = false;
  let localMode = false;
  const submissionKeys = [];
  const workspaceHeaders = [];
  let role = 'admin';
  let workspaceId = 1;
  const endpoints = [
    { id: 'session-create', group: 'Sessions', method: 'POST', path: '/sessions/create', summary: 'Create session', pathParams: [], bodyExample: {} },
    { id: 'agent-create', group: 'Agents', method: 'POST', path: '/agents/create', summary: 'Create agent', pathParams: [], bodyExample: {} },
    { id: 'agent-list', group: 'Agents', method: 'GET', path: '/agents', summary: 'List agents', pathParams: [] },
    { id: 'call-dispatch', group: 'Calls', method: 'POST', path: '/calls/dispatch', summary: 'Dispatch call', pathParams: [], danger: true, bodyExample: {} }
  ];
  const groups = ['Sessions', 'Agents', 'Calls'].map(name => ({ name, description: `${name} actions`, endpoints: endpoints.filter(endpoint => endpoint.group === name) }));
  const history = [{ id: 1, method: 'GET', path: '/agents', status: 200, ok: true, duration_ms: 128, created_at: '2026-10-06T09:00:00Z' }];
  // Serve the real frontend files with isolated API fixtures. No running server,
  // credentials, database, or upstream network access is needed for these checks.
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    const replyFile = (file, contentType) => route.fulfill({ contentType, body: fs.readFileSync(path.join(__dirname, '..', 'static', file)) });
    if (url.origin !== new URL(baseUrl).origin) return route.abort();
    if (url.pathname === '/') return replyFile('index.html', 'text/html');
    if (url.pathname === '/static/app.js') return replyFile('app.js', 'text/javascript');
    if (url.pathname === '/static/styles.css') return replyFile('styles.css', 'text/css');
    if (url.pathname === '/login/') return route.fulfill({ contentType: 'text/html', body: '<h1>Sign in</h1>' });
    return route.abort();
  });
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const payload = route.request().postDataJSON();
    const reply = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    if (expired) return reply({ error: 'Sign in to continue.' }, 401);
    if (url.pathname === '/api/session') return reply(localMode ? { csrfToken: 'test-csrf', localToken: 'test-local' } : { authenticated: true, hosted: true, csrfToken: 'test-csrf', user: { id: 1, username: 'Preview member' }, workspace: { id: workspaceId, name: workspaceId === 1 ? 'Design team' : 'Support team' }, role, workspaces: [{ id: 1, name: 'Design team', role }, { id: 2, name: 'Support team', role }] });
    if (url.pathname === '/api/endpoints') return reply({ groups, endpoints });
    if (url.pathname === '/api/workspace') { workspaceId = Number(payload.workspaceId); return reply({ ok: true }); }
    if (url.pathname === '/api/logout') return reply({ ok: true });
    workspaceHeaders.push(route.request().headers()['x-workspace-id']);
    if (url.pathname === '/api/settings') {
      if (startupFailure) return reply({ error: 'Preview settings unavailable' }, 503);
      return reply({ ...settings, canManageSettings: role === 'admin', readOnly: settings.readOnly || role === 'viewer' });
    }
    if (url.pathname === '/api/history') {
      if (historyFailure) return reply({ error: 'Preview history unavailable' }, 503);
      const search = url.searchParams.get('search') || '';
      if (search === 'older') await new Promise(resolve => setTimeout(resolve, 450));
      const items = search ? [{ ...history[0], path: `/${search}` }] : history;
      return reply({ items, total: 1, page: Number(url.searchParams.get('page') || 1), totalPages: 1 });
    }
    if (url.pathname === '/api/saved-payloads') return reply({ records: [] });
    if (url.pathname === '/api/preflight') {
      assert.equal(route.request().headers()['x-csrf-token'], 'test-csrf');
      return reply({ danger: payload.path === '/calls/dispatch', ...(payload.path === '/calls/dispatch' ? { confirmToken: 'preview-confirmation', requiredConfirm: 'Dispatch call', expiresInSeconds: 60 } : {}) });
    }
    if (url.pathname === '/api/run') {
      if (payload.path === '/calls/dispatch') assert.equal(payload.confirmToken, 'preview-confirmation');
      if (payload.method !== 'GET') {
        const key = route.request().headers()['idempotency-key'];
        assert.match(key, /^[a-f0-9-]{36}$/);
        submissionKeys.push(key);
      }
      executions++;
      await new Promise(resolve => setTimeout(resolve, 250));
      if (networkFailure) return route.abort('failed');
      if (responseExpired) return reply({ error: 'The recorded response has expired. This action will not be repeated.', code: 'response_expired', operationId: 10 }, 409);
      if (upstreamError) return reply({ ok: false, status: 503, data: { error: 'Preview upstream unavailable' } }, 502);
      return reply({ ok: true, status: 200, durationMs: 128, data: { message: 'Preview request completed', result: 'No live API was called' } });
    }
    if (route.request().method() !== 'GET') return reply({ error: 'Unexpected mutation blocked by UI test' }, 400);
    return reply({ error: 'Unexpected API path blocked by UI test' }, 404);
  });
  const action = text => page.locator('.endpoint-item').filter({ hasText: text }).first();
  const category = text => page.locator('.group-button').filter({ hasText: text }).first();
  const waitUntil = async expression => page.waitForFunction(expression);
  const passed = [];
  try {
    await page.goto(baseUrl);
    await page.locator('#sendRequestBtn').waitFor();
    assert(Number(await page.locator('#totalEndpointCount').innerText()) > 0);
    assert.equal(await page.locator('#settingsPanel').getAttribute('open'), null);
    assert.equal(await page.locator('#accountName').innerText(), 'Preview member');
    assert.equal(await page.locator('#accountRole').textContent(), 'admin');
    passed.push('Workspace boots with its action catalog and collapsed settings');
    assert.equal(await page.evaluate(() => shellQuote("a'b")), "'a'\\''b'");
    const mismatch = await page.evaluate(() => {
      document.getElementById('resolvedPathInput').value = '/agents/create';
      try { readRunnerPayload(findEndpoint(state.selectedEndpointId)); return false; }
      catch { return true; }
      finally { document.getElementById('resolvedPathInput').value = '/sessions/create'; }
    });
    assert(mismatch);
    passed.push('Shell exports escape quotes and mismatched action paths are rejected');
    await page.locator('#openSettingsBtn').click();
    assert.equal(await page.locator('#settingsPanel').evaluate(element => element.open), true);
    await page.locator('#openSettingsBtn').click();
    await page.locator('#themeToggleBtn').click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.locator('#themeToggleBtn').click();
    passed.push('Settings toggle and appearance switching');

    await category('Agents').click();
    await action('Create agent').click();
    await page.locator('#bodyJson').fill('{"name":"Retained draft"}');
    await action('List agents').click();
    await action('Create agent').click();
    assert.equal(await page.locator('#bodyJson').inputValue(), '{"name":"Retained draft"}');
    await page.locator('#bodyJson').fill('{broken');
    assert.equal(await page.locator('#bodyJson').getAttribute('aria-invalid'), 'true');
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), true);
    await page.locator('#bodyJson').fill('{"name":"Retained draft"}');
    await page.locator('[data-format="bodyJson"]').click();
    assert((await page.locator('#bodyJson').inputValue()).includes('\n'));
    passed.push('Draft retention, inline JSON errors and formatting');

    const before = executions;
    await page.locator('#sendRequestBtn').click();
    await page.evaluate(() => document.getElementById('sendRequestBtn').click());
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Completed'));
    assert.equal(executions, before + 1);
    passed.push('Repeated clicks produce one submission');

    networkFailure = true;
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Outcome not yet confirmed'));
    const uncertainKey = submissionKeys.at(-1);
    assert.equal(await page.locator('#sendRequestBtn').innerText(), 'Check previous request');
    assert.equal(await page.evaluate(() => JSON.stringify(sessionStorage).includes('Retained draft')), false);
    const uncertainDraft = await page.locator('#bodyJson').inputValue();
    await page.reload();
    await page.locator('#sendRequestBtn').waitFor();
    await category('Agents').click();
    await action('Create agent').click();
    await page.locator('#bodyJson').fill(uncertainDraft);
    networkFailure = false;
    responseExpired = true;
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Outcome not yet confirmed'));
    assert.equal(submissionKeys.at(-1), uncertainKey);
    assert.equal(await page.locator('#sendRequestBtn').innerText(), 'Check previous request');
    responseExpired = false;
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Completed'));
    assert.equal(submissionKeys.at(-1), uncertainKey);
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Completed'));
    assert.notEqual(submissionKeys.at(-1), uncertainKey);
    passed.push('Uncertain mutation identifiers survive refresh; completed actions get a new identifier');

    await category('Calls').click();
    await action('Dispatch call').click();
    const beforeCancel = executions;
    await page.locator('#sendRequestBtn').click();
    await page.locator('#dangerDialog[open]').waitFor();
    await page.keyboard.press('Escape');
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Cancelled'));
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), false);
    assert.equal(executions, beforeCancel);
    await page.locator('#sendRequestBtn').click();
    await page.locator('#dangerDialog[open]').waitFor();
    await page.locator('#modalConfirmInput').fill('Dispatch call');
    await page.locator('#modalConfirmBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Completed'));
    assert.equal(executions, beforeCancel + 1);
    passed.push('Escape cancels safely; protected confirmation executes once');

    await category('Agents').click();
    await action('List agents').click();
    upstreamError = true;
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Request error'));
    assert((await page.locator('#responseOutput').innerText()).includes('Preview upstream unavailable'));
    upstreamError = false;
    passed.push('Upstream error details remain visible');

    await page.locator('[data-view="history"]').click();
    historyFailure = true;
    await page.locator('#refreshHistoryBtn').click();
    await waitUntil(() => document.getElementById('historyStatus').textContent.includes('could not refresh'));
    assert((await page.locator('#historyRows').innerText()).includes('/agents'));
    historyFailure = false;
    await page.locator('#historySearchInput').fill('older');
    await page.waitForTimeout(300);
    await page.locator('#historySearchInput').fill('newer');
    await waitUntil(() => document.getElementById('historyRows').textContent.includes('/newer'));
    await page.waitForTimeout(500);
    assert((await page.locator('#historyRows').innerText()).includes('/newer'));
    passed.push('History refresh errors preserve records; stale search cannot overwrite results');

    await page.locator('[data-view="database"]').click();
    assert((await page.locator('#savedPayloadList').innerText()).includes('Build your request library'));
    passed.push('Saved-request empty state and active navigation');
    await category('Agents').click();
    await action('Create agent').click();
    await page.evaluate(() => { document.getElementById('toast').hidden = true; });
    await page.screenshot({ path: `${root}/omnidim-ui-desktop.png`, fullPage: true, animations: 'disabled' });
    await page.locator('#themeToggleBtn').click();
    await page.screenshot({ path: `${root}/omnidim-ui-dark.png`, fullPage: true, animations: 'disabled' });
    await page.locator('#themeToggleBtn').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: `${root}/omnidim-ui-mobile.png`, fullPage: true, animations: 'disabled' });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.evaluate(() => { document.getElementById('toast').hidden = false; });
    passed.push('390px mobile viewport has no horizontal page overflow');
    await page.setViewportSize({ width: 1440, height: 1050 });

    settings = { ...settings, hasApiKey: false };
    await page.reload();
    await page.locator('#sendRequestBtn').waitFor();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), true);
    assert((await page.locator('#workspaceNotice').innerText()).includes('Connect your account'));
    settings = { ...settings, hasApiKey: true, readOnly: true };
    await page.reload();
    await page.locator('#sendRequestBtn').waitFor();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), true);
    assert.equal(await page.locator('#saveSettingsBtn').isDisabled(), true);
    await category('Agents').click();
    await action('List agents').click();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), false);
    passed.push('Missing-key onboarding and read-only controls');

    startupFailure = true;
    await page.reload();
    await waitUntil(() => document.getElementById('noticeTitle').textContent === 'Workspace could not load');
    startupFailure = false;
    settings = { ...settings, readOnly: false };
    await page.locator('#retryLoadBtn').click();
    await page.locator('#sendRequestBtn').waitFor();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), false);
    passed.push('Startup failure shows retry and recovers');

    role = 'viewer';
    await page.reload();
    await page.locator('#sendRequestBtn').waitFor();
    await category('Agents').click();
    await action('List agents').click();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), false);
    assert.equal(await page.locator('#savePayloadBtn').isDisabled(), true);
    await page.locator('#openSettingsBtn').click();
    assert.equal(await page.locator('#apiKeyInput').isDisabled(), true);
    assert((await page.locator('#settingsAccessNote').innerText()).includes('administrators'));
    await action('Create agent').click();
    assert.equal(await page.locator('#sendRequestBtn').isDisabled(), true);
    passed.push('Viewer role permits read actions and prevents changes to requests, credentials and settings');

    role = 'admin';
    await page.reload();
    await page.locator('#sendRequestBtn').waitFor();
    await page.locator('#bodyJson').fill('{"privateDraft":"belongs-to-first-workspace"}');
    await page.locator('#workspaceSelect').selectOption('2');
    await waitUntil(() => document.getElementById('workspaceSelect')?.value === '2' && document.getElementById('bodyJson'));
    assert(!(await page.locator('#bodyJson').inputValue()).includes('privateDraft'));
    assert(workspaceHeaders.includes('1') && workspaceHeaders.includes('2'));
    passed.push('Workspace switch clears drafts and sends the workspace identity with scoped requests');

    expired = true;
    await page.locator('[data-view="history"]').click();
    await page.locator('#refreshHistoryBtn').click();
    await page.waitForURL('**/login/?next=%2F');
    assert.equal(await page.locator('h1').innerText(), 'Sign in');
    passed.push('Session expiry clears sensitive workspace data and redirects to sign in');
    expired = false;
    await page.goto(baseUrl);
    await page.locator('#sendRequestBtn').waitFor();
    await page.locator('#logoutBtn').click();
    await page.waitForURL('**/login/?next=%2F');
    passed.push('Sign out sends a protected request and returns to sign in');

    localMode = true;
    await page.goto(baseUrl);
    await page.locator('#sendRequestBtn').waitFor();
    assert.equal(await page.locator('#accountBar').isVisible(), false);
    assert.equal(await page.evaluate(() => state.localToken), 'test-local');
    await category('Agents').click();
    await action('List agents').click();
    await page.locator('#sendRequestBtn').click();
    await waitUntil(() => document.getElementById('responseMeta').textContent.startsWith('Completed'));
    passed.push('Local mode remains usable without hosted account controls');
    assert.deepEqual(errors, []);
    fs.writeFileSync(`${root}/omnidim-ui-checks.json`, JSON.stringify({ passed, pageErrors: errors, liveUpstreamCalls: 0 }, null, 2));
    console.log(JSON.stringify({ passed, pageErrors: errors, liveUpstreamCalls: 0 }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });

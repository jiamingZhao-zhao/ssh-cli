// Browser-independent regressions; Node is only needed by contributors/CI.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const source = readFileSync(join(__dirname, '../internal/ui/web/app.js'), 'utf8');

test('owned UI sources are strict UTF-8 and retain Chinese labels', () => {
  for (const file of ['app.js', 'app.css', 'index.html']) {
    const bytes = readFileSync(join(__dirname, '../internal/ui/web', file));
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    assert.ok(!text.includes('\uFFFD'), file + ' contains a replacement character');
    if (file === 'index.html') {
      for (const label of ['主机名称：', '主机别名：', '传输队列', '文件', '历史']) assert.ok(text.includes(label), label);
      assert.ok(!text.includes('不写入审计'));
    }
  }
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const timers = [];
  const sandbox = { AbortController, TextDecoder, TextEncoder, Blob, crypto: require('node:crypto').webcrypto,
    document: { hidden: false, addEventListener() {}, getElementById() { return null; } },
    setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout(id) { timers[id - 1] = null; } };
  sandbox.window = sandbox;
  vm.createContext(sandbox); vm.runInContext(source, sandbox);
  const app = sandbox.sshui();
  app.loadAudit = app.loadDashboard = app.loadSessions = () => {};
  return { app, timers, sandbox };
}

function connected(app) {
  app.view = 'terminal'; app.termAlias = app.explicitAlias = 'a'; app.files.alias = 'a';
  app.startMetrics = () => {};
}

test('later directory wins even if the old transport ignores abort', async () => {
  const { app } = fixture(); connected(app);
  const slow = deferred(), fast = deferred();
  app.postRead = (_url, body) => body.path === '/slow' ? slow.promise : fast.promise;
  app.ensureFsRoot = () => {};
  const first = app.listFiles('/slow'), second = app.listFiles('/fast');
  assert.equal(app.filesLoading, true);
  fast.resolve({ path: '/fast', entries: [] }); await second;
  slow.resolve({ path: '/slow', entries: [] }); await first;
  assert.equal(app.files.path, '/fast'); assert.equal(app.filesLoading, false);
});

test('old history error cannot overwrite files after changing pane', async () => {
  const { app } = fixture(); connected(app);
  const history = deferred();
  app.postRead = (url) => url === '/api/history' ? history.promise : Promise.resolve({ path: '/', entries: [] });
  const pending = app.loadHistory('a');
  app.showFiles(); await app.listFiles('/');
  history.reject(new Error('old history error')); await pending;
  assert.equal(app.errors.files, ''); assert.equal(app.files.mode, 'files');
});

test('root response from an earlier host visit cannot contaminate a later visit', async () => {
  const { app } = fixture(); connected(app);
  const old = deferred(), fresh = deferred(); let calls = 0;
  app.postRead = () => (++calls === 1 ? old.promise : fresh.promise);
  app.refreshFiles = () => {};
  const pending = app.ensureFsRoot();
  app.termAlias = app.explicitAlias = 'b'; app.syncWorkspace();
  app.termAlias = app.explicitAlias = 'a'; app.syncWorkspace();
  const current = app.ensureFsRoot();
  fresh.resolve({ path: '/', entries: [{ path: '/new', name: 'new', dir: true }] }); await current;
  old.resolve({ path: '/', entries: [{ path: '/old', name: 'old', dir: true }] }); await pending;
  assert.ok(app.treeRows().some(row => row.path === '/new'));
  assert.ok(!app.treeRows().some(row => row.path === '/old'));
});

test('refresh keeps selection and scroll; navigation clears them', async () => {
  const { app, sandbox } = fixture(); connected(app);
  const list = { clientHeight: 200, scrollTop: 90 };
  sandbox.document.querySelector = selector => selector === '.ws-table-wrap' ? list : null;
  app.files.path = '/work'; app.selectedPath = '/work/a';
  app.ensureFsRoot = () => {};
  app.postRead = async (_url, body) => ({ path: body.path, entries: [{ path: '/work/a', name: 'a' }] });
  await app.listFiles('/work');
  assert.equal(app.selectedPath, '/work/a'); assert.equal(list.scrollTop, 90);
  await app.listFiles('/other');
  assert.equal(app.selectedPath, ''); assert.equal(list.scrollTop, 0);
});

test('host switch restores selection and scroll independently', () => {
  const { app, sandbox } = fixture(); connected(app);
  const list = { clientHeight: 200, scrollTop: 90 };
  sandbox.document.querySelector = selector => selector === '.ws-table-wrap' ? list : null;
  app.refreshFiles = () => {};
  app.files.path = '/work'; app.selectedPath = '/work/a';
  app.termAlias = app.explicitAlias = 'b'; app.syncWorkspace();
  list.scrollTop = 20;
  app.termAlias = app.explicitAlias = 'a'; app.syncWorkspace();
  assert.equal(list.scrollTop, 90); assert.equal(app.selectedPath, '/work/a');
});

test('monitoring failure retains terminal state and labels old samples', () => {
  const { app } = fixture(); connected(app);
  app.termTabs = [{ id: 't', alias: 'a', state: 'connected' }]; app.termActive = 't';
  app.metrics.alias = 'a'; app.metricsUpdated = 1000; app.metricsClock = 31000;
  app.errors.metrics = 'read timeout';
  assert.equal(app.overviewStatus(), '在线'); assert.match(app.metricsCaption(), /未更新.*30 秒前/);
  app.clearLivePanes(); assert.equal(app.metricsUpdated, 0); assert.equal(app.errors.metrics, '');
});

test('NDJSON requires a final result and decodes Chinese across byte boundaries', async () => {
  const { sandbox } = fixture();
  const response = text => {
    const bytes = Buffer.from(text); let i = 0;
    return { body: { getReader: () => ({ read: async () => i < bytes.length ? { value: bytes.subarray(i, ++i), done: false } : { done: true } }) } };
  };
  const result = await sandbox.readNDJSON(response('{"loaded":2,"total":2}\n{"ok":true,"local":"中文目录"}'), () => {});
  assert.equal(result.local, '中文目录');
  await assert.rejects(sandbox.readNDJSON(response('{"loaded":2,"total":2}\n')), /未确认/);
  await assert.rejects(sandbox.readNDJSON({ text: async () => '{"loaded":2}' }), /未确认/);
});

function uploadFixture() {
  const ctx = fixture(), requests = [];
  ctx.sandbox.FormData = class { set() {} };
  ctx.sandbox.sessionStorage = { getItem: () => '' };
  ctx.sandbox.XMLHttpRequest = class {
    constructor() { this.upload = {}; requests.push(this); }
    open() {} setRequestHeader() {} send() {}
    abort() { this.onabort(); }
  };
  return { ...ctx, requests };
}

test('100 percent local upload waits for remote completion and ignores late local progress', async () => {
  const { app, requests } = uploadFixture();
  const pending = app.uploadOne('a', { name: '中文.txt', size: 100 }, '/work');
  const xhr = requests[0];
  xhr.upload.onprogress({ lengthComputable: true, loaded: 120, total: 120 });
  assert.equal(app.transfers[0].active, true); assert.match(app.transferDetail(app.transfers[0]), /等待远端确认/);
  xhr.responseText = '{"loaded":40,"total":100}\n'; xhr.onprogress();
  xhr.upload.onprogress({ lengthComputable: true, loaded: 120, total: 120 });
  assert.equal(app.transfers[0].loaded, 40); assert.equal(app.transfers[0].label, '写入远端');
  xhr.status = 200; xhr.responseText += '{"ok":true}\n'; await xhr.onload(); await pending;
  assert.equal(app.transfers[0].label, '完成'); assert.equal(app.transfers[0].active, false);
});

test('cancelled upload cannot be revived by late progress or success', async () => {
  const { app, requests } = uploadFixture();
  const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work');
  const xhr = requests[0]; app.cancelTransfer(app.transfers[0].id); await pending;
  xhr.responseText = '{"loaded":100,"total":100}\n'; xhr.onprogress();
  xhr.status = 200; xhr.responseText += '{"ok":true}'; await xhr.onload();
  assert.equal(app.transfers[0].active, false); assert.equal(app.transfers[0].label, '已请求取消');
  assert.match(app.transfers[0].error, /核验/);
});

test('cancel while overwrite confirmation is pending never sends a second request', async () => {
  const { app, requests } = uploadFixture(), answer = deferred();
  app.askConfirm = () => answer.promise;
  const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work');
  const xhr = requests[0]; xhr.status = 409; xhr.responseText = '{"ok":false,"needsOverwrite":true}';
  const onload = xhr.onload(); app.cancelTransfer(app.transfers[0].id);
  answer.resolve(true); await onload; await pending;
  assert.equal(requests.length, 1); assert.equal(app.transfers[0].label, '已取消');
});

test('missing upload result stays uncertain with a persistent explanation', async () => {
  const { app, requests } = uploadFixture();
  const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work');
  const xhr = requests[0]; xhr.status = 200; xhr.responseText = '{"loaded":100,"total":100}\n';
  await xhr.onload(); await pending;
  assert.equal(app.transfers[0].label, '结果待确认'); assert.match(app.transfers[0].error, /不要直接重试/);
});

test('single command double click sends once and never retries a lost reply', async () => {
  const { app } = fixture(), reply = deferred(); let calls = 0;
  app.postJSON = () => { calls++; return reply.promise; };
  app.exec.command = 'echo once';
  const pending = app.runExec(); await app.runExec(); assert.equal(calls, 1);
  reply.reject(new Error('lost reply')); await pending;
  assert.equal(calls, 1); assert.equal(app.execBusy, false); assert.match(app.errors.operate, /不要直接重复执行/);
});

test('terminal resize debounces, focuses on explicit switch, and ignores hidden panes', () => {
  const { app, sandbox, timers } = fixture(); let fits = 0, focuses = 0;
  const pane = { classList: { contains: () => true }, clientWidth: 800, clientHeight: 400 };
  const entry = { id: 't', ready: true, pane, ws: { readyState: 1, send: () => assert.fail('fit must not duplicate onResize') },
    fit: { fit() { fits++; } }, term: { focus() { focuses++; } } };
  sandbox.entry = entry; vm.runInContext("termMap.set('t', entry)", sandbox);
  app.view = 'terminal'; app.termActive = 't';
  app.fitActive(); app.fitActive(true); app.fitActive();
  for (const timer of timers.splice(0)) if (timer) timer();
  assert.equal(fits, 1); assert.equal(focuses, 1);
  pane.clientWidth = 0; app.fitActive(); timers.at(-1)(); assert.equal(fits, 1);
});

test('incomplete command result does not clear the command or look successful', async () => {
  const { app } = fixture();
  app.postJSON = async () => ({ ok: true }); app.exec.command = 'echo once';
  await app.runExec();
  assert.equal(app.exec.command, 'echo once'); assert.equal(app.operateOut, '');
  assert.match(app.errors.operate, /未收到完整执行结果.*不要直接重复执行/);
});

function terminalFixture() {
  const ctx = fixture(), sockets = [], output = [];
  const { app, sandbox } = ctx;
  sandbox.location = { protocol: 'http:', host: 'localhost' };
  sandbox.WebSocket = class {
    constructor() { this.readyState = 1; this.bufferedAmount = 0; this.sent = []; sockets.push(this); }
    send(data) { this.sent.push(typeof data === 'string' ? data : Buffer.from(data)); }
    close() { this.readyState = 3; if (this.onclose) this.onclose({ code: 1000 }); }
  };
  const entry = { id: 't', alias: 'a', generation: 0, ready: false, input: [], inputBytes: 0, inputTimer: 0,
    pane: { classList: { toggle() {} }, remove() {} },
    term: { options: {}, cols: 80, rows: 24, write(data) { output.push(data); }, dispose() { this.disposed = true; } } };
  sandbox.entry = entry; vm.runInContext("termMap.set('t', entry)", sandbox);
  app.termTabs = [{ id: 't', alias: 'a', state: 'closed', ordinal: 1, error: '' }]; app.termActive = 't';
  app.postJSON = async () => ({ ticket: 'fixture' });
  app.syncWorkspace = app.fitActive = () => {};
  const control = (ws, state, category, message) => ws.onmessage({ data: JSON.stringify({ type: 'terminal', state, category, message }) });
  return { ...ctx, entry, sockets, output, control };
}

test('WebSocket upgrade and terminal output cannot mark an unready PTY online', async () => {
  const { app, entry, sockets, control } = terminalFixture();
  await app.connectTerm(entry); const ws = sockets[0]; ws.onopen();
  assert.equal(app.termTabs[0].state, 'connecting'); assert.equal(entry.term.options.disableStdin, true);
  ws.onmessage({ data: new TextEncoder().encode('pre-ready data').buffer });
  assert.equal(app.termTabs[0].state, 'connecting');
  control(ws, 'ready');
  assert.equal(app.termTabs[0].state, 'connected'); assert.equal(entry.term.options.disableStdin, false);
});

test('connection error keeps its category and cannot be cleared by another tab output', async () => {
  const { app, entry, sockets, control } = terminalFixture();
  await app.connectTerm(entry); const ws = sockets[0];
  control(ws, 'error', 'auth', 'authentication failed'); ws.close();
  assert.match(app.terminalError(), /认证失败/);
  const first = app.termTabs[0];
  app.termTabs.push({ id: 'other', alias: 'b', state: 'connected', error: '' });
  app.markTabIdle('other');
  assert.equal(app.termTabs[0].error, first.error);
  app.showPane('other'); assert.equal(app.terminalError(), '');
  app.showPane('t'); assert.match(app.terminalError(), /认证失败/);
});

test('reconnect preserves the terminal and discards old connection events and queued input', async () => {
  const { app, entry, sockets, output, control } = terminalFixture();
  await app.connectTerm(entry); const old = sockets[0], late = old.onmessage;
  control(old, 'ready'); output.push('old output');
  old.bufferedAmount = 200000; app.queueTerminalInput(entry, 'must not replay'); old.close();
  await app.reconnectTerminal();
  assert.equal(entry.term.disposed, undefined); assert.ok(output.includes('old output'));
  assert.ok(output.some(text => typeof text === 'string' && text.includes('新的 shell')));
  assert.equal(app.termTabs.length, 1); assert.equal(app.termTabs[0].id, 't');
  assert.equal(entry.inputBytes, 0); assert.equal(sockets[1].sent.length, 0);
  late({ data: JSON.stringify({ type: 'terminal', state: 'ready' }) });
  assert.equal(app.termTabs[0].state, 'connecting'); control(sockets[1], 'ready');
  assert.equal(app.termTabs[0].state, 'connected');
});

test('closing during ticket acquisition cannot create a hidden socket', async () => {
  const { app, entry, sockets } = terminalFixture(), ticket = deferred();
  app.postJSON = () => ticket.promise;
  const pending = app.connectTerm(entry); app.closeTab('t');
  ticket.resolve({ ticket: 'late' }); await pending;
  assert.equal(sockets.length, 0); assert.equal(app.termTabs.length, 0); assert.equal(entry.term.disposed, true);
});

test('large UTF-8 paste is chunked below the server limit and preserves following input', async () => {
  const { app, entry, sockets, control, timers } = terminalFixture();
  await app.connectTerm(entry); control(sockets[0], 'ready');
  const text = '中文🙂'.repeat(140000); // 1.4 MB, above the server's per-message limit.
  app.queueTerminalInput(entry, text); app.queueTerminalInput(entry, 'pwd\r');
  for (let i = 0; i < timers.length; i++) { assert.ok(i < 1000); if (timers[i]) timers[i](); }
  const chunks = sockets[0].sent;
  assert.ok(chunks.length > 1); assert.ok(chunks.every(chunk => chunk.length <= 32768));
  assert.equal(Buffer.concat(chunks).toString('utf8'), text + 'pwd\r'); assert.equal(entry.inputBytes, 0);
});

test('input queue is bounded and an oversized paste sends no partial command', async () => {
  const { app, entry, sockets, control } = terminalFixture();
  await app.connectTerm(entry); control(sockets[0], 'ready');
  app.queueTerminalInput(entry, 'x'.repeat((4 << 20) + 1));
  assert.equal(sockets[0].sent.length, 0); assert.equal(entry.inputBytes, 0);
  assert.match(app.toasts.at(-1).text, /本次输入未发送/);
  sockets[0].bufferedAmount = 200000; app.queueTerminalInput(entry, 'pending');
  assert.equal(sockets[0].sent.length, 0); assert.equal(entry.inputBytes, 7);
  app.closeTab('t'); assert.equal(entry.inputTimer, 0); assert.equal(entry.inputBytes, 0);
});

test('closing active tab selects its neighbor; same-host labels remain distinct', () => {
  const { app } = terminalFixture();
  app.termTabs = [{ id: 'left', alias: 'a', ordinal: 1 }, { id: 't', alias: 'a', ordinal: 2 }, { id: 'right', alias: 'b', ordinal: 1 }, { id: 'last', alias: 'c', ordinal: 1 }];
  assert.notEqual(app.terminalTabLabel(app.termTabs[0]), app.terminalTabLabel(app.termTabs[1]));
  app.closeTab('t'); assert.equal(app.termActive, 'right');
});

test('ready terminal fitting does not steal focus from a form', () => {
  const { app, sandbox, timers } = fixture(); let focuses = 0;
  const entry = { id: 't', ready: true, pane: { clientWidth: 800, clientHeight: 400, classList: { contains: () => true }, contains: () => false },
    fit: { fit() {} }, term: { focus() { focuses++; } } };
  sandbox.entry = entry; vm.runInContext("termMap.set('t', entry)", sandbox);
  sandbox.document.activeElement = { matches: () => true };
  app.view = 'terminal'; app.termActive = 't'; app.fitActive(true); timers.at(-1)();
  assert.equal(focuses, 0);
});

test('terminal size and collapsed file preference survive reload with bounds', () => {
  const { app, sandbox } = fixture(); let saved = '{"termFontSize":20,"filesCollapsed":true}';
  sandbox.localStorage = { getItem: () => saved, setItem: (_key, value) => { saved = value; } };
  sandbox.document.documentElement = { setAttribute() {} };
  app.applyStored(); assert.equal(app.termFontSize, 20); assert.equal(app.filesCollapsed, true);
  app.fitActive = () => {}; app.changeTermFont(20); app.toggleFiles();
  assert.equal(app.termFontSize, 22); assert.equal(JSON.parse(saved).filesCollapsed, false);
  saved = '{"termFontSize":500}'; const fresh = sandbox.sshui(); fresh.applyStored(); assert.equal(fresh.termFontSize, 14);
});

test('arrow navigation switches adjacent tabs without moving focus into the shell', () => {
  const { app, sandbox } = terminalFixture(); let focused = '', requested;
  app.termTabs.push({ id: 'other', alias: 'b', ordinal: 1 });
  sandbox.document.getElementById = id => ({ focus() { focused = id; } });
  app.fitActive = value => { requested = value; };
  app.terminalTabKey({ key: 'ArrowRight', target: { closest: () => ({}) }, preventDefault() {} });
  assert.equal(app.termActive, 'other'); assert.equal(focused, 'tab-other'); assert.equal(requested, false);
  app.terminalTabKey({ key: 'Home', target: { closest: () => ({}) }, preventDefault() {} });
  assert.equal(app.termActive, 't');
});

test('explicit copy uses selected text without sending shell input', async () => {
  const { app, entry, sandbox, sockets, control } = terminalFixture(); let copied;
  await app.connectTerm(entry); control(sockets[0], 'ready');
  entry.term.hasSelection = () => true; entry.term.getSelection = () => '中文输出';
  sandbox.navigator = { clipboard: { writeText: async text => { copied = text; } } };
  await app.copyTerminal(); assert.equal(copied, '中文输出'); assert.equal(sockets[0].sent.length, 0);
});

test('disconnect reports discarded input and reconnect never replays it', async () => {
  const { app, entry, sockets, control } = terminalFixture();
  await app.connectTerm(entry); control(sockets[0], 'ready');
  sockets[0].bufferedAmount = 200000; app.queueTerminalInput(entry, 'partial command'); sockets[0].close();
  assert.match(app.terminalError(), /部分内容可能已到达远端.*不会自动重发/);
  assert.equal(entry.inputBytes, 0); await app.reconnectTerminal(); assert.equal(sockets[1].sent.length, 0);
});

test('reconnect snapshots a full-screen application before returning to the normal buffer', async () => {
  const { app, entry, output } = terminalFixture();
  entry.term.rows = 2;
  entry.term.buffer = { active: { type: 'alternate', getLine: i => ({ translateToString: () => 'vim line ' + i }) } };
  await app.reconnectTerminal();
  const text = output.join(''); assert.match(text, /全屏画面.*\r\nvim line 0\r\nvim line 1/);
});
test('slow metrics complete before next refresh is scheduled', async () => {
  const { app, timers } = fixture(), response = deferred();
  app.view = 'terminal'; app.explicitAlias = app.termAlias = 'a';
  let calls = 0;
  app.postRead = async () => { calls++; return response.promise; };
  const pending = app.refreshMetrics();
  app.startMetrics(); await app.refreshMetrics();
  assert.equal(calls, 1); assert.equal(timers.length, 0);
  response.resolve({ alias: 'a', connected: true }); await pending;
  assert.equal(app.metrics.connected, true); assert.equal(timers.length, 1);
  app.stopMetrics();
});
test('host detail ignores an older response even when transport ignores abort', async () => {
  const { app } = fixture(), first = deferred(), second = deferred();
  app.api = (url) => url.includes('first') ? first.promise : second.promise;
  app.readJSON = async (data) => data;
  app.currentHost = 'first'; const p = app.loadHost();
  app.currentHost = 'second'; const q = app.loadHost();
  second.resolve({ host: { alias: 'second' } }); await q;
  first.resolve({ host: { alias: 'first' } }); await p;
  assert.equal(app.detail.host.alias, 'second');
});
test('batch click twice sends one request; a lost reply blocks re-execution', async () => {
  const { app } = fixture(), response = deferred();
  app.selectedAliases = () => ['a']; app.batchCommand = 'echo once';
  app.batchPreview = { canExecute: true, planDigest: 'plan' };
  app.batchPreviewKey = JSON.stringify(app.batchPayload());
  let calls = 0;
  app.api = () => { calls++; return response.promise; };
  const pending = app.submitBatch(); await app.submitBatch();
  assert.equal(calls, 1);
  response.reject(new Error('lost reply')); await pending;
  assert.equal(app.batchUncertain, true);
  await app.submitBatch(); assert.equal(calls, 1);
});
test('closed terminal is not a live workspace', () => {
  const { app } = fixture();
  app.termTabs = [{ id: 'one', alias: 'a', state: 'connected' }]; app.termActive = 'one';
  assert.equal(app.liveAlias(), 'a');
  app.setTabState('one', 'closed'); assert.equal(app.liveAlias(), '');
  assert.equal(app.terminalState(), '已断开');
});
test('host switch restores each host directory independently', () => {
  const { app } = fixture();
  app.view = 'terminal'; app.explicitAlias = app.termAlias = 'a';
  app.refreshFiles = app.startMetrics = () => {};
  app.files.alias = 'a'; app.files.path = '/work/a'; app.pathDraft = '/work/a';
  app.explicitAlias = app.termAlias = 'b'; app.syncWorkspace();
  app.files.path = '/work/b'; app.pathDraft = '/work/b';
  app.explicitAlias = app.termAlias = 'a'; app.syncWorkspace();
  assert.equal(app.files.path, '/work/a'); assert.equal(app.pathDraft, '/work/a');
});
test('file tree anchors at / and shows basenames', async () => {
  const { app } = fixture();
  app.termTabs = [{ id: 't', alias: 'a', state: 'connected' }];
  app.termActive = 't';
  const paths = [];
  app.postRead = async (_url, body) => {
    paths.push(body.path);
    if (body.path === '/') {
      return { path: '/', home: '/root', entries: [
        { name: 'bin', path: '/bin', dir: true },
        { name: 'mnt', path: '/mnt', dir: true },
        { name: 'root', path: '/root', dir: true }
      ] };
    }
    return { path: '/root', home: '/root', entries: [
      { name: '.ansible', path: '/root/.ansible', dir: true }
    ] };
  };
  app.tree['/root'] = { name: '/root', open: false, loaded: false, dirs: [] };
  await app.listFiles('/root');
  assert.equal(app.treeRoot, '/');
  assert.equal(app.tree['/root'].name, 'root');
  const rows = app.treeRows();
  assert.equal(rows.find((row) => row.path === '/root').name, 'root');
  assert.ok(rows.some((row) => row.path === '/bin' && row.name === 'bin'));
  assert.ok(rows.some((row) => row.path === '/mnt' && row.name === 'mnt'));
  assert.equal(rows.some((row) => row.name === '/root'), false);
  assert.ok(paths.includes('/'));
});
test('overview shows disk bytes, top 5 memory rows, and a short command', () => {
  const { app, sandbox } = fixture();
  const disk = { mount: '/', percent: '28%', used: '10485760', size: '41943040' };
  assert.equal(app.diskText(disk), '28% · 10.0 GB / 40.0 GB');
  app.procSort = { key: 'mem', dir: 'desc' };
  app.metrics.procs = [];
  for (let i = 0; i < 8; i++) {
    app.metrics.procs.push({ pid: String(i + 1), rss: (i + 1) * 1000, cpu: '1', comm: '/usr/lib/jvm/java -jar /data/web/ag.jar', args: 'java -jar /data/web/ag.jar extra' });
  }
  const rows = app.sortedProcs();
  assert.equal(rows.length, 5);
  assert.equal(rows[0].rss, 8000);
  assert.equal(rows[4].rss, 4000);
  assert.equal(app.procShort(rows[0]), 'java');
  assert.equal(app.procShort({ comm: 'nginx: master process /usr/sbin/nginx' }), 'nginx:');
  const detail = app.transferDetail({ loaded: 3 * 1024 * 1024, total: 10 * 1024 * 1024, active: true, label: '下载中' });
  assert.equal(detail, '30% · 3.0 MB / 10.0 MB · 下载中');
  assert.equal(sandbox.lastJSONObject('{"loaded":1,"total":2}\n{"ok":true,"local":"/tmp/a"}\n').local, '/tmp/a');
});
test('process table stays five rows when overview data is missing', () => {
  const { app } = fixture();
  app.metrics = { procs: [] };
  let rows = app.procRows();
  assert.equal(rows.length, 5);
  assert.equal(rows.every((row) => row.empty), true);
  app.metrics.procs = [{ pid: '9', rss: 1000, cpu: '1', comm: 'nginx' }];
  rows = app.procRows();
  assert.equal(rows.length, 5);
  assert.equal(rows.filter((row) => !row.empty).length, 1);
  assert.equal(rows[0].pid, '9');
  assert.equal(app.canOpenDownload({ active: true, kind: 'download', local: '/tmp/a' }), false);
  assert.equal(app.canOpenDownload({ active: false, kind: 'upload', local: '/tmp/a' }), false);
  assert.equal(app.canOpenDownload({ active: false, kind: 'download', local: '/tmp/a' }), true);
  app.metrics.disks = [];
  const meters = app.diskMeters();
  assert.equal(meters.length, 1);
  assert.equal(app.diskText(meters[0]), '—');
  assert.equal(app.memText(null), '—');
  assert.equal(app.pct(null), '—');
});
test('overview separates hostname and alias and copies the displayed address', async () => {
  const { app, sandbox } = fixture();
  app.catalog.hosts = [{ alias: 'hn-test-105', user: 'root', host: '10.4.85.105', port: 22 }];
  app.termAlias = 'hn-test-105';
  app.metrics = { alias: 'hn-test-105', connected: true, hostname: 'ecs-8025-0001', user: 'root', address: '10.4.85.105', port: 22 };
  assert.equal(app.overviewTitle(), 'ecs-8025-0001');
  assert.equal(app.panelAlias(), 'hn-test-105');
  assert.equal(app.overviewStatus(), '在线');
  assert.equal(app.overviewStatusClass(), 'is-online');
  assert.equal(app.overviewIP(), '10.4.85.105');
  assert.equal(app.overviewAddr(), 'root@10.4.85.105:22');
  app.metrics.connected = false;
  assert.equal(app.overviewStatus(), '未连接');
  app.metrics.hostname = '';
  assert.equal(app.overviewTitle(), '—');
  app.metrics.alias = 'other'; app.metrics.hostname = 'other-host'; app.metrics.address = '192.0.2.2';
  assert.equal(app.overviewTitle(), '—');
  assert.equal(app.overviewIP(), '10.4.85.105');
  app.termTabs = [{ id: 't1', alias: 'hn-test-105', state: 'closed' }];
  app.termActive = 't1';
  assert.equal(app.overviewStatus(), '已断开');
  assert.equal(app.overviewStatusClass(), 'is-closed');
  let copied;
  sandbox.navigator = { clipboard: { async writeText(value) { copied = value; } } };
  await app.copyOverviewIP();
  assert.equal(copied, '10.4.85.105');
});

test('terminal state overrides stale connected metrics', () => {
  const { app } = fixture();
  app.metrics = { alias: 'a', connected: true };
  app.termTabs = [{ id: 't', alias: 'a', state: 'connected' }]; app.termActive = 't';
  for (const [state, label, color] of [
    ['connecting', '连接中', 'is-connecting'], ['connected', '在线', 'is-online'],
    ['closed', '已断开', 'is-closed'], ['expired', '已到期', 'is-closed']
  ]) {
    app.setTabState('t', state);
    assert.equal(app.overviewStatus(), label); assert.equal(app.overviewStatusClass(), color);
  }
});

test('workspace uses a responsive third by default and retains a manual split', () => {
  const { app, sandbox } = fixture();
  assert.match(app.workspaceGrid(), /33\.333vh/);
  sandbox.innerHeight = 900;
  sandbox.document.querySelector = () => ({ getBoundingClientRect: () => ({ height: 300 }) });
  sandbox.document.body = { style: {} };
  const handlers = {};
  sandbox.addEventListener = (name, fn) => { handlers[name] = fn; };
  sandbox.removeEventListener = () => {};
  let prefs;
  app.savePrefs = (patch) => { prefs = patch; }; app.fitActive = () => {};
  app.beginSplit('lower', { clientX: 0, clientY: 600 });
  handlers.mousemove({ clientX: 0, clientY: 550 }); handlers.mouseup();
  assert.equal(app.ws.lower, 350); assert.equal(prefs.wsLower, 350);
  assert.match(app.workspaceGrid(), /350px/);
  app.ws.lower = 9999; assert.match(app.workspaceGrid(), /4096px/);
  sandbox.innerHeight = 2160;
  sandbox.document.querySelector = () => ({ getBoundingClientRect: () => ({ height: 720 }) });
  app.ws.lower = null;
  app.beginSplit('lower', { clientX: 0, clientY: 1440 });
  handlers.mousemove({ clientX: 0, clientY: 1439 }); handlers.mouseup();
  assert.equal(app.ws.lower, 721); assert.equal(prefs.wsLower, 721);
});

test('network graph uses sampled rates, keeps hosts separate and marks missing data', () => {
  const { app } = fixture();
  app.explicitAlias = app.termAlias = 'a'; app.metrics.alias = 'a';
  app.pushNet('a', { connected: true, netRx: 9999999, netTx: 9999999, netRxRate: 2048, netTxRate: 0 });
  assert.equal(app.netRateText('rx'), '2.0 KB/s');
  assert.equal(app.netRateText('tx'), '0 B/s');
  app.pushNet('b', { connected: true, netRxRate: 9000, netTxRate: 9000 });
  assert.equal(app.netRateText('rx'), '2.0 KB/s');
  app.errors.metrics = 'timeout'; assert.equal(app.netRateText('rx'), '—');
  app.errors.metrics = '';
  app.pushNet('a', { connected: true, netRxRate: 0, netTxRate: 0, notes: ['net: denied by policy'] });
  assert.equal(app.netRateText('rx'), '—');
  app.pushNet('a', { connected: false, netRxRate: 20, netTxRate: 20 });
  assert.equal(app.netRateText('tx'), '—');
  for (let i = 0; i < 30; i++) app.pushNet('a', { connected: true, netRxRate: i, netTxRate: i });
  assert.equal(app.netSeries.a.length, 24);
});

test('network canvas preserves gaps and genuine zero rates', () => {
  const { app, sandbox } = fixture();
  let chart;
  sandbox.document.getElementById = () => ({});
  sandbox.document.documentElement = { getAttribute: () => 'light' };
  sandbox.Chart = class {
    constructor(_canvas, config) { chart = this; this.data = config.data; }
    update() {}
  };
  app.pushNet('a', { connected: true, netRxRate: 0, netTxRate: 2048 });
  assert.equal(chart.data.datasets[0].data[0], 0);
  assert.equal(chart.data.datasets[1].data[0], 2048);
  app.pushNet('a', { connected: true, notes: ['net: unavailable'] });
  assert.equal(chart.data.datasets[0].data[1], null);
  assert.equal(chart.data.datasets[1].data[1], null);
});
test('clear button only applies when a transfer is finished', () => {
  const { app } = fixture();
  assert.equal(app.hasFinishedTransfers(), false);
  assert.equal(app.downloadDirLabel(), '默认 Downloads');
  app.transfers = [{ id: '1', active: true }];
  assert.equal(app.hasFinishedTransfers(), false);
  app.transfers = [{ id: '1', active: false, label: '完成' }, { id: '2', active: true }];
  assert.equal(app.hasFinishedTransfers(), true);
  app.clearFinishedTransfers();
  assert.equal(app.transfers.length, 1);
  assert.equal(app.transfers[0].id, '2');
  app.downloadDir = '/tmp/out';
  assert.equal(app.downloadDirLabel(), '/tmp/out');
  app.downloadDir = '';
  assert.equal(app.downloadDirLabel(), '默认 Downloads');
});
test('transfers do not keep a browser byte cap', () => {
  assert.equal(source.includes('128 MiB'), false);
  assert.equal(source.includes('63 MiB'), false);
  assert.equal(source.includes('new Blob(chunks)'), false);
  assert.equal(source.includes('local: this.downloadDir'), true);
});

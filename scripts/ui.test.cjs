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
  app.flushTransferProgress();
  assert.equal(app.transfers[0].active, true); assert.match(app.transferDetail(app.transfers[0]), /等待远端确认/);
  xhr.responseText = '{"loaded":40,"total":100}\n'; xhr.onprogress();
  xhr.upload.onprogress({ lengthComputable: true, loaded: 120, total: 120 });
  app.flushTransferProgress();
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

function jsonReply(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, headers: { get: () => '' }, text: async () => JSON.stringify(data) };
}

test('file prompt locks its host even when the user switches away and back', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work';
  const prompt = deferred(); let writes = 0;
  app.ask = () => prompt.promise; app.postJSON = async () => { writes++; };
  app.refreshFiles = () => {};
  const pending = app.createEntry('file');
  app.termAlias = app.explicitAlias = 'b'; app.syncWorkspace();
  app.termAlias = app.explicitAlias = 'a'; app.syncWorkspace();
  prompt.resolve('中文.txt'); await pending;
  assert.equal(writes, 0); assert.equal(app.fileAction.uncertain, false);
  assert.match(app.fileAction.message, /操作已取消/);
});

test('delete confirmation cannot follow a directory change', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work';
  app.menu.entry = { path: '/work/a', name: 'a' };
  const prompt = deferred(); let writes = 0;
  app.askConfirm = () => prompt.promise; app.postJSON = async () => { writes++; };
  const pending = app.deleteEntry(); app.files.path = '/other';
  prompt.resolve(true); await pending; assert.equal(writes, 0);
});

test('file prompt cannot survive reconnecting the same terminal tab', async () => {
  const { app, entry } = terminalFixture(); app.view = 'terminal'; app.files.path = '/work'; app.termTabs[0].state = 'connected';
  const prompt = deferred(); app.ask = () => prompt.promise;
  app.postJSON = () => assert.fail('reconnected workspace must cancel the old write');
  const pending = app.createEntry('file'); entry.generation++;
  prompt.resolve('new'); await pending; assert.equal(app.fileAction.uncertain, false);
});

test('file policy confirmation rechecks scope before the second HTTP request', async () => {
  const { app, sandbox } = fixture(); connected(app); app.files.path = '/work'; app.csrf = 'csrf';
  sandbox.sessionStorage = { getItem: () => '' }; let calls = 0;
  sandbox.fetch = async () => { calls++; return jsonReply({ needsConfirm: true, confirm: 'a' }, 409); };
  app.ask = async (label) => { if (label.includes('请输入')) app.files.path = '/other'; return 'new'; };
  await app.createEntry('file');
  assert.equal(calls, 1); assert.equal(app.fileAction.uncertain, false);
});

test('file authentication confirmation also rechecks scope before retry', async () => {
  const { app, sandbox } = fixture(); connected(app); app.files.path = '/work'; app.csrf = 'csrf';
  sandbox.sessionStorage = { getItem: () => '', setItem() {} }; let calls = 0;
  sandbox.fetch = async () => { calls++; return jsonReply({}, 401); };
  app.ask = async (label) => { if (label.includes('Bearer')) app.files.path = '/other'; return 'new'; };
  await app.createEntry('file'); assert.equal(calls, 1); assert.equal(app.fileAction.uncertain, false);
});

test('file action suppresses duplicate dialogs and preserves failed input for editing', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work';
  const prompt = deferred(); let prompts = 0, writes = 0;
  app.ask = () => { prompts++; return prompt.promise; };
  app.postJSON = async () => { writes++; const err = new Error('invalid name'); err.outcome = 'not_started'; throw err; };
  const pending = app.createEntry('file'); await app.createEntry('file');
  assert.equal(prompts, 1); prompt.resolve('bad/name'); await pending;
  assert.equal(writes, 1); assert.equal(app.fileAction.name, 'bad/name'); assert.equal(app.fileAction.uncertain, false);
  app.ask = async (_label, initial) => { assert.equal(initial, 'bad/name'); return null; };
  await app.editFileAction(app.fileAction); assert.equal(writes, 1);
});

test('lost file result blocks later writes until the user verifies it', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; let calls = 0;
  app.ask = async () => 'new'; app.postJSON = async () => { calls++; throw new Error('lost reply'); };
  await app.createEntry('file'); await app.createEntry('dir');
  assert.equal(calls, 1); assert.equal(app.fileAction.uncertain, true);
  app.askConfirm = async () => false; await app.clearFileAction(); assert.ok(app.fileAction);
  app.askConfirm = async () => true; await app.clearFileAction(); assert.equal(app.fileAction, null);
});

test('completed file change selects the returned path and refresh failure never invites replay', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work';
  app.ask = async () => '中文.txt'; app.postJSON = async () => ({ outcome: 'completed', path: '/work/中文.txt' });
  app.listFiles = async () => { app.files.entries = [{ path: '/work/中文.txt' }]; };
  await app.createEntry('file'); assert.equal(app.selectedPath, '/work/中文.txt'); assert.equal(app.fileAction.done, true);
  app.listFiles = async () => { throw new Error('read failed'); };
  await app.createEntry('file'); assert.equal(app.fileAction.done, true); assert.ok(!app.fileAction.uncertain);
  assert.match(app.errors.files, /操作已完成.*刷新失败/);
});

test('late file result stays associated with its original host and leaves the new directory alone', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; const reply = deferred(), started = deferred();
  app.ask = async () => 'new'; app.postJSON = () => { started.resolve(); return reply.promise; };
  app.listFiles = () => assert.fail('must not refresh the new host');
  const pending = app.createEntry('file'); await started.promise;
  app.termAlias = app.explicitAlias = 'b'; app.files.path = '/new-host'; app.workspaceSeq++;
  reply.resolve({ outcome: 'completed', path: '/work/new' }); await pending;
  assert.match(app.fileAction.message, /已完成：a/); assert.equal(app.files.path, '/new-host');
});

test('single command queries the original ID without replay and retains edits made meanwhile', async () => {
  const { app } = fixture(); let writes = 0, queried;
  app.exec.alias = 'a'; app.exec.command = 'echo once';
  app.postJSON = async () => { writes++; throw new Error('lost reply'); };
  await app.runExec(); const id = app.execOperationID; await app.runExec();
  assert.equal(writes, 1); assert.equal(app.execUncertain, true);
  app.exec.command = 'echo next'; app.exec.alias = 'b';
  app.api = async (url) => { queried = url; return jsonReply({ state: 'complete', result: { outcome: 'completed', exitCode: 7, stdout: 'once', auditWarning: 'failed' } }); };
  await app.checkExecResult();
  assert.equal(queried, '/api/operations/' + id); assert.equal(writes, 1); assert.equal(app.execUncertain, false);
  assert.equal(app.exec.command, 'echo next'); assert.match(app.operateOut, /a · echo once.*\nexit 7\nonce/);
  assert.match(app.auditWarning, /审计写入失败/);
});

test('unknown, running and expired single results never unlock execution', async () => {
  const { app } = fixture(); app.execUncertain = true; app.execOperationID = '0123456789abcdef';
  for (const [status, data] of [[200, { state: 'running' }], [404, { ok: false, error: 'expired' }],
    [200, { state: 'unknown', result: { outcome: 'completed', exitCode: 0 } }],
    [200, { state: 'complete', result: { outcome: 'unknown', error: 'transport failed' } }]]) {
    app.api = async () => jsonReply(data, status); await app.checkExecResult(); assert.equal(app.execUncertain, true);
  }
});

test('batch result with a transport-unknown row still requires verification', async () => {
  const { app } = fixture(); app.batchUncertain = true; app.batchOperationID = '0123456789abcdef';
  app.api = async () => jsonReply({ state: 'complete', result: { results: [{ alias: 'a', ok: false, outcome: 'unknown', error: 'lost connection' }] } });
  await app.checkBatchResult(); assert.equal(app.batchUncertain, true);
});

test('session failure before single execution is safe to edit without verification', async () => {
  const { app, sandbox } = fixture(); let writes = 0;
  app.ensureSession = async () => { throw new Error('session failed'); };
  sandbox.fetch = async () => { writes++; };
  await app.runExec(); assert.equal(writes, 0); assert.equal(app.execUncertain, false);
});

test('audit warning persists across successful reads and streaming upload completion', async () => {
  const { app } = fixture();
  await app.parseJSON(jsonReply({ results: [{ auditWarning: 'failed' }] }));
  await app.parseJSON(jsonReply({ ok: true })); assert.match(app.auditWarning, /审计写入失败/);
  const upload = uploadFixture(); const pending = upload.app.uploadOne('a', { name: 'a', size: 1 }, '/work');
  const xhr = upload.requests[0]; xhr.status = 200; xhr.responseText = '{"ok":true,"auditWarning":"failed"}\n';
  await xhr.onload(); await pending; assert.match(upload.app.auditWarning, /审计写入失败/);
  assert.equal(upload.app.transfers[0].label, '完成');
});

test('terminal audit warning does not disconnect a ready PTY', async () => {
  const { app, entry, sockets, control } = terminalFixture();
  await app.connectTerm(entry); control(sockets[0], 'ready'); control(sockets[0], 'audit_warning');
  assert.equal(entry.ready, true); assert.equal(app.termTabs[0].state, 'connected'); assert.match(app.auditWarning, /审计写入失败/);
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
});

test('multiple upload batches share one worker and pending files are visible immediately', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; app.ensureSession = async () => {};
  app.listFiles = async () => {}; const releases = [], order = []; let active = 0, peak = 0;
  app.uploadOne = async (_alias, file, _dest, id) => {
    active++; peak = Math.max(peak, active); order.push(file.name);
    await new Promise(resolve => releases.push(resolve)); active--;
    app.finishTransfer(id, { label: '完成' });
  };
  const first = app.enqueueUploads([{ name: 'one' }, { name: 'two' }], '/work');
  const second = app.enqueueUploads([{ name: 'three' }], '/work');
  assert.equal(app.transfers.length, 3); assert.equal(app.transfers.filter(t => t.queued).length, 2);
  for (let i = 0; i < 3; i++) {
    while (releases.length <= i) await new Promise(resolve => setImmediate(resolve));
    releases[i]();
  }
  await Promise.all([first, second]); assert.equal(peak, 1); assert.deepEqual(order, ['one', 'two', 'three']);
});

test('queued upload cancellation releases the file without opening a request', async () => {
  const { app, requests } = uploadFixture(); connected(app); app.files.path = '/work';
  app.ensureSession = async () => {}; app.listFiles = async () => {};
  const pending = app.enqueueUploads([{ name: 'one', size: 1 }, { name: 'two', size: 1 }], '/work');
  const queued = app.transfers.find(t => t.queued); app.cancelTransfer(queued.id);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 1); requests[0].status = 200; requests[0].responseText = '{"ok":true}';
  await requests[0].onload(); const results = await pending;
  assert.equal(requests.length, 1); assert.equal(results[1].active, false); assert.equal(results[1].label, '已取消');
});

test('cancel batch affects its running and pending items and lets the next batch continue', async () => {
  const { app, requests } = uploadFixture(); connected(app); app.files.path = '/work';
  app.ensureSession = async () => {}; app.listFiles = async () => {};
  const first = app.enqueueUploads([{ name: 'one', size: 1 }, { name: 'two', size: 1 }], '/work');
  const second = app.enqueueUploads([{ name: 'next', size: 1 }], '/work');
  await new Promise(resolve => setImmediate(resolve));
  app.cancelBatch(app.transfers[0].batch);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 2); assert.equal(app.transfers[1].label, '已取消');
  requests[1].status = 200; requests[1].responseText = '{"ok":true}'; await requests[1].onload();
  await Promise.all([first, second]); assert.equal(app.transfers[2].label, '完成');
  assert.equal(app.transferNeedsVerification(app.transfers[0]), true);
});

test('cancel during session preparation cannot start a late transfer', async () => {
  const { app, requests } = uploadFixture(); connected(app); app.files.path = '/work'; const session = deferred();
  app.ensureSession = () => session.promise; app.listFiles = async () => {};
  const pending = app.enqueueUploads([{ name: 'one', size: 1 }], '/work'); app.cancelTransfer(app.transfers[0].id);
  session.resolve(); await pending; assert.equal(requests.length, 0); assert.equal(app.transfers[0].label, '已取消');
});

test('cancelling an already-finished XHR awaiting confirmation releases the global worker', async () => {
  const { app, requests } = uploadFixture(); connected(app); app.files.path = '/work';
  app.ensureSession = async () => {}; app.listFiles = async () => {}; const answer = deferred(); app.askConfirm = () => answer.promise;
  const pending = app.enqueueUploads([{ name: 'one', size: 1 }, { name: 'two', size: 1 }], '/work');
  await new Promise(resolve => setImmediate(resolve));
  const xhr = requests[0]; xhr.status = 409; xhr.responseText = '{"ok":false,"needsOverwrite":true,"path":"/work/one"}';
  const prompt = xhr.onload(); xhr.abort = () => {}; // Native DONE XHR.abort emits no abort event.
  app.cancelTransfer(app.transfers[0].id); await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 2); answer.resolve(true); await prompt;
  assert.equal(requests.length, 2); requests[1].status = 200; requests[1].responseText = '{"ok":true}'; await requests[1].onload(); await pending;
});

test('upload form submits once and keeps user edits made while queued', async () => {
  const { app, sandbox } = fixture(), result = deferred();
  const file = { name: 'one', size: 1 }, fields = { alias: 'a', remote: '/old', confirm: '', file };
  sandbox.FormData = class { constructor() { this.fields = { ...fields }; } get(key) { return this.fields[key]; } };
  let requests = 0, reset = 0;
  app.enqueueUploads = () => { requests++; return result.promise; };
  const ev = { target: { reset() { reset++; } } }; const pending = app.upload(ev); await app.upload(ev);
  fields.remote = '/new'; result.resolve([{ label: '完成' }]); await pending;
  assert.equal(requests, 1); assert.equal(reset, 0); assert.equal(app.uploadBusy, false);
});

test('downloads wait behind uploads and preserve their selected destination', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; app.ensureSession = async () => {};
  app.listFiles = async () => {}; const release = deferred(); let target;
  app.uploadOne = async (_a, _f, _p, id) => { await release.promise; app.finishTransfer(id, { label: '完成' }); };
  app.downloadOne = async (entry, alias, id, local) => { target = { entry, alias, local }; app.finishTransfer(id, { label: '完成' }); };
  const upload = app.enqueueUploads([{ name: 'one' }], '/work'); app.downloadDir = '/original';
  const entry = { path: '/source/one', name: 'one' }; const download = app.wsDownload(entry);
  app.downloadDir = '/changed'; entry.path = '/changed'; app.explicitAlias = app.termAlias = 'b';
  assert.equal(target, undefined); release.resolve(); await Promise.all([upload, download]);
  assert.equal(target.local, '/original'); assert.equal(target.alias, 'a'); assert.equal(target.entry.path, '/source/one');
});

test('clearing history and automatic pruning never discard unresolved transfers', async () => {
  const { app } = fixture();
  app.patchTransfer('unknown', { active: false, label: '结果待确认', needsVerification: true });
  for (let i = 0; i < 160; i++) app.finishTransfer('done' + i, { label: '完成' });
  assert.equal(app.transfers.length, 101); assert.equal(app.transfers[0].id, 'unknown');
  app.clearFinishedTransfers(); assert.equal(app.transfers.length, 1); assert.equal(app.hasFinishedTransfers(), false);
  app.askConfirm = async () => false; await app.verifyTransfer('unknown'); assert.equal(app.transfers.length, 1);
  app.askConfirm = async () => true; await app.verifyTransfer('unknown'); app.clearFinishedTransfers(); assert.equal(app.transfers.length, 0);
});

test('queue admission is bounded and never evicts unknown results to make room', () => {
  const { app } = fixture(); app.toast = () => {};
  app.transfers = Array.from({ length: 256 }, (_, i) => ({ id: String(i), needsVerification: true }));
  assert.equal(app.canQueueTransfers(1), false); assert.equal(app.transfers.length, 256);
});

test('progress bursts coalesce and late progress cannot revive a completed row', async () => {
  const { app, requests, timers } = uploadFixture();
  const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work'); const xhr = requests[0];
  for (let i = 1; i <= 100; i++) xhr.upload.onprogress({ lengthComputable: true, loaded: i, total: 100 });
  assert.equal(timers.filter(Boolean).length, 1); assert.equal(app.transfers[0].loaded, 0);
  app.flushTransferProgress(); assert.equal(app.transfers[0].loaded, 100); assert.equal(app.transfers[0].active, true);
  xhr.status = 200; xhr.responseText = '{"ok":true}'; await xhr.onload(); await pending;
  xhr.upload.onprogress({ lengthComputable: true, loaded: 1, total: 100 }); app.flushTransferProgress();
  assert.equal(app.transfers[0].label, '完成'); assert.equal(app.transfers[0].active, false);
});

test('partial remote write reported as an error is retained for verification', async () => {
  const { app, requests } = uploadFixture(); const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work');
  requests[0].status = 400; requests[0].responseText = '{"ok":false,"outcome":"unknown","error":"write failed"}';
  await requests[0].onload(); await pending; app.clearFinishedTransfers();
  assert.equal(app.transfers.length, 1); assert.equal(app.transferNeedsVerification(app.transfers[0]), true);
});

test('cancel just after an overwrite retry requires verification even before progress arrives', async () => {
  const { app, requests } = uploadFixture(); app.askConfirm = async () => true;
  const pending = app.uploadOne('a', { name: 'a', size: 100 }, '/work');
  requests[0].status = 409; requests[0].responseText = '{"ok":false,"needsOverwrite":true,"path":"/work/a"}';
  await requests[0].onload(); assert.equal(requests.length, 2);
  app.cancelTransfer(app.transfers[0].id); await pending;
  assert.equal(app.transferNeedsVerification(app.transfers[0]), true);
});

test('upload authentication retries only after a known 401 and cancellation stops a late retry', async () => {
  const { app, requests, sandbox } = uploadFixture(); let token;
  sandbox.sessionStorage.setItem = (key, value) => { if (key === 'sshCliBearer') token = value; }; app.ask = async () => 'new-token';
  const pending = app.uploadOne('a', { name: 'a', size: 1 }, '/work');
  requests[0].status = 401; requests[0].responseText = 'unauthorized'; await requests[0].onload();
  assert.equal(requests.length, 2); assert.equal(token, 'new-token');
  app.cancelTransfer(app.transfers[0].id); await pending; assert.equal(app.transferNeedsVerification(app.transfers[0]), true);
  const second = uploadFixture(), answer = deferred(); second.app.ask = () => answer.promise;
  second.sandbox.sessionStorage.setItem = () => {};
  const stopped = second.app.uploadOne('a', { name: 'a', size: 1 }, '/work'); second.requests[0].status = 401;
  const prompt = second.requests[0].onload(); second.app.cancelTransfer(second.app.transfers[0].id);
  answer.resolve('token'); await prompt; await stopped; assert.equal(second.requests.length, 1);
  assert.equal(second.app.transferNeedsVerification(second.app.transfers[0]), false);
});

test('expired session refreshes credentials only for an explicitly rejected request', async () => {
  const { app, sandbox } = fixture(); app.csrf = 'old';
  sandbox.sessionStorage = { getItem: () => '' }; const calls = [];
  sandbox.fetch = async (url, opts) => {
    calls.push([url, opts && opts.headers && opts.headers['X-CSRF-Token']]);
    if (url === '/api/session') return jsonReply({ ok: true, csrf: 'new' });
    if (calls.length === 1) { const reply = jsonReply({}, 403); reply.headers.get = key => key === 'X-SSH-CLI-Session-Expired' ? '1' : ''; return reply; }
    return jsonReply({ ok: true });
  };
  await app.api('/write', { method: 'POST', body: '{}' });
  assert.deepEqual(calls.map(row => row[0]), ['/write', '/api/session', '/write']);
  assert.equal(calls[2][1], 'new');
  let denied = 0; sandbox.fetch = async () => { denied++; return jsonReply({}, 403); };
  await app.api('/write', { method: 'POST', body: '{}' }); assert.equal(denied, 1);
});

test('reload restores verification metadata without file bytes, secrets, commands or replay', () => {
  const { app, sandbox } = fixture(); const storage = new Map();
  sandbox.sessionStorage = { setItem: (key, value) => storage.set(key, value), getItem: key => storage.get(key) };
  app.execOperationID = 'operation_123456789'; app.execUncertain = true; app.exec.command = 'secret-command';
  app.transfers = [{ id: 'up1', alias: 'a', name: 'file', remote: '/work', kind: 'upload', started: true, active: true, file: 'PRIVATE_BYTES' }];
  app.persistPending(); const saved = storage.get('sshCliPending');
  assert.ok(!saved.includes('PRIVATE_BYTES')); assert.ok(!saved.includes('secret-command'));
  app.transfers = []; app.execUncertain = false; app.restorePending();
  assert.equal(app.transfers.length, 1); assert.equal(app.transfers[0].active, false); assert.equal(app.transfers[0].needsVerification, true);
  assert.equal(app.execUncertain, true); assert.equal(app.execOperationID, 'operation_123456789');
  app.transfers[0].needsVerification = false; app.transfers[0].label = '已核验'; app.execUncertain = false;
  app.persistPending(); assert.equal(JSON.parse(storage.get('sshCliPending')).transfers.length, 0);
});

test('terminal search is scoped to the active tab and never sends shell input', () => {
  const { app, sandbox } = fixture(); const calls = [];
  vm.runInContext('termMap.set("a", { search: { findNext: (s) => { window.searchCalls.push(s); return false; }, findPrevious: () => true, clearDecorations() {} }, term: { focus() {} } });', Object.assign(sandbox, { searchCalls: calls }));
  app.termActive = 'a'; app.termSearch.text = 'needle'; app.searchTerminal(false);
  assert.deepEqual(calls, ['needle']); assert.equal(app.termSearch.found, false);
  app.termActive = 'missing'; app.searchTerminal(false); assert.equal(calls.length, 1);
});

test('cancelled HTTP authentication is not mistaken for an accepted command or download', async () => {
  const { app, sandbox } = fixture(); app.csrf = 'csrf';
  sandbox.sessionStorage = { getItem: () => '' }; sandbox.fetch = async () => jsonReply({}, 401);
  app.ask = async () => null;
  await app.wsDownload({ path: '/source/a', name: 'a' }, 'a');
  assert.equal(app.transferNeedsVerification(app.transfers[0]), false); assert.equal(app.transfers[0].label, '失败');
  app.exec.alias = 'a'; app.exec.command = 'echo once'; await app.runExec();
  assert.equal(app.execUncertain, false); assert.equal(app.exec.command, 'echo once');
});

test('terminal acknowledges binary byte counts only after consumption and never on a replacement socket', async () => {
  const { app, entry, sockets, control } = terminalFixture(); const callbacks = [];
  entry.term.write = (_data, callback) => { if (callback) callbacks.push(callback); };
  await app.connectTerm(entry); control(sockets[0], 'ready', 'output_ack');
  sockets[0].onmessage({ data: new TextEncoder().encode('中文').buffer }); assert.equal(sockets[0].sent.length, 0);
  callbacks.shift()(); assert.deepEqual(JSON.parse(sockets[0].sent[0]), { type: 'output_ack', bytes: 6 });
  sockets[0].onmessage({ data: new Uint8Array(100).buffer }); sockets[0].close(); await app.reconnectTerminal();
  callbacks.shift()(); assert.equal(sockets[1].sent.length, 0); assert.equal(sockets[0].sent.length, 1);
});

test('wide directory listings do not create thousands of placeholder nodes', () => {
  const { app } = fixture(); app.files.path = '/work';
  app.noteTree('/work', Array.from({ length: 2000 }, (_, i) => ({ dir: true, name: 'd' + i, path: '/work/d' + i })));
  assert.ok(Object.keys(app.tree).length < 5); assert.equal(app.treeRows().length, 2002);
});

test('collapsing a loading directory prevents duplicate requests and late reopening', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; app.noteTree('/work', [{ path: '/work/child', dir: true, name: 'child' }]);
  const reply = deferred(); let requests = 0; app.postRead = () => { requests++; return reply.promise; };
  const row = { path: '/work/child', name: 'child' }; const pending = app.toggleTree(row);
  await app.toggleTree(row); await app.toggleTree(row); await app.toggleTree(row);
  reply.resolve({ path: row.path, entries: [{ path: '/work/child/deep', dir: true }] }); await pending;
  assert.equal(requests, 1); assert.equal(app.tree[row.path].open, false); assert.equal(app.tree[row.path].pending, false);
  assert.ok(!app.treeRows().some(item => item.path === '/work/child/deep'));
});

test('a directory read finishing after a host switch clears the original cache busy state', async () => {
  const { app } = fixture(); connected(app); app.files.path = '/work'; app.noteTree('/work', []);
  const reply = deferred(); app.postRead = () => reply.promise;
  const pending = app.toggleTree({ path: '/work/child', name: 'child' }); const original = app.tree['/work/child'];
  app.rememberWorkspace(); app.tree = {}; app.workspaceSeq++; app.termAlias = app.explicitAlias = 'b';
  reply.resolve({ path: '/work/child', entries: [] }); await pending;
  assert.equal(original.pending, false); assert.equal(app.tree['/work/child'], undefined);
});

test('directory cache evicts old branches while retaining the current path and visible reloadable rows', () => {
  const { app } = fixture(); app.files.path = '/current/deep'; app.noteTree('/current/deep', []);
  for (let i = 0; i < 50; i++) app.noteTree('/old' + i, []);
  assert.ok(Object.keys(app.tree).length <= 32); assert.ok(app.tree['/current']); assert.ok(app.tree['/current/deep']);
  assert.equal(app.tree['/old0'], undefined); assert.ok(app.treeRows().some(row => row.path === '/old0' && !row.open));
});

test('workspace cache respects aggregate entry budget and retains the most recently used host', () => {
  const { app } = fixture();
  for (let i = 0; i < 12; i++) {
    app.files = { alias: 'h' + i, entries: Array.from({ length: 2000 }, () => ({})) };
    app.tree = {}; app.rememberWorkspace();
  }
  assert.ok(Object.keys(app.workspaceCache).length <= 8); assert.ok(app.workspaceCache.h11);
  assert.equal(app.workspaceCache.h0, undefined);
});

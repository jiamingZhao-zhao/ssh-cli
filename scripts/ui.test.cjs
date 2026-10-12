// Browser-independent regressions; Node is only needed by contributors/CI.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const source = readFileSync(join(__dirname, '../internal/ui/web/app.js'), 'utf8');
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const timers = [];
  const sandbox = { AbortController, crypto: require('node:crypto').webcrypto,
    document: { hidden: false, addEventListener() {}, getElementById() { return null; } },
    setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout() {} };
  sandbox.window = sandbox;
  vm.createContext(sandbox); vm.runInContext(source, sandbox);
  const app = sandbox.sshui();
  app.loadAudit = app.loadDashboard = app.loadSessions = () => {};
  return { app, timers, sandbox };
}
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
test('transfers do not keep a browser byte cap', () => {
  assert.equal(source.includes('128 MiB'), false);
  assert.equal(source.includes('63 MiB'), false);
  assert.equal(source.includes('new Blob(chunks)'), false);
  assert.equal(source.includes('local: this.downloadDir'), true);
});

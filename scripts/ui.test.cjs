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
test('overview shows disk bytes, top 7 memory rows, and a short command', () => {
  const { app, sandbox } = fixture();
  const disk = { mount: '/', percent: '28%', used: '10485760', size: '41943040' };
  assert.equal(app.diskText(disk), '28% · 10.0 GB / 40.0 GB');
  app.procSort = { key: 'mem', dir: 'desc' };
  app.metrics.procs = [];
  for (let i = 0; i < 8; i++) {
    app.metrics.procs.push({ pid: String(i + 1), rss: (i + 1) * 1000, cpu: '1', comm: '/usr/lib/jvm/java -jar /data/web/ag.jar', args: 'java -jar /data/web/ag.jar extra' });
  }
  const rows = app.sortedProcs();
  assert.equal(rows.length, 7);
  assert.equal(rows[0].rss, 8000);
  assert.equal(rows[6].rss, 2000);
  assert.equal(app.procShort(rows[0]), 'java');
  assert.equal(app.procShort({ comm: 'nginx: master process /usr/sbin/nginx' }), 'nginx:');
  const detail = app.transferDetail({ loaded: 3 * 1024 * 1024, total: 10 * 1024 * 1024, active: true, label: '下载中' });
  assert.equal(detail, '30% · 3.0 MB / 10.0 MB');
  assert.equal(sandbox.lastJSONObject('{"loaded":1,"total":2}\n{"ok":true,"local":"/tmp/a"}\n').local, '/tmp/a');
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

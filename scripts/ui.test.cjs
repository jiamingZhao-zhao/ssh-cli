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
  assert.equal(detail, '30% · 3.0 MB / 10.0 MB');
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
  app.ws.lower = 9999; assert.match(app.workspaceGrid(), /520px/);
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

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

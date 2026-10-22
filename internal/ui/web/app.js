const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZES = [10, 20, 50];
const termMap = new Map();
const TERM_CHUNK = 32 << 10;
const TERM_INPUT_LIMIT = 4 << 20;
const inputEncoder = new TextEncoder();
const SEARCH_LIMIT = 200;
function entryReady(id) { const entry = termMap.get(id); return entry && entry.wasReady; }
function blankSearch() { return { open: false, text: "", found: true, index: -1, count: 0 }; }
const transferCtl = new Map();
const transferJobs = new Map();
const transferQueue = [];
const transferProgress = new Map();
const TRANSFER_HISTORY = 100;
const TRANSFER_LIMIT = 256;
let transferPaintTimer = 0;
const auditHeader = "X-SSH-CLI-Audit-Warning";
let chartDays = null;
let chartOps = null;
let netChart = null;
let rangePicker = null;
let suppressRange = false;
const promptQueue = [];
let promptResolve = null;
let dialogReturnFocus = null;
let hostPickerResize = null;

function operationID() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, "0")).join("");
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function plainBodyMessage(text, statusText) {
  const raw = String(text || "").replace(/\s+/g, " ").trim();
  if (raw.toLowerCase().indexOf("csrf") >= 0) return "请求被拒绝：缺少 CSRF，请刷新页面";
  if (raw) return raw.slice(0, 180);
  return statusText || "请求失败";
}

function friendlyError(message, statusText) {
  return plainBodyMessage(message, statusText);
}

function checkRead(signal) {
  if (!signal || !signal.aborted) return;
  const err = new Error("已取消");
  err.name = "AbortError";
  throw err;
}

// pickHMAC chooses one HMAC object. An empty ops.hmac must not hide the
// dashboard status: the home page loads dash.hmac before the ops page.
function pickHMAC(opsHmac, dashHmac) {
  if (opsHmac && opsHmac.status) return opsHmac;
  if (dashHmac && dashHmac.status) return dashHmac;
  return { status: "unsigned" };
}

function hmacView(opsHmac, dashHmac) {
  const hmac = pickHMAC(opsHmac, dashHmac);
  const status = hmac.status || "unsigned";
  const map = {
    ok: "HMAC 有效。policy.mac 和当前策略一致。",
    unsigned: "还没有签名。需要时在命令行运行 ssh-cli policy sign。",
    "needs-resign": "policy.mac 是旧版，不含连接信息。运行 ssh-cli policy sign 重签。",
    missing: "配置标记为已签名，但 policy.mac 不在。恢复文件，或运行 ssh-cli policy unsign。",
    mismatch: "HMAC 不一致，配置会被拒绝加载。先核对 policy.mac，不要继续放宽策略。",
    error: "读不到 HMAC 状态。"
  };
  let className = "alert alert-danger";
  if (status === "ok") className = "alert alert-success";
  else if (status === "unsigned") className = "alert alert-info";
  else if (status === "needs-resign") className = "alert alert-warning";
  return {
    status: status,
    text: (map[status] || status) + (hmac.error ? " " + hmac.error : ""),
    className: className
  };
}

// batchRowFailed treats a handled request with a non-zero exit or a non-ok
// status as a failure. row.ok only means the API accepted the row.
function batchRowFailed(row) {
  if (!row || row.ok === false) return true;
  const status = row.status ? String(row.status) : "";
  if (status && status !== "ok") return true;
  if (row.exitCode !== undefined && row.exitCode !== null && row.exitCode !== "" && Number(row.exitCode) !== 0) return true;
  return false;
}

function lastJSONObject(text) {
  const parts = String(text || "").split("\n");
  for (let i = parts.length - 1; i >= 0; i--) {
    const line = parts[i].trim();
    if (!line) continue;
    return JSON.parse(line);
  }
  return {};
}

async function readNDJSON(res, onProgress) {
  if (!res.body || !res.body.getReader) {
    const data = lastJSONObject(await res.text());
    if (typeof data.ok !== "boolean") throw new Error("传输结果未确认，请核验目标文件，不要直接重试。");
    return data;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  let finalMsg = null;
  const take = (line) => {
    const trimmed = String(line || "").trim();
    if (!trimmed) return;
    const msg = JSON.parse(trimmed);
    if (msg && msg.ok == null && msg.loaded != null) {
      if (onProgress) onProgress(msg);
      return;
    }
    finalMsg = msg;
  };
  while (true) {
    const step = await reader.read();
    if (step.done) break;
    buf += dec.decode(step.value, { stream: true });
    let nl = buf.indexOf("\n");
    while (nl >= 0) {
      take(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      nl = buf.indexOf("\n");
    }
  }
  buf += dec.decode();
  if (buf.trim()) take(buf);
  if (!finalMsg || typeof finalMsg.ok !== "boolean") throw new Error("传输结果未确认，请核验目标文件，不要直接重试。");
  return finalMsg;
}

function batchSummary(results) {
  const rows = results || [];
  let failed = 0;
  const lines = rows.map((row) => {
    const bad = batchRowFailed(row);
    if (bad) failed++;
    const exit = (row.exitCode === undefined || row.exitCode === null || row.exitCode === "") ? "" : " exit " + row.exitCode;
    const head = (row.alias || "") + " " + (bad ? "失败" : "ok") + exit;
    if (row.stdoutSuppressed) return head + "\n" + (row.notice || "输出已丢弃");
    return head + (row.error ? "\n" + row.error : "") + (row.stdout ? "\n" + row.stdout : "") + (row.stderr ? "\n" + row.stderr : "") + (row.truncated ? "\n[输出已截断]" : "");
  });
  if (!rows.length) return { failed: 0, total: 0, text: "没有结果" };
  const summary = failed ? ("失败 " + failed + " / " + rows.length) : ("成功 " + rows.length);
  return { failed: failed, total: rows.length, text: summary + "\n\n" + lines.join("\n\n") };
}

function blankMetrics() {
  return { alias: "", connected: false, address: "", port: "", user: "", hostname: "", uptime: "", load: "", cpuPercent: null, mem: null, swap: null, procs: [], disks: [], notes: [], netRx: 0, netTx: 0, netRxRate: 0, netTxRate: 0 };
}

function cleanPosix(p) {
  const abs = String(p || "").charAt(0) === "/";
  const parts = String(p || "").split("/");
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    const s = parts[i];
    if (s === "" || s === ".") continue;
    if (s === "..") {
      if (out.length) out.pop();
      continue;
    }
    out.push(s);
  }
  if (!out.length) return abs ? "/" : ".";
  return (abs ? "/" : "") + out.join("/");
}

// Breadcrumbs used to paint a slash before every segment, and the root segment
// was already "/", so /root showed up as ///root. Typed paths are cleaned here.
function normalizeRemotePath(base, raw) {
  let p = String(raw || "").trim();
  if (!p) return { error: "请输入要打开的路径。" };
  if (p.indexOf("\0") >= 0 || /[\r\n]/.test(p)) return { error: "路径无效。" };
  p = p.replace(/\\/g, "/");
  if (p.indexOf("//") === 0 && p.indexOf("///") !== 0) p = p.slice(1);
  const root = cleanPosix(base || "");
  const rooted = root.charAt(0) === "/";
  if (p === "~") {
    if (!rooted) return { error: "请输入绝对路径，例如 /root。" };
    return { path: root };
  }
  if (p.indexOf("~/") === 0) {
    if (!rooted) return { error: "请输入绝对路径，例如 /root。" };
    p = root.replace(/\/$/, "") + "/" + p.slice(2);
  } else if (p.charAt(0) !== "/") {
    if (!rooted) return { error: "请输入绝对路径，例如 /root。" };
    p = root.replace(/\/$/, "") + "/" + p;
  }
  const cleaned = cleanPosix(p);
  if (!cleaned || cleaned.charAt(0) !== "/") return { error: "路径无效。" };
  return { path: cleaned };
}

function chineseUptime(raw) {
  const s = String(raw || "").trim();
  if (!s) return "—";
  if (s.indexOf("已运行") >= 0) return s;
  let body = s;
  const up = s.indexOf(" up ");
  if (up >= 0) body = s.slice(up + 4);
  else if (s.indexOf("up ") === 0) body = s.slice(3);
  const loadAt = body.toLowerCase().indexOf("load average");
  if (loadAt >= 0) body = body.slice(0, loadAt);
  let days = 0;
  let hours = 0;
  let mins = 0;
  const dayM = body.match(/(\d+)\s+days?/);
  if (dayM) days = parseInt(dayM[1], 10) || 0;
  const hourM = body.match(/(\d+)\s+hours?/);
  if (hourM) hours = parseInt(hourM[1], 10) || 0;
  const minM = body.match(/(\d+)\s+mins?/);
  if (minM) mins = parseInt(minM[1], 10) || 0;
  if (!hours && !mins) {
    const clock = body.match(/(\d+):(\d{2})/);
    if (clock) {
      hours = parseInt(clock[1], 10) || 0;
      mins = parseInt(clock[2], 10) || 0;
    }
  }
  if (!days && !hours && !mins && s.toLowerCase().indexOf("up") < 0) return "已运行";
  let text = "已运行";
  if (days) text += " " + days + " 天";
  if (hours) text += " " + hours + " 小时";
  if (mins || (!days && !hours)) text += " " + mins + " 分";
  return text;
}

function formatKB(kb) {
  const units = ["KB", "MB", "GB", "TB"];
  let n = Number(kb) || 0;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  const shown = (i === 0 || n >= 100) ? String(Math.round(n)) : n.toFixed(1);
  return shown + " " + units[i];
}

function stamp(value) {
  if (!value) return "";
  const d = new Date(value);
  if (isNaN(d.getTime())) return String(value);
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
}

function ymd(value) {
  if (!value) return "";
  if (typeof value.format === "function") return value.format("YYYY-MM-DD");
  const d = value.dateInstance || value;
  if (!(d instanceof Date) || isNaN(d.getTime())) return "";
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate());
}

function destroyCharts() {
  if (chartDays) {
    chartDays.destroy();
    chartDays = null;
  }
  if (chartOps) {
    chartOps.destroy();
    chartOps = null;
  }
}

function destroyNetChart() {
  if (netChart) {
    netChart.destroy();
    netChart = null;
  }
}

function paintNetChart(series) {
  if (typeof Chart === "undefined") return;
  const el = document.getElementById("ws-net-chart");
  if (!el) return;
  const theme = chartTheme();
  const rows = series || [];
  const labels = [];
  const rx = [];
  const tx = [];
  for (let i = 0; i < rows.length; i++) {
    const d = new Date(rows[i].t || Date.now());
    labels.push(pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds()));
    rx.push(rows[i].rxRate == null ? null : Math.round(rows[i].rxRate));
    tx.push(rows[i].txRate == null ? null : Math.round(rows[i].txRate));
  }
  if (netChart) {
    netChart.data.labels = labels;
    netChart.data.datasets[0].data = rx;
    netChart.data.datasets[1].data = tx;
    netChart.update();
    return;
  }
  netChart = new Chart(el, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        { label: "下载", data: rx, backgroundColor: "rgba(54,179,126,0.65)", maxBarThickness: 5 },
        { label: "上传", data: tx, backgroundColor: "rgba(255,139,78,0.65)", maxBarThickness: 5 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        label: (ctx) => ctx.dataset.label + " " + (ctx.parsed.y / 1024).toFixed(1) + " KB/s"
      } } },
      scales: {
        x: { display: false },
        y: { beginAtZero: true, ticks: { color: theme.ink, maxTicksLimit: 3, font: { size: 10 },
          callback: (value) => value >= 1024 ? (value / 1024).toFixed(0) + "K" : value + "B"
        }, grid: { color: theme.grid } }
      }
    }
  });
}

function chartTheme() {
  const dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
  return {
    ink: dark ? "#f4f5f7" : "#1d2129",
    grid: dark ? "rgba(244,245,247,0.14)" : "rgba(29,33,41,0.08)"
  };
}

function restyleCharts() {
  const theme = chartTheme();
  if (netChart) {
    netChart.options.scales.y.ticks.color = theme.ink;
    netChart.options.scales.y.grid.color = theme.grid;
    netChart.update();
  }
  if (chartDays) {
    const legend = chartDays.options.plugins && chartDays.options.plugins.legend;
    if (legend && legend.labels) legend.labels.color = theme.ink;
    ["x", "y"].forEach((axis) => {
      const scale = chartDays.options.scales && chartDays.options.scales[axis];
      if (!scale) return;
      scale.ticks = Object.assign({}, scale.ticks, { color: theme.ink });
      scale.grid = Object.assign({}, scale.grid, { color: theme.grid });
    });
    chartDays.update();
  }
  if (chartOps) {
    const legend = chartOps.options.plugins && chartOps.options.plugins.legend;
    if (legend && legend.labels) legend.labels.color = theme.ink;
    chartOps.update();
  }
}

function paintOverview(ov, attempt) {
  if (typeof Chart === "undefined") return;
  const daysEl = document.getElementById("chart-days");
  const opsEl = document.getElementById("chart-ops");
  if (!daysEl || !opsEl) return;
  if (daysEl.offsetParent === null) {
    if ((attempt || 0) < 6) setTimeout(() => paintOverview(ov, (attempt || 0) + 1), 40);
    return;
  }
  destroyCharts();
  const days = (ov && ov.days) || [];
  const ops = (ov && ov.ops) || [];
  const theme = chartTheme();
  chartDays = new Chart(daysEl, {
    type: "bar",
    data: {
      labels: days.map((d) => d.date),
      datasets: [
        { label: "成功", data: days.map((d) => d.ok || 0), backgroundColor: "#36b37e", borderRadius: 6, stack: "a" },
        { label: "拒绝", data: days.map((d) => d.denied || 0), backgroundColor: "#de350b", borderRadius: 6, stack: "a" },
        { label: "其他", data: days.map((d) => d.other || 0), backgroundColor: "#ffab00", borderRadius: 6, stack: "a" }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { color: theme.ink } } },
      scales: {
        x: { stacked: true, ticks: { color: theme.ink }, grid: { color: theme.grid } },
        y: { stacked: true, beginAtZero: true, ticks: { precision: 0, color: theme.ink }, grid: { color: theme.grid } }
      }
    }
  });
  chartOps = new Chart(opsEl, {
    type: "doughnut",
    data: {
      labels: ops.map((item) => item.op),
      datasets: [{
        data: ops.map((item) => item.count || 0),
        backgroundColor: ["#0052cc", "#36b37e", "#ffab00", "#de350b", "#6554c0", "#00b8d9", "#5c6370", "#97a0af"],
        borderWidth: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "bottom", labels: { color: theme.ink } } } }
  });
}

document.addEventListener("alpine:init", () => {
  Alpine.data("sshui", () => sshui());
});

function sshui() {
  return {
    view: "home",
    navOpen: false,
    navCollapsed: false,
    _sessionWait: null,
    currentHost: "",
    csrf: "",
    seq: 0,
    theme: "light",
    density: "comfortable",
    catalog: { envs: [], groups: [], hosts: [], policies: [] },
    catalogLoading: false,
    hostFilter: { env: [], group: [] },
    termFilter: { env: [], group: [], query: "" },
    hostPickerOpen: false,
    hostPickerLimit: 40,
    known: [],
    sessions: [],
    dash: { hosts: 0, groups: 0, envs: 0, sessions: 0, recent: [], failures: [], audit: {}, hmac: {} },
    detail: { host: {}, policy: { capabilities: {} }, sessions: [], audit: [] },
    ops: { hmac: {}, audit: {} },
    audit: { records: [], page: 1, pageSize: DEFAULT_PAGE_SIZE, total: 0, stats: {}, jump: "" },
    auditFilter: { op: "", host: "", group: "", env: "", status: "", source: "", since: "", until: "" },
    col: { time: "", status: "", op: "", host: "", env: "", command: "", reason: "" },
    q: { hosts: "", groups: "", tags: "", envs: "", policy: "", known: "" },
    pages: {
      hosts: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      groups: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      tags: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      envs: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      policy: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      known: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" },
      sessions: { page: 1, size: DEFAULT_PAGE_SIZE, jump: "" }
    },
    selected: {},
    pickAll: false,
    tagDraft: {},
    tagBulk: {},
    dialog: { host: false, group: false, policy: false, env: false, batch: false, detail: false, proc: false, confirm: false },
    confirmView: { message: "", value: "", kind: "text", detail: "" },
    bundleYaml: "",
    bundleImport: "",
    cleanupNote: "",
    operateOut: "",
    batchOut: "",
    batchBusy: false,
    batchUncertain: false,
    batchOperationID: "",
    batchPreview: null,
    batchPreviewKey: "",
    hostSeq: 0,
    hostLoading: false,
    termOpening: false,
    termFontSize: 14,
	termSearch: blankSearch(),
    filesCollapsed: false,
    workspaceCache: Object.create(null),
    workspaceSeq: 0,
    filesReadSeq: 0,
    filesLoading: false,
    filesPendingPath: "",
    fileScroll: { list: 0, tree: 0, history: 0 },
    panel: "terminal",
    errors: {},
    settingsNote: "",
    draft: {
      commandTimeout: "",
      pageSize: DEFAULT_PAGE_SIZE,
      theme: "light",
      density: "comfortable",
      relayCrossEnv: false,
      idle: "",
      maxLife: ""
    },
    hostForm: null,
    groupForm: null,
    policyForm: null,
    envForm: null,
    exec: { alias: "", command: "", timeout: "", confirm: "", allowOutflow: false },
    relay: { from: "", fromPath: "", to: "", toPath: "", confirm: "", allowCrossEnv: false },
    termTabs: [],
    termActive: "",
    termAlias: "",
    explicitAlias: "",
    procSort: { key: "mem", dir: "desc" },
    pathDraft: "",
    pathError: "",
    pathFocused: false,
    tree: {},
    treeRoot: "",
    ws: { side: 280, lower: null },
    metrics: { alias: "", connected: false, address: "", port: "", user: "", hostname: "", uptime: "", load: "", cpuPercent: null, mem: null, swap: null, procs: [], disks: [], notes: [], netRx: 0, netTx: 0, netRxRate: 0, netTxRate: 0 },
    netSeries: {},
    metricsTimer: 0,
    metricsSeq: 0,
    metricsBusy: "",
    metricsFailures: 0,
    metricsUpdated: 0,
    metricsClock: 0,
    sessionsSeq: 0,
    workspaceClosedAlias: "",
    execBusy: false,
    execUncertain: false,
    execOperationID: "",
    execSnapshot: null,
    fileBusy: false,
    fileAction: null,
    auditWarning: "",
    readAbort: {},
    files: { alias: "", mode: "files", path: "", parent: "", home: "", crumbs: [], entries: [], truncated: false },
    procView: { pid: "", ppid: "", user: "", cpu: "", mem: "", memPct: "", stat: "", etime: "", cmd: "", cwd: "", cwdNote: "" },
    drop: { over: false, target: "", label: "" },
    transfers: [],
    transferRunning: false,
    uploadBusy: false,
    treeClock: 0,
    downloadDir: "",
    toasts: [],
    menu: { open: false, x: 0, y: 0, entry: null, newOpen: false },
    selectedPath: "",
    historyView: { alias: "", found: false, status: "", path: "", shell: "", lines: [], notes: [], truncated: false, error: "", suppressed: false },
    detailTitle: "",
    detailText: "",
    overview: { days: [], ops: [] },
    titles: {
      home: "概览",
      terminal: "终端",
      hosts: "主机",
      host: "主机详情",
      groups: "分组",
      tags: "标签",
      envs: "环境",
      policy: "危险命令",
      known: "已知主机密钥",
      audit: "审计",
      sessions: "会话",
      operate: "执行",
      relay: "跨机拷贝",
      bundle: "运维",
      settings: "设置"
    },
    viewAlias: {
      "": "home",
      home: "home",
      terminal: "terminal",
      hosts: "hosts",
      host: "host",
      groups: "groups",
      tags: "tags",
      envs: "envs",
      policy: "policy",
      known: "hosts",
      audit: "audit",
      sessions: "sessions",
      operate: "operate",
      relay: "relay",
      bundle: "bundle",
      settings: "settings"
    },

    init() {
      this.restorePending();
      this.hostForm = this.blankHost();
      this.groupForm = this.blankGroup();
      this.policyForm = this.blankPolicy();
      this.envForm = this.blankEnv();
      this.applyStored();
      this.ensureSession().catch((err) => this.setError("home", err.message));
      document.querySelectorAll("label.form-label").forEach((label, i) => {
        const control = label.nextElementSibling;
        if (control && control.matches("input,select,textarea")) {
          if (!control.id) control.id = "field-" + i;
          label.htmlFor = control.id;
        }
      });
      document.querySelectorAll('[role="dialog"]').forEach((el, i) => {
        el.setAttribute("aria-modal", "true");
        const title = el.querySelector(".modal-title");
        if (title) { title.id = "dialog-title-" + i; el.setAttribute("aria-labelledby", title.id); }
      });
      const parsed = this.readHash(location.hash.replace(/^#/, ""));
      this.show(parsed.view || "home");
      this.loadCatalog();
      this.loadAudit();
      this.loadSessions();
      window.addEventListener("hashchange", () => {
        const next = this.readHash(location.hash.replace(/^#/, ""));
        this.show(next.view || "home");
      });
      document.addEventListener("keydown", (ev) => {
        if (ev.isComposing || ev.keyCode === 229) return;
        if (this.anyDialog()) { this.dialogKey(ev); return; }
        if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
        const tag = (ev.target && ev.target.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select" || ev.target.isContentEditable) return;
        ev.preventDefault();
        this.show("hosts");
        setTimeout(() => {
          const input = document.getElementById("host-search");
          if (input) input.focus();
        }, 0);
      });
      window.addEventListener("resize", () => {
        if (this.view === "terminal") this.fitActive();
        if (this.hostPickerOpen) this.positionHostPicker();
      });
      if (window.visualViewport) window.visualViewport.addEventListener("resize", () => {
        if (this.hostPickerOpen) this.positionHostPicker();
      });
      document.addEventListener("visibilitychange", () => {
        if (document.hidden && this._endSplit) this._endSplit();
        if (document.hidden) this.stopMetrics();
        else if (this.view === "terminal") this.startMetrics();
      });
      window.addEventListener("beforeunload", (ev) => {
        if (this.termTabs.some((tab) => tab.state === "connected") || this.transfers.some((t) => t.active) || this.execBusy || this.execUncertain || this.fileBusy || (this.fileAction && this.fileAction.uncertain) || this.batchBusy || this.batchUncertain) {
          ev.preventDefault(); ev.returnValue = "";
        }
      });
      setInterval(() => this.tickSessions(), 1000);
      setInterval(() => {
        if (this.view === "sessions" || this.view === "home") this.loadSessions();
      }, 20000);
    },

    applyStored() {
      const prefs = this.loadPrefs();
      this.draft.commandTimeout = prefs.commandTimeout || "";
      this.draft.pageSize = PAGE_SIZES.indexOf(Number(prefs.pageSize)) >= 0 ? Number(prefs.pageSize) : DEFAULT_PAGE_SIZE;
      this.draft.theme = prefs.theme === "dark" ? "dark" : "light";
      this.draft.density = prefs.density === "compact" ? "compact" : "comfortable";
      this.draft.relayCrossEnv = !!prefs.relayCrossEnv;
      this.theme = this.draft.theme;
      this.density = this.draft.density;
      this.navCollapsed = !!prefs.navCollapsed;
      if (prefs.wsSide >= 220 && prefs.wsSide <= 460) this.ws.side = prefs.wsSide;
      if (prefs.wsLower >= 160 && prefs.wsLower <= 4096) this.ws.lower = prefs.wsLower;
      if (Number.isInteger(prefs.termFontSize) && prefs.termFontSize >= 12 && prefs.termFontSize <= 22) this.termFontSize = prefs.termFontSize;
      this.filesCollapsed = prefs.filesCollapsed === true;
      this.downloadDir = typeof prefs.downloadDir === "string" ? prefs.downloadDir : "";
      this.exec.timeout = this.draft.commandTimeout;
      this.audit.pageSize = this.draft.pageSize;
      for (const key of Object.keys(this.pages)) this.pages[key].size = this.draft.pageSize;
      this.relay.allowCrossEnv = this.draft.relayCrossEnv;
      document.documentElement.setAttribute("data-bs-theme", this.theme);
      document.documentElement.setAttribute("data-theme", this.theme);
    },

    loadPrefs() {
      try {
        return JSON.parse(localStorage.getItem("sshCliPrefs") || "{}");
      } catch (err) {
        return {};
      }
    },

    savePrefs(patch) {
      const next = Object.assign(this.loadPrefs(), patch || {});
      localStorage.setItem("sshCliPrefs", JSON.stringify(next));
      return next;
    },

    saveDownloadDir() {
      this.savePrefs({ downloadDir: this.downloadDir || "" });
    },

    downloadDirLabel() {
      const dir = String(this.downloadDir || "").trim();
      return dir || "默认 Downloads";
    },

    useDefaultDownloadDir() {
      this.downloadDir = "";
      this.saveDownloadDir();
    },

    async pickDownloadDir() {
      try {
        const data = await this.postJSON("/api/download-dir", {});
        if (!data || data.cancelled) return;
        const dir = String(data.path || "").trim();
        if (!dir) return;
        this.downloadDir = dir;
        this.saveDownloadDir();
      } catch (err) {
        this.toast((err && err.message) || "没有选到目录", "bad");
      }
    },

    toggleTheme() {
      this.draft.theme = this.theme === "dark" ? "light" : "dark";
      this.applyLook();
      this.savePrefs({ theme: this.draft.theme });
    },

    toggleDensity() {
      this.draft.density = this.density === "compact" ? "comfortable" : "compact";
      this.applyLook();
      this.savePrefs({ density: this.draft.density });
    },

    toggleNav() {
      this.navCollapsed = !this.navCollapsed;
      this.savePrefs({ navCollapsed: this.navCollapsed });
      const app = this;
      setTimeout(() => {
        if (app.view === "terminal") app.fitActive();
      }, 200);
    },

    applyLook() {
      this.theme = this.draft.theme === "dark" ? "dark" : "light";
      this.density = this.draft.density === "compact" ? "compact" : "comfortable";
      document.documentElement.setAttribute("data-bs-theme", this.theme);
      document.documentElement.setAttribute("data-theme", this.theme);
      restyleCharts();
    },

    tableClass() {
      return this.density === "compact" ? "table table-vcenter card-table table-sm" : "table table-vcenter card-table";
    },

    themeLabel() {
      return this.theme === "dark" ? "浅色" : "深色";
    },

    densityLabel() {
      return this.density === "compact" ? "标准" : "紧凑";
    },

    readHash(name) {
      const raw = String(name || "").replace(/^#/, "");
      const slash = raw.indexOf("/");
      if (slash === -1) return { view: raw, arg: "" };
      return { view: raw.slice(0, slash), arg: decodeURIComponent(raw.slice(slash + 1)) };
    },

    is(name) {
      return this.view === name;
    },

    pageTitle() {
      if (this.view === "host" && this.currentHost) return "主机详情 · " + this.currentHost;
      return this.titles[this.view] || "ssh-cli";
    },

    show(name) {
      if (this._endSplit) this._endSplit();
      const parsed = this.readHash(name);
      const view = this.viewAlias[parsed.view] || "home";
      if (this.hostPickerOpen && view !== "terminal") this.closeHostPicker();
      if (view === "host" && parsed.arg) this.currentHost = parsed.arg;
      this.view = view;
      this.navOpen = false;
      const hash = view === "host" && this.currentHost ? "#host/" + encodeURIComponent(this.currentHost) : "#" + view;
      if (location.hash !== hash) history.replaceState(null, "", hash);
      if (view !== "home") destroyCharts();
      if (view === "home") this.loadDashboard();
      if (view === "terminal") {
        this.fitActive();
        this.syncWorkspace();
      } else {
        this.stopMetrics();
      }
      if (view === "audit") setTimeout(() => this.bindRange(), 0);
      if (view === "host") this.loadHost();
      if (view === "sessions") this.loadSessions();
      if (view === "settings") this.loadSettings();
      if (view === "bundle" || view === "policy") this.loadOps();
      if (view === "relay") this.relay.allowCrossEnv = !!this.loadPrefs().relayCrossEnv;
      if (view === "audit") this.loadAudit();
    },

    openHost(alias) {
      this.currentHost = alias;
      this.show("host/" + alias);
    },

    explain(msg) {
      const m = String(msg || "");
      if (!m) return "操作没有完成。看审计里的最近失败，或回到概览。";
      const low = m.toLowerCase();
      if (low.indexOf("jump cycle") >= 0) return "这几台主机会互相绕回去。改成直连，或换一台不会绕回来的跳板。";
      if (low.indexOf("invalid jump host") >= 0) return "不能把这台主机自己当成跳板。选另一台已经保存的主机，或取消「经跳板」。";
      if (low.indexOf("jump host") >= 0 && low.indexOf("does not exist") >= 0) return "跳板还没登记。先在主机页添加那台跳板，再回来选择。";
      if (low.indexOf("is the jump host for") >= 0) return "还有别的主机要经过它才能连接。先编辑那些主机，取消「经跳板」或换一台，再删除。";
      if (low.indexOf("jump chain longer") >= 0) return "跳板一层套一层，最多 8 台。改短一点再保存。";
      if (low.indexOf("invalid via") >= 0) return "跳板没选对。从列表里选一台已经保存的主机。";
      if (/denied|policy|builtin/.test(low) || m.indexOf("拒绝") >= 0 || m.indexOf("拦截") >= 0) {
        return m + "。打开主机详情看命中的规则。危险命令清单默认不拦截，要启用并选中后才生效。";
      }
      if (/auth|permission denied|认证/.test(low)) {
        return m + "。认证失败。在主机表单里更新密码或私钥路径后再连。密码不会出现在审计里。";
      }
      if (/connect|dial|refused|timeout|no route|network|known_hosts|host key|i\/o/.test(low)) {
        return m + "。连接失败。核对地址和端口，确认本机能访问该主机。主机密钥变了就打开这台主机的详情，清除信任后再连。";
      }
      return m;
    },

    setError(key, msg) {
      this.errors[key] = msg ? this.explain(msg) : "";
    },

    noteAudit(data) {
      if (data && (data.auditWarning || (Array.isArray(data.results) && data.results.some((row) => row && row.auditWarning)))) {
        this.auditWarning = "本地审计写入失败，请检查配置目录的权限和磁盘空间。远端操作结果见本次返回，不要因此重复执行。";
      }
    },

    async requestBearer() {
      const typed = await this.ask("这个监听地址要求 Bearer token。请粘贴启动 ssh-cli ui 时打印的那一行。", "", "password");
      if (typed == null || !String(typed).trim()) { const err = new Error("需要 Bearer token"); err.outcome = "not_started"; throw err; }
      const token = String(typed).trim(); sessionStorage.setItem("sshCliBearer", token); return token;
    },

    async api(url, options, beforeSend) {
      const opts = Object.assign({ credentials: "same-origin" }, options || {});
      const method = String(opts.method || "GET").toUpperCase();
      if (method !== "GET" && method !== "HEAD" && !this.csrf) await this.ensureSession();
      const headers = Object.assign({}, opts.headers || {});
      const token = sessionStorage.getItem("sshCliBearer") || "";
      if (token) headers.Authorization = "Bearer " + token;
      if (this.csrf) headers["X-CSRF-Token"] = this.csrf;
      opts.headers = headers;
      if (beforeSend) beforeSend();
      let res = await fetch(url, opts);
      if (res.status === 401) {
        headers.Authorization = "Bearer " + await this.requestBearer();
        opts.headers = headers;
        if (beforeSend) beforeSend();
        res = await fetch(url, opts);
      }
      if (res.status === 403 && res.headers && res.headers.get("X-SSH-CLI-Session-Expired") === "1") {
        this.csrf = "";
        await this.ensureSession();
        headers["X-CSRF-Token"] = this.csrf;
        if (beforeSend) beforeSend();
        res = await fetch(url, opts);
      }
      if (res.headers && res.headers.get(auditHeader)) this.noteAudit({ auditWarning: true });
      return res;
    },

    async parseJSON(res) {
      const text = await res.text();
      const trimmed = String(text || "").trim();
      if (!trimmed) {
        if (!res.ok) throw new Error(res.statusText || "请求失败");
        return {};
      }
      try {
        const data = JSON.parse(trimmed);
        this.noteAudit(data);
        return data;
      } catch (err) {
        throw new Error(plainBodyMessage(trimmed, res.statusText));
      }
    },

    async readJSON(res) {
      const data = await this.parseJSON(res);
      if (!res.ok || data.ok === false) throw new Error(friendlyError(data && data.error, res.statusText));
      return data;
    },

    persistPending() {
      // No file bytes, command text, command output, or credentials are stored.
      try {
        const transfers = (this.transfers || []).filter((t) => t.started && t.active || this.transferNeedsVerification(t)).slice(-TRANSFER_LIMIT).map((t) => ({
          id: t.id, alias: t.alias, kind: t.kind, name: t.name, remote: t.remote, local: t.local,
          active: false, needsVerification: true, label: "结果待确认"
        }));
        sessionStorage.setItem("sshCliPending", JSON.stringify({ transfers: transfers,
          file: this.fileAction && !this.fileAction.done && (this.fileAction.uncertain || this.fileBusy) ? { alias: this.fileAction.scope.alias, path: this.fileAction.path, op: this.fileAction.op } : null,
          exec: (this.execBusy || this.execUncertain) ? this.execOperationID : "",
          batch: (this.batchBusy || this.batchUncertain) ? this.batchOperationID : "" }));
      } catch (err) { /* Storage may be disabled; in-page verification still works. */ }
    },

    restorePending() {
      try {
        const raw = sessionStorage.getItem("sshCliPending") || "{}";
        if (raw.length > 512 * 1024) return;
        const saved = JSON.parse(raw);
        if (saved.file && typeof saved.file.alias === "string" && typeof saved.file.path === "string") {
          this.fileAction = { scope: { alias: saved.file.alias }, path: saved.file.path, op: saved.file.op, uncertain: true,
            message: saved.file.alias + " · " + saved.file.path + "：页面已重新载入，请核验原主机文件后清除提示。" };
        }
        this.transfers = (Array.isArray(saved.transfers) ? saved.transfers : []).slice(-TRANSFER_LIMIT).filter((t) => t && typeof t.id === "string" && typeof t.name === "string").map((t) => ({
          id: t.id, alias: t.alias, kind: t.kind, name: t.name, remote: t.remote, local: t.local,
          active: false, needsVerification: true, label: "结果待确认", error: "页面已重新载入，请核验原目标；不会自动重新传输。"
        }));
        if (/^[A-Za-z0-9_-]{16,80}$/.test(saved.exec || "")) { this.execOperationID = saved.exec; this.execUncertain = true; }
        if (/^[A-Za-z0-9_-]{16,80}$/.test(saved.batch || "")) { this.batchOperationID = saved.batch; this.batchUncertain = true; }
      } catch (err) { /* Ignore malformed browser state. */ }
    },

    async ensureSession() {
      if (this.csrf) return;
      if (!this._sessionWait) {
        const app = this;
        this._sessionWait = (async () => {
          const data = await app.readJSON(await app.api("/api/session"));
          app.csrf = data.csrf || "";
          if (!app.csrf) throw new Error("请求被拒绝：缺少 CSRF，请刷新页面");
        })().finally(() => {
          app._sessionWait = null;
        });
      }
      await this._sessionWait;
    },

    replaceRead(key) {
      this.abortRead(key);
      if (typeof AbortController === "undefined") return undefined;
      const ctrl = new AbortController();
      this.readAbort[key] = ctrl;
      return ctrl.signal;
    },

    abortRead(key) {
      if (key === "files") {
        this.filesReadSeq++;
        this.filesLoading = false;
      }
      const ctrl = this.readAbort && this.readAbort[key];
      if (ctrl) ctrl.abort();
      if (this.readAbort) delete this.readAbort[key];
    },

    async postRead(url, body, signal) {
      await this.ensureSession();
      checkRead(signal);
      const res = await this.api(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
        signal: signal
      });
      const data = await this.readJSON(res);
      checkRead(signal);
      return data;
    },

    async postJSON(url, body, beforeSend) {
      let sent = false;
      try {
        await this.ensureSession();
        const payload = Object.assign({}, body);
        for (let attempt = 0; attempt < 4; attempt++) {
          const res = await this.api(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          }, () => { if (beforeSend) beforeSend(); sent = true; });
          const data = await this.parseJSON(res);
          if (res.status === 409 && data.needsConfirm) {
            sent = false;
            const typed = await this.ask((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
            if (typed == null) {
              const err = new Error("已取消"); err.outcome = "not_started"; throw err;
            }
            if (data.confirmField) payload[data.confirmField] = typed;
            else payload.confirm = typed;
            payload.humanConfirm = payload.humanConfirm || typed;
            continue;
          }
          if (!res.ok || data.ok === false) {
            const err = new Error(friendlyError(data.error, res.statusText));
            err.outcome = data.outcome || (res.status >= 400 && res.status < 500 ? "not_started" : "unknown");
            throw err;
          }
          return data;
        }
        const err = new Error("确认失败"); err.outcome = "not_started"; throw err;
      } catch (err) {
        if (!sent && !err.outcome) err.outcome = "not_started";
        throw err;
      }
    },

    async loadCatalog() {
      this.setError("hosts", "");
      this.catalogLoading = true;
      try {
        this.catalog = await this.readJSON(await this.api("/api/catalog"));
        if (!this.catalog.hosts) this.catalog.hosts = [];
        if (!this.catalog.groups) this.catalog.groups = [];
        if (!this.catalog.envs) this.catalog.envs = [];
        if (!this.catalog.policies) this.catalog.policies = [];
        this.reconcileHostFilters();
        this.syncTagDrafts();
        if (!this.exec.alias && this.catalog.hosts.length) this.exec.alias = this.catalog.hosts[0].alias;
        if (!this.termAlias && this.catalog.hosts.length) this.termAlias = this.catalog.hosts[0].alias;
        if (!this.relay.from && this.catalog.hosts.length) {
          this.relay.from = this.catalog.hosts[0].alias;
          this.relay.to = this.catalog.hosts[0].alias;
        }
        this.clampAll();
        if (this.hostPickerOpen) this.$nextTick(() => this.positionHostPicker());
      } catch (err) {
        this.setError("hosts", err.message);
      } finally { this.catalogLoading = false; }
    },

    async loadKnown() {
      this.setError("known", "");
      try {
        const data = await this.readJSON(await this.api("/api/known-hosts"));
        this.known = data.knownHosts || [];
        this.clampPage("known");
      } catch (err) {
        this.setError("known", err.message);
      }
    },

    async loadDashboard() {
      this.setError("home", "");
      try {
        this.dash = await this.readJSON(await this.api("/api/dashboard"));
        if (!this.dash.recent) this.dash.recent = [];
        if (!this.dash.failures) this.dash.failures = [];
        this.overview = await this.readJSON(await this.api("/api/audit/overview"));
        if (!this.overview.days) this.overview.days = [];
        if (!this.overview.ops) this.overview.ops = [];
        paintOverview(this.overview);
        await this.loadSessions();
      } catch (err) {
        this.setError("home", err.message);
      }
    },

    async loadHost() {
      this.setError("host", "");
      if (!this.currentHost) {
        this.setError("host", "先从主机列表打开一台主机。");
        return;
      }
      const alias = this.currentHost;
      const seq = ++this.hostSeq;
      this.hostLoading = true;
      const signal = this.replaceRead("host");
      this.detail = { host: {}, policy: { capabilities: {} }, sessions: [], audit: [], knownHosts: [] };
      try {
        const data = await this.readJSON(await this.api("/api/hosts/detail?alias=" + encodeURIComponent(alias), { signal: signal }));
        if (seq !== this.hostSeq || this.currentHost !== alias) return;
        this.detail = data;
        if (!this.detail.policy) this.detail.policy = { capabilities: {} };
        if (!this.detail.policy.capabilities) this.detail.policy.capabilities = {};
        if (!this.detail.audit) this.detail.audit = [];
        if (!this.detail.sessions) this.detail.sessions = [];
        if (!this.detail.knownHosts) this.detail.knownHosts = [];
        if (this.detail.knownError) this.setError("known", this.detail.knownError);
      } catch (err) {
        if (err.name === "AbortError" || seq !== this.hostSeq) return;
        this.setError("host", err.message);
      } finally {
        if (seq === this.hostSeq) this.hostLoading = false;
      }
    },

    async loadSessions() {
      const seq = ++this.sessionsSeq;
      this.setError("sessions", "");
      try {
        const data = await this.readJSON(await this.api("/api/sessions"));
        if (seq !== this.sessionsSeq) return;
        this.sessions = data.sessions || [];
        if (this.explicitAlias && !this.sessions.some((item) => item.alias === this.explicitAlias)) {
          this.workspaceClosedAlias = this.explicitAlias;
          this.explicitAlias = "";
          if (this.view === "terminal") this.syncWorkspace();
        }
        if (this.dash) this.dash.sessions = this.sessions.length;
        this.clampPage("sessions");
      } catch (err) {
        if (seq !== this.sessionsSeq) return;
        this.setError("sessions", err.message);
      }
    },

    async loadOps() {
      this.setError("bundle", "");
      try {
        this.ops = await this.readJSON(await this.api("/api/ops"));
        if (!this.ops.hmac) this.ops.hmac = {};
      } catch (err) {
        this.setError("bundle", err.message);
      }
    },

    async loadSettings() {
      this.setError("settings", "");
      this.applyStored();
      try {
        const data = await this.readJSON(await this.api("/api/settings"));
        const session = data.session || {};
        this.draft.idle = session.idleConfig || "";
        this.draft.maxLife = session.maxLifeConfig || "";
        this.settingsNote = "当前空闲 " + (session.idle || "") + "，最长 " + (session.maxLife || "") + "。主题、分页和默认超时只在这台浏览器。";
      } catch (err) {
        this.setError("settings", err.message);
      }
    },

    async saveSettings() {
      this.setError("settings", "");
      const size = PAGE_SIZES.indexOf(Number(this.draft.pageSize)) >= 0 ? Number(this.draft.pageSize) : DEFAULT_PAGE_SIZE;
      this.draft.pageSize = size;
      this.savePrefs({
        commandTimeout: String(this.draft.commandTimeout || "").trim(),
        pageSize: size,
        theme: this.draft.theme,
        density: this.draft.density,
        relayCrossEnv: !!this.draft.relayCrossEnv
      });
      this.applyLook();
      this.exec.timeout = String(this.draft.commandTimeout || "").trim();
      this.audit.pageSize = size;
      this.audit.page = 1;
      for (const key of Object.keys(this.pages)) {
        this.pages[key].size = size;
        this.pages[key].page = 1;
      }
      try {
        await this.postJSON("/api/settings", {
          idle: String(this.draft.idle || "").trim(),
          maxLife: String(this.draft.maxLife || "").trim()
        });
        await this.loadSettings();
        this.loadAudit();
      } catch (err) {
        this.setError("settings", err.message);
      }
    },

    auditParams() {
      const params = new URLSearchParams();
      const f = this.auditFilter;
      if (f.op) params.set("op", f.op);
      if (f.host) params.set("host", f.host);
      if (f.group) params.set("group", f.group);
      if (f.env) params.set("env", f.env);
      if (f.status) params.set("status", f.status);
      if (f.source) params.set("source", f.source);
      if (String(f.since || "").trim()) params.set("since", String(f.since).trim());
      if (String(f.until || "").trim()) params.set("until", String(f.until).trim());
      params.set("page", String(this.audit.page));
      params.set("pageSize", String(this.audit.pageSize || DEFAULT_PAGE_SIZE));
      return params;
    },

    async loadAudit() {
      this.setError("audit", "");
      try {
        const data = await this.readJSON(await this.api("/api/audit?" + this.auditParams().toString()));
        this.audit.records = data.records || [];
        this.audit.page = data.page || this.audit.page;
        this.audit.pageSize = data.pageSize || this.audit.pageSize;
        this.audit.total = data.total || 0;
        this.audit.stats = data.stats || {};
        if ((this.auditFilter.source || "") === "cli") {
          this.dash.auditCli = this.audit.total;
        }
      } catch (err) {
        this.setError("audit", err.message);
      }
    },

    searchAudit() {
      this.audit.page = 1;
      this.loadAudit();
    },

    setRange(value) {
      this.auditFilter.since = value;
      this.auditFilter.until = "";
      const el = document.getElementById("audit-range");
      if (el) el.value = "";
      suppressRange = true;
      setTimeout(() => { suppressRange = false; }, 300);
      if (rangePicker && rangePicker.clearSelection) rangePicker.clearSelection();
      this.searchAudit();
    },

    auditPrev() {
      if (this.audit.page > 1) {
        this.audit.page -= 1;
        this.loadAudit();
      }
    },

    auditNext() {
      if (this.audit.page < this.auditPages()) {
        this.audit.page += 1;
        this.loadAudit();
      }
    },

    auditSetPage(n) {
      const max = this.auditPages();
      const page = Math.min(Math.max(1, Number(n) || 1), max);
      if (page === this.audit.page) return;
      this.audit.page = page;
      this.loadAudit();
    },

    auditWindow() {
      return this._pageWindow(this.audit.page, this.auditPages());
    },

    auditGo() {
      const n = parseInt(String(this.audit.jump || "").trim(), 10);
      if (!Number.isFinite(n) || n < 1) return;
      const page = Math.min(Math.floor(n), this.auditPages());
      this.audit.jump = String(page);
      this.auditSetPage(page);
    },

    showAllAudit() {
      this.auditFilter.source = "";
      this.searchAudit();
    },

    clearAuditCols() {
      this.col = { time: "", status: "", op: "", host: "", env: "", command: "", reason: "" };
    },

    auditPages() {
      const size = this.audit.pageSize || DEFAULT_PAGE_SIZE;
      return Math.max(1, Math.ceil((this.audit.total || 0) / size));
    },

    setAuditSize() {
      this.audit.page = 1;
      this.loadAudit();
    },

    async exportAudit() {
      this.setError("audit", "");
      const params = this.auditParams();
      params.delete("page");
      params.delete("pageSize");
      try {
        const res = await this.api("/api/audit/export?" + params.toString());
        if (!res.ok) {
          const data = await this.parseJSON(res);
          throw new Error(friendlyError(data.error, res.statusText));
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "audit.csv";
        a.click();
        URL.revokeObjectURL(url);
      } catch (err) {
        this.setError("audit", err.message);
      }
    },

    async cleanupAudit() {
      this.setError("audit", "");
      try {
        const data = await this.postJSON("/api/audit/cleanup", {});
        await this.loadAudit();
        this.setError("audit", "");
        this.cleanupNote = "已删除 " + data.removed + " 条，保留 " + data.kept + " 条。30 天以内的记录不会删。";
      } catch (err) {
        this.setError("audit", err.message);
      }
    },

    shownAudit() {
      return (this.audit.records || []).filter((rec) => this.auditVisible(rec));
    },

    auditVisible(rec) {
      const cols = {
        time: this.formatTime(rec.time) || rec.time || "",
        status: rec.status || "",
        op: rec.op || "",
        host: rec.host || "",
        env: rec.env || "",
        command: this.subject(rec),
        reason: rec.reason || ""
      };
      const keys = Object.keys(this.col);
      for (let i = 0; i < keys.length; i++) {
        const q = String(this.col[keys[i]] || "").trim().toLowerCase();
        if (q && String(cols[keys[i]] || "").toLowerCase().indexOf(q) < 0) return false;
      }
      return true;
    },

    formatTime(value) {
      return stamp(value);
    },

    openDetail(title, text) {
      this.detailTitle = title || "详情";
      this.detailText = text || "";
      this.openDialog("detail");
    },

    bindRange() {
      if (rangePicker || typeof Litepicker === "undefined") return;
      const el = document.getElementById("audit-range");
      if (!el) return;
      const app = this;
      rangePicker = new Litepicker({
        element: el,
        singleMode: false,
        numberOfMonths: 2,
        numberOfColumns: 2,
        format: "YYYY-MM-DD",
        lang: "zh-CN",
        autoApply: true,
        setup: (picker) => {
          picker.on("selected", (start, end) => {
            if (suppressRange) return;
            const since = ymd(start);
            const until = ymd(end);
            if (!since || !until) return;
            app.auditFilter.since = since;
            app.auditFilter.until = until;
            app.searchAudit();
          });
        }
      });
    },

    async openTerminal(alias) {
      if (this.termOpening) return;
      const name = String(alias || this.termAlias || "").trim();
      this.termAlias = name;
      this.show("terminal");
      if (!name) {
        this.setError("terminal", "先选择一台主机。");
        return;
      }
      if (this.terminalBlocked(name)) {
        this.setError("terminal", this.hostByAlias(name).terminalReason + "；请使用「执行」页发送受策略检查的命令。");
        return;
      }
      this.setError("terminal", "");
      this.termOpening = true;
      try {
        await new Promise((resolve) => setTimeout(resolve, 40));
        await this.mountTerm(name);
      } finally { this.termOpening = false; }
    },

    async focusTerminal(alias) {
      const name = String(alias || "").trim();
      if (!name) {
        this.show("terminal");
        return;
      }
      const tabs = this.termTabs || [];
      for (let i = 0; i < tabs.length; i++) {
        if (tabs[i].alias === name) {
          this.termAlias = name;
          this.show("terminal");
          this.showPane(tabs[i].id);
          return;
        }
      }
      await this.openTerminal(name);
    },

    async openLiveTerminal() {
      const live = this.liveSessions();
      if (live.length) {
        await this.focusTerminal(live[0].alias);
        return;
      }
      this.show("terminal");
    },

    liveSessions() {
      return (this.sessions || []).filter((item) => item && item.alias);
    },

    liveCount() {
      const n = this.liveSessions().length;
      if (n) return n;
      return (this.dash && this.dash.sessions) || 0;
    },

    async mountTerm(alias) {
      const screen = document.getElementById("term-screen");
      if (!screen || typeof Terminal === "undefined" || !window.FitAddon) {
        this.setError("terminal", "终端组件没有加载。");
        return;
      }
      const id = "t" + operationID();
      const pane = document.createElement("div");
      pane.className = "term-pane";
      pane.dataset.id = id;
      pane.id = "pane-" + id;
      pane.setAttribute("role", "tabpanel");
      pane.setAttribute("aria-labelledby", "tab-" + id);
      screen.appendChild(pane);
      const term = new Terminal({
        cursorBlink: true,
        allowProposedApi: true,
        disableStdin: true,
        fontFamily: '"SF Mono", Menlo, Consolas, monospace',
        fontSize: this.termFontSize,
        theme: { background: "#1d1d1f", foreground: "#f5f5f7", cursor: "#f5f5f7" }
      });
      const fit = new FitAddon.FitAddon();
      term.loadAddon(fit);
      const search = typeof SearchAddon !== "undefined" ? new SearchAddon.SearchAddon({ highlightLimit: SEARCH_LIMIT }) : null;
      if (search) term.loadAddon(search);
      term.open(pane);
      fit.fit();
      const app = this;
      const ordinal = 1 + this.termTabs.filter((t) => t.alias === alias).reduce((n, t) => Math.max(n, t.ordinal || 1), 0);
      const entry = { id: id, alias: alias, term: term, fit: fit, search: search, searchState: blankSearch(), pane: pane, ws: null, generation: 0, ready: false, input: [], inputBytes: 0, inputTimer: 0 };
      termMap.set(id, entry);
      if (search) entry.searchResults = search.onDidChangeResults((result) => {
        Object.assign(entry.searchState, { index: result.resultIndex, count: result.resultCount, found: result.resultCount > 0 });
        if (app.termActive === id) Object.assign(app.termSearch, entry.searchState);
      });
      this.termTabs.push({ id: id, alias: alias, ordinal: ordinal, busy: true, state: "connecting", error: "" });
      if (typeof ResizeObserver !== "undefined") {
        entry.observer = new ResizeObserver(() => { if (app.termActive === id) app.fitActive(); });
        entry.observer.observe(pane);
      }
      term.onData((data) => app.queueTerminalInput(entry, data));
      term.onResize(({ cols, rows }) => app.queueTerminalResize(entry, cols, rows));
      term.attachCustomKeyEventHandler((ev) => app.terminalKey(entry, ev));
      this.showPane(id);
      await this.connectTerm(entry);
    },

    terminalKey(entry, ev) {
      // Let the IME and AltGr finish before interpreting application shortcuts.
      if (ev.isComposing || ev.keyCode === 229 || ev.altKey || ev.type !== "keydown") return true;
      if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey) {
        const key = String(ev.key || "").toLowerCase();
        if (key === "f" || key === "c") {
          ev.preventDefault();
          if (key === "f") this.openTermSearch(); else this.copyTerminal(entry);
          return false;
        }
      }
      return true;
    },

    openTermSearch() {
      const entry = termMap.get(this.termActive);
      if (!entry || !entry.search) return;
      this.termSearch.open = true;
      this.searchTerminal(false, true);
      this.$nextTick(() => { const input = document.getElementById("term-search"); if (input) { input.focus(); input.select(); } });
    },

    searchTerminal(previous, incremental) {
      const entry = termMap.get(this.termActive), text = this.termSearch.text;
      if (!entry || !entry.search) return;
      if (!entry.searchState) entry.searchState = blankSearch();
      if (incremental && entry.searchState.open && entry.searchState.text === text) return;
      Object.assign(entry.searchState, this.termSearch);
      if (!text) {
        entry.search.clearDecorations();
        Object.assign(this.termSearch, { found: true, count: 0, index: -1 });
      } else {
        const options = { incremental: !!incremental, decorations: {
          matchBackground: "#665400", matchBorder: "#bca02b", matchOverviewRuler: "#bca02b",
          activeMatchBackground: "#795b00", activeMatchBorder: "#ffdf70", activeMatchColorOverviewRuler: "#ffdf70"
        } };
        this.termSearch.found = previous ? entry.search.findPrevious(text, options) : entry.search.findNext(text, options);
      }
      Object.assign(entry.searchState, this.termSearch);
    },

    searchTerminalEvent(ev, previous, incremental) {
      if (ev.isComposing || ev.keyCode === 229) return;
      this.searchTerminal(previous, incremental);
    },

    searchResultText() {
      const s = this.termSearch;
      if (!s.text) return "";
      if (!s.found) return "无匹配";
      return (s.index >= 0 ? s.index + 1 : "—") + " / " + s.count + (s.count >= SEARCH_LIMIT ? "+" : "");
    },

    closeTermSearch() {
      this.termSearch.open = false;
      const entry = termMap.get(this.termActive);
      if (entry) {
        Object.assign(entry.searchState || {}, this.termSearch);
        if (entry.search) entry.search.clearDecorations();
        entry.term.focus();
      }
    },

    clearTerminalResize(entry) {
      if (entry.resizeTimer) clearTimeout(entry.resizeTimer);
      entry.resizeTimer = 0; entry.pendingResize = null; entry.lastResize = "";
    },

    queueTerminalResize(entry, cols, rows) {
      entry.pendingResize = { cols: cols, rows: rows };
      if (entry.resizeTimer) return;
      const generation = entry.generation;
      entry.resizeTimer = setTimeout(() => {
        if (generation !== entry.generation || termMap.get(entry.id) !== entry) return;
        entry.resizeTimer = 0;
        const size = entry.pendingResize; entry.pendingResize = null;
        if (!size || termMap.get(entry.id) !== entry || generation !== entry.generation || !entry.ws || entry.ws.readyState !== 1) return;
        const key = size.cols + ":" + size.rows;
        if (entry.lastResize === key) return;
        try { entry.ws.send(JSON.stringify({ type: "resize", cols: size.cols, rows: size.rows })); entry.lastResize = key; }
        catch (err) { /* Socket close is reported by the connection handler. */ }
      }, 40);
    },

    async connectTerm(entry) {
      const app = this, id = entry.id, term = entry.term;
      const generation = ++entry.generation;
      let ws;
      const current = () => termMap.get(id) === entry && entry.generation === generation;
      this.clearTerminalResize(entry);
      entry.ready = false;
      entry.outputAck = false;
      entry.maxLife = false;
      entry.hadError = false;
      entry.wasReady = false;
      term.options.disableStdin = true;
      this.setTabState(id, "connecting");
      this.setTerminalError(id, "");
      try {
        const opened = await this.postJSON("/api/terminal/open", { alias: entry.alias, cols: term.cols || 80, rows: term.rows || 24 });
        if (!current()) return;
        if (!opened.ticket) throw new Error("未收到终端连接凭据，请刷新页面后重试。");
        const proto = location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(proto + "//" + location.host + "/api/terminal/ws?ticket=" + encodeURIComponent(opened.ticket) + "&outputAck=1");
      } catch (err) {
        if (!current()) return;
        this.setTabState(id, "closed");
        this.setTerminalError(id, err.message || "终端连接失败");
        if (this.termActive === id) this.syncWorkspace();
        return;
      }
      ws.binaryType = "arraybuffer";
      entry.ws = ws;
      ws.onmessage = (ev) => {
        if (!current()) return;
        const text = typeof ev.data === "string" ? ev.data : "";
        if (text) {
          let state;
          try { state = JSON.parse(text); } catch (err) { /* Legacy close notices are plain text. */ }
          if (state && state.type === "terminal") {
            if (state.state === "ready") {
              entry.outputAck = state.category === "output_ack";
              entry.ready = true;
              entry.wasReady = true;
              term.options.disableStdin = false;
              app.setTabState(id, "connected");
              app.setTerminalError(id, "");
              if (app.termActive === id) { app.syncWorkspace(); app.fitActive(true); }
            } else if (state.state === "audit_warning") {
              app.noteAudit({ auditWarning: true });
            } else if (state.state === "error") {
              const labels = { auth: "认证失败", connect: "连接失败", timeout: "连接超时", pty: "远端终端启动失败" };
              const message = (labels[state.category] || "终端连接失败") + "：" + String(state.message || "请检查连接").replace(/[\x00-\x1f\x7f-\x9f]/g, " ");
              entry.ready = false;
              term.options.disableStdin = true;
              app.setTabState(id, "closed");
              app.setTerminalError(id, message);
              term.write("\r\n" + message + "\r\n");
              if (app.termActive === id) app.syncWorkspace();
            }
            return;
          }
        }
        if (text.indexOf("已达到最长时限") >= 0) {
          entry.maxLife = true;
          term.write(text);
          app.setTerminalError(id, "会话已达到最长时限，连接已关闭");
          app.toast("会话已达到最长时限，连接已关闭", "bad");
          return;
        }
        app.markTabIdle(id);
        const output = text || new Uint8Array(ev.data);
        if (entry.outputAck && !text) {
          term.write(output, () => {
            if (current() && ws.readyState === 1) ws.send(JSON.stringify({ type: "output_ack", bytes: output.byteLength }));
          });
        } else term.write(output);
      };
      ws.onopen = () => {
        if (current() && ws.readyState === 1) app.queueTerminalResize(entry, term.cols, term.rows);
      };
      ws.onerror = () => {
        if (current()) entry.hadError = true;
      };
      ws.onclose = (ev) => {
        if (!current()) return;
        const wasReady = entry.ready;
        const pendingInput = entry.inputBytes > 0 || ws.bufferedAmount > 0;
        entry.ready = false;
        term.options.disableStdin = true;
        app.clearTerminalInput(entry);
        app.clearTerminalResize(entry);
        app.setTabState(id, entry.maxLife ? "expired" : "closed");
        if (app.termActive === id) app.syncWorkspace();
        if (entry.maxLife) return;
        const tab = app.termTabs.find((t) => t.id === id);
        if (tab && tab.error) return;
        let message = wasReady ? "终端连接已断开 (" + ev.code + ")；重新连接会启动新的 shell。" : "终端连接失败，远端终端尚未就绪。";
        if (pendingInput) message += " 未发送输入已丢弃，部分内容可能已到达远端，请核验；不会自动重发。";
        app.setTerminalError(id, message);
        term.write("\r\n" + message + "\r\n");
      };
    },

    setTerminalError(id, message) {
      this.termTabs = this.termTabs.map((tab) => tab.id === id ? Object.assign({}, tab, { error: message, failed: tab.state === "closed" ? (!entryReady(tab.id) || tab.failed) : tab.failed }) : tab);
    },

    terminalError() {
      const tab = this.termTabs.find((t) => t.id === this.termActive);
      return (tab && tab.error) || this.errors.terminal || "";
    },

    terminalTabLabel(tab) {
      return tab.alias + " · " + (tab.ordinal || 1);
    },

    async copyTerminal(entry) {
      entry = entry || termMap.get(this.termActive);
      if (!entry || !entry.term.hasSelection()) return;
      try { await navigator.clipboard.writeText(entry.term.getSelection()); }
      catch (err) { this.toast("复制失败，请检查浏览器剪贴板权限。", "bad"); }
    },

    queueTerminalInput(entry, text) {
      if (!entry.ready || !entry.ws || entry.ws.readyState !== 1) return;
      // Reject oversized input before sending any part of this command.
      if (!text) return;
      // Encode once: the byte limit and chunk sender use the same representation.
      const bytes = inputEncoder.encode(text);
      const size = bytes.length;
      if (size + entry.inputBytes + entry.ws.bufferedAmount > TERM_INPUT_LIMIT) {
        this.toast("待发送内容超过 4 MiB，本次输入未发送，请使用文件上传。", "bad");
        return;
      }
      entry.input.push({ bytes: bytes, offset: 0 });
      entry.inputBytes += bytes.length;
      this.flushTerminalInput(entry);
    },

    flushTerminalInput(entry) {
      if (entry.inputTimer) return;
      if (!entry.ready || !entry.ws || entry.ws.readyState !== 1 || termMap.get(entry.id) !== entry) { this.clearTerminalInput(entry); return; }
      let chunks = 0;
      try {
        while (entry.input.length && entry.ws.bufferedAmount < (128 << 10) && chunks++ < 8) {
          const item = entry.input[0], end = Math.min(item.bytes.length, item.offset + TERM_CHUNK);
          entry.ws.send(item.bytes.subarray(item.offset, end));
          entry.inputBytes -= end - item.offset;
          item.offset = end;
          if (end === item.bytes.length) entry.input.shift();
        }
      } catch (err) {
        this.clearTerminalInput(entry);
        this.setTerminalError(entry.id, "输入发送中断，部分内容可能已到达远端。请核验，不会自动重发。");
        entry.ws.close();
        return;
      }
      if (entry.input.length) entry.inputTimer = setTimeout(() => { entry.inputTimer = 0; this.flushTerminalInput(entry); }, 16);
    },

    clearTerminalInput(entry) {
      if (entry.inputTimer) clearTimeout(entry.inputTimer);
      entry.inputTimer = 0; entry.input = []; entry.inputBytes = 0;
    },

    changeTermFont(delta) {
      this.termFontSize = Math.max(12, Math.min(22, this.termFontSize + delta));
      termMap.forEach((entry) => { entry.term.options.fontSize = this.termFontSize; });
      this.savePrefs({ termFontSize: this.termFontSize });
      this.fitActive();
    },

    toggleFiles() {
      this.filesCollapsed = !this.filesCollapsed;
      this.savePrefs({ filesCollapsed: this.filesCollapsed });
      this.fitActive();
    },

    showPane(id, focus) {
      const previous = termMap.get(this.termActive), next = termMap.get(id);
      if (previous && previous.searchState) Object.assign(previous.searchState, this.termSearch);
      this.termSearch = Object.assign(blankSearch(), next && next.searchState);
      this.termActive = id;
      this.setError("terminal", "");
      termMap.forEach((entry) => {
        entry.pane.classList.toggle("active", entry.id === id);
      });
      this.fitActive(focus !== false);
      this.syncWorkspace();
      const reveal = () => {
        const tab = document.querySelector && document.querySelector(".term-tab.active");
        if (tab) tab.scrollIntoView({ block: "nearest", inline: "nearest" });
      };
      if (this.$nextTick) this.$nextTick(reveal);
    },

    terminalTabKey(ev) {
      if (ev.isComposing || ev.ctrlKey || ev.metaKey || ev.altKey || !ev.target.closest("[role='tab']")) return;
      const tabs = this.termTabs, index = tabs.findIndex((t) => t.id === this.termActive);
      if (!tabs.length || index < 0) return;
      let next;
      if (ev.key === "Delete") { ev.preventDefault(); this.closeTab(tabs[index].id, true); return; }
      if (ev.key === "ArrowRight") next = (index + 1) % tabs.length;
      else if (ev.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
      else if (ev.key === "Home") next = 0;
      else if (ev.key === "End") next = tabs.length - 1;
      else return;
      ev.preventDefault();
      this.showPane(tabs[next].id, false);
      const focus = () => { const el = document.getElementById("tab-" + tabs[next].id); if (el) el.focus(); };
      if (this.$nextTick) this.$nextTick(focus); else focus();
    },

    fitActive(focus) {
      const entry = termMap.get(this.termActive);
      if (!entry) return;
      entry.focusAfterFit = focus === false ? false : (entry.focusAfterFit || !!focus);
      if (entry.fitTimer) clearTimeout(entry.fitTimer);
      entry.fitTimer = setTimeout(() => {
        entry.fitTimer = 0;
        if (termMap.get(entry.id) !== entry || this.view !== "terminal" || !entry.pane.classList.contains("active") || !entry.pane.clientWidth || !entry.pane.clientHeight) return;
        const size = entry.fit.proposeDimensions ? entry.fit.proposeDimensions() : null;
        if (!size || size.cols !== entry.term.cols || size.rows !== entry.term.rows) entry.fit.fit();
        const active = document.activeElement;
        if (entry.focusAfterFit && !this.anyDialog() && entry.ready && (!active || !active.matches("input,textarea,select,[contenteditable='true']") || entry.pane.contains(active))) entry.term.focus();
        entry.focusAfterFit = false;
      }, 30);
    },

    closeTab(id, focusTab) {
      const index = this.termTabs.findIndex((tab) => tab.id === id);
      const entry = termMap.get(id);
      if (entry) {
        entry.generation++;
        entry.ready = false;
        this.clearTerminalInput(entry);
        this.clearTerminalResize(entry);
        if (entry.searchResults) entry.searchResults.dispose();
        if (entry.fitTimer) clearTimeout(entry.fitTimer);
        if (entry.observer) entry.observer.disconnect();
        if (entry.ws) {
          entry.ws.onclose = entry.ws.onmessage = entry.ws.onopen = entry.ws.onerror = null;
          try { entry.ws.close(); } catch (err) { /* already closed */ }
        }
        entry.term.dispose();
        entry.pane.remove();
        termMap.delete(id);
      }
      this.termTabs = this.termTabs.filter((tab) => tab.id !== id);
      if (this.termActive === id) {
        const next = this.termTabs[Math.min(Math.max(0, index), this.termTabs.length - 1)];
        if (next) this.showPane(next.id, !focusTab);
        else { this.termActive = ""; this.termSearch = blankSearch(); this.syncWorkspace(); }
      }
      if (focusTab && this.$nextTick) this.$nextTick(() => {
        const el = document.getElementById("tab-" + this.termActive);
        if (el) el.focus();
      });
    },

    scrollTerminalTabs(ev) {
      const el = ev.currentTarget;
      if (ev.ctrlKey || ev.metaKey || ev.altKey || el.scrollWidth <= el.clientWidth || Math.abs(ev.deltaY) <= Math.abs(ev.deltaX)) return;
      ev.preventDefault(); el.scrollLeft += ev.deltaY * (ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? el.clientWidth : 1);
    },

    tabAlias() {
      const tabs = this.termTabs || [];
      for (let i = 0; i < tabs.length; i++) {
        if (tabs[i].id === this.termActive) return tabs[i].alias;
      }
      return "";
    },

    panelAlias() {
      return this.tabAlias() || this.termAlias || "";
    },

    liveAlias() {
      const tab = this.termTabs.find((item) => item.id === this.termActive);
      if (tab) return tab.state === "connected" ? tab.alias : "";
      if (this.explicitAlias && this.explicitAlias === (this.termAlias || "")) return this.explicitAlias;
      return "";
    },

    setTabState(id, state) {
      this.termTabs = this.termTabs.map((tab) => tab.id === id ? Object.assign({}, tab, { state: state, busy: false, failed: state === "connecting" || state === "connected" ? false : tab.failed }) : tab);
    },

    terminalTabState(tab) {
      return tab ? ({ connecting: "连接中", connected: "已连接", closed: tab.failed ? "连接失败" : "已断开", expired: "已到期" }[tab.state] || "已断开") : "未连接";
    },

    terminalState() { return this.terminalTabState(this.termTabs.find((item) => item.id === this.termActive)); },

    canReconnectTerminal() {
      const tab = this.termTabs.find((item) => item.id === this.termActive);
      return !!tab && (tab.state === "closed" || tab.state === "expired");
    },

    async reconnectTerminal() {
      const entry = termMap.get(this.termActive);
      const tab = this.termTabs.find((t) => t.id === this.termActive);
      if (!entry || !tab || tab.state === "connecting" || tab.state === "connected" || this.termOpening) return;
      this.termOpening = true;
      this.clearTerminalInput(entry);
      if (entry.ws) { entry.generation++; entry.ws.close(); }
      // Leave full-screen modes and soft-reset terminal modes without clearing scrollback.
      // Preserve an alternate-screen application's last visible frame as plain text.
      const buffer = entry.term.buffer && entry.term.buffer.active;
      let snapshot = "";
      if (buffer && buffer.type === "alternate") {
        const lines = [];
        for (let i = 0; i < Math.min(entry.term.rows, 500); i++) {
          const line = buffer.getLine(i);
          lines.push(line ? line.translateToString(true) : "");
        }
        snapshot = "\r\n── 断线前的全屏画面（纯文本） ──\r\n" + lines.join("\r\n");
      }
      entry.term.write("\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[!p" + snapshot + "\r\n── 重新连接：新的 shell，之前的命令不会重发 ──\r\n");
      try { await this.connectTerm(entry); } finally { this.termOpening = false; }
    },

    selectPanel(name) { this.panel = name; this.fitActive(name === "terminal"); },

    rememberFileScroll() {
      if (!document.querySelector) return;
      for (const [key, selector] of [["list", ".ws-table-wrap"], ["tree", ".ws-tree"], ["history", ".ws-history"]]) {
        const el = document.querySelector(selector);
        if (el && el.clientHeight) this.fileScroll[key] = el.scrollTop;
      }
    },

    restoreFileScroll(scroll, immediate) {
      if (!document.querySelector) return;
      const seq = this.filesReadSeq;
      const apply = () => {
        if (seq !== this.filesReadSeq) return;
        for (const [key, selector] of [["list", ".ws-table-wrap"], ["tree", ".ws-tree"], ["history", ".ws-history"]]) {
          const el = document.querySelector(selector);
          if (el) el.scrollTop = scroll[key] || 0;
        }
      };
      if (this.$nextTick && !immediate) this.$nextTick(apply);
      else apply();
    },

    rememberWorkspace() {
      if (!this.files.alias) return;
      this.rememberFileScroll();
      delete this.workspaceCache[this.files.alias];
      this.workspaceCache[this.files.alias] = { files: Object.assign({}, this.files), tree: this.tree, root: this.treeRoot, draft: this.pathDraft, selected: this.selectedPath, scroll: Object.assign({}, this.fileScroll) };
      const keys = Object.keys(this.workspaceCache);
      const cost = (saved) => (saved.files.entries || []).length + Object.values(saved.tree).reduce((n, node) => n + (node.dirs || []).length, 0);
      let total = keys.reduce((n, key) => n + cost(this.workspaceCache[key]), 0);
      while (keys.length > 1 && (keys.length > 8 || total > 16000)) {
        const key = keys.shift(); total -= cost(this.workspaceCache[key]); delete this.workspaceCache[key];
      }
    },

    workspaceLive() {
      return !!this.liveAlias();
    },

    activeTermAlias() {
      return this.panelAlias();
    },

    onTermHost() {
      if (this.tabAlias()) return;
      if (this.explicitAlias && this.explicitAlias !== this.termAlias) this.explicitAlias = "";
      this.syncWorkspace();
    },

    clearLivePanes() {
      this.rememberWorkspace();
      this.workspaceSeq++;
      this._rootLoad = null;
      this.stopMetrics();
      this.abortRead("files");
      this.metricsSeq++;
      this.metrics = blankMetrics();
      this.metricsUpdated = 0;
      this.setError("metrics", "");
      this.setError("files", "");
      this.files.alias = "";
      this.files.path = "";
      this.files.parent = "";
      this.files.crumbs = [];
      this.files.entries = [];
      this.files.truncated = false;
      this.files.home = "";
      this.tree = {};
      this.treeRoot = "";
      this.selectedPath = "";
      this.fileScroll = { list: 0, tree: 0, history: 0 };
      destroyNetChart();
      if (!this.pathFocused) this.pathDraft = "";
      this.pathError = "";
      this.historyView = { alias: "", found: false, status: "", path: "", shell: "", lines: [], notes: [], truncated: false, error: "", suppressed: false };
      this.netSeries = {};
    },

    hostByAlias(alias) {
      const hosts = (this.catalog && this.catalog.hosts) || [];
      for (let i = 0; i < hosts.length; i++) {
        if (hosts[i].alias === alias) return hosts[i];
      }
      return null;
    },

    terminalBlocked(alias) {
      const host = this.hostByAlias(alias);
      return !!host && host.terminalAllowed === false;
    },

    terminalIdentity() {
      const host = this.hostByAlias(this.panelAlias());
      return host ? host.alias + " · " + host.env : "未选择主机";
    },

    terminalStatusLine() {
      const alias = this.panelAlias();
      if (!alias) return "未选择主机";
      return this.terminalIdentity() + " · " + this.overviewAddr() + " · " + this.terminalState();
    },

    workspaceGrid() {
      const side = Math.max(220, Math.min(460, Number(this.ws && this.ws.side) || 280));
      const saved = Number(this.ws && this.ws.lower);
      const lower = saved ? Math.max(160, Math.min(4096, saved)) + "px" : "33.333vh";
      return "--ws-side:" + side + "px;--ws-lower:min(" + lower + ", max(160px, calc(100vh - 180px)))";
    },

    overviewAddr() {
      const alias = this.panelAlias();
      const live = this.workspaceLive() && this.metrics && this.metrics.alias === alias ? this.metrics : null;
      if (live && live.address) return live.user + "@" + live.address + ":" + live.port;
      const h = this.hostByAlias(alias);
      if (!h) return "选择主机后显示地址";
      return (h.user || "") + "@" + (h.host || "") + ":" + (h.port || "");
    },

    overviewTitle() {
      const alias = this.panelAlias();
      const live = this.metrics && alias && this.metrics.alias === alias ? this.metrics : null;
      return (live && live.hostname) || "—";
    },

    overviewStatus() {
      const alias = this.panelAlias();
      const tab = this.termTabs.find((item) => item.id === this.termActive);
      if (tab) {
          const label = tab.state === "connected" ? "在线" : this.terminalTabState(tab);
        if (label) return label;
      }
      const live = this.metrics && alias && this.metrics.alias === alias ? this.metrics : null;
      if (alias && this.workspaceClosedAlias === alias && !this.workspaceLive()) return "已断开";
      if (live && live.connected && !this.errors.metrics) return "在线";
      if (this.errors.metrics) return "状态待确认";
      if (this.metricsPending()) return "连接中";
      return "未连接";
    },

    overviewStatusClass() {
      return { "在线": "is-online", "连接中": "is-connecting", "状态待确认": "is-connecting", "连接失败": "is-closed", "已断开": "is-closed", "已到期": "is-closed" }[this.overviewStatus()] || "";
    },

    overviewIP() {
      const alias = this.panelAlias();
      const live = this.metrics && alias && this.metrics.alias === alias ? this.metrics : null;
      if (live && live.address) return String(live.address);
      const host = this.hostByAlias(alias);
      return host && host.host ? String(host.host) : "";
    },

    async copyOverviewIP() {
      const ip = this.overviewIP();
      if (!ip) return;
      const clip = typeof navigator !== "undefined" && navigator.clipboard ? navigator.clipboard : null;
      try {
        if (!clip || !clip.writeText) throw new Error("clipboard");
        await clip.writeText(ip);
        this.toast("已复制 " + ip);
      } catch (err) {
        this.toast(ip);
      }
    },

    viaOf(alias) {
      const h = this.hostByAlias(alias);
      if (!h || !h.via) return "";
      return "经由 " + h.via;
    },

    jumpChoices() {
      const self = this.hostForm && this.hostForm.alias;
      return this.sortedHosts().filter((h) => h.alias && h.alias !== self);
    },

    sideStyle() { return "width:" + this.ws.side + "px"; },
    beginSplit(which, ev) {
      if (this._endSplit) this._endSplit();
      const startX = ev.clientX;
      const startY = ev.clientY;
      const baseSide = this.ws.side;
      const pane = document.querySelector(".ws-lower");
      const baseLower = pane ? pane.getBoundingClientRect().height : (this.ws.lower || window.innerHeight / 3);
      const app = this;
      let pending, frame = 0;
      const apply = () => {
        frame = 0;
        const e = pending; pending = null;
        if (!e) return;
        if (which === "side") {
          app.ws.side = Math.max(220, Math.min(460, baseSide + (e.clientX - startX)));
        } else {
          const limit = Math.max(160, window.innerHeight - 180);
          app.ws.lower = Math.max(160, Math.min(limit, baseLower - (e.clientY - startY)));
        }
      };
      const move = (e) => {
        pending = { clientX: e.clientX, clientY: e.clientY };
        if (!frame) frame = window.requestAnimationFrame(apply);
      };
      const prevCursor = document.body.style.cursor;
      const prevSelect = document.body.style.userSelect;
      document.body.style.cursor = which === "side" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";
      const up = () => {
        if (frame) window.cancelAnimationFrame(frame);
        apply(); app._endSplit = null;
        window.removeEventListener("blur", up);
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
        document.body.style.cursor = prevCursor;
        document.body.style.userSelect = prevSelect;
        app.saveSplit();
        app.fitActive();
      };
      this._endSplit = up;
      window.addEventListener("blur", up);
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    },

    saveSplit() {
      this.savePrefs({ wsSide: this.ws.side, wsLower: this.ws.lower });
    },

    syncWorkspace() {
      const alias = this.liveAlias();
      if (!alias) {
        this.clearLivePanes();
        return;
      }
      if (this.files.alias !== alias) {
        this.rememberWorkspace();
        this.workspaceSeq++;
        this._rootLoad = null;
        this.stopMetrics();
        destroyNetChart();
        this.metrics = blankMetrics();
        this.metricsUpdated = 0;
        this.metricsFailures = 0;
        this.setError("metrics", "");
        this.setError("files", "");
        this.abortRead("files");
        this.files.alias = alias;
        this.files.path = "";
        this.files.parent = "";
        this.files.crumbs = [];
        this.files.entries = [];
        this.files.truncated = false;
        this.files.home = "";
        this.tree = {};
        this.treeRoot = "";
        this.selectedPath = "";
        this.fileScroll = { list: 0, tree: 0, history: 0 };
        const saved = this.workspaceCache[alias];
        if (saved) {
          this.files = Object.assign({}, saved.files);
          this.tree = saved.tree;
          this.treeRoot = saved.root;
          this.pathDraft = saved.draft;
          this.selectedPath = saved.selected || "";
          this.fileScroll = Object.assign({ list: 0, tree: 0, history: 0 }, saved.scroll);
        }
        const epoch = this.workspaceSeq;
        const scroll = Object.assign({}, this.fileScroll);
        const refresh = () => {
          if (epoch !== this.workspaceSeq) return;
          this.restoreFileScroll(scroll, true);
          if (this.files.mode !== "history") this.refreshFiles();
        };
        if (this.$nextTick) this.$nextTick(refresh);
        else refresh();
      }
      if (this.files.mode === "history" && this.historyView.alias !== alias) this.loadHistory(alias);
      this.startMetrics();
    },

    startMetrics() {
      if (document.hidden || this.view !== "terminal" || !this.liveAlias()) return;
      if (this.metricsBusy === this.liveAlias() || this.metricsTimer) return;
      this.refreshMetrics();
    },

    stopMetrics() {
      this.metricsSeq++;
      this.metricsBusy = "";
      this.abortRead("metrics");
      if (this.metricsTimer) {
        window.clearTimeout(this.metricsTimer);
        this.metricsTimer = 0;
      }
    },

    async refreshMetrics() {
      const alias = this.liveAlias();
      if (!alias || this.view !== "terminal" || document.hidden || this.metricsBusy === alias) return;
      this.metricsBusy = alias;
      const seq = ++this.metricsSeq;
      const signal = this.replaceRead("metrics");
      try {
        const data = await this.postRead("/api/metrics", { alias: alias }, signal);
        if (seq !== this.metricsSeq || this.liveAlias() !== alias) return;
        data.procs = data.procs || [];
        data.disks = data.disks || [];
        data.notes = data.notes || [];
        this.metrics = data;
        this.metricsUpdated = Date.now();
        this.metricsClock = this.metricsUpdated;
        this.metricsFailures = 0;
        this.pushNet(alias, data);
        this.setError("metrics", "");
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (seq !== this.metricsSeq) return;
        this.metricsFailures++;
        this.pushNet(alias, { connected: false });
        this.setError("metrics", err.message || "概况暂时不可用");
      } finally {
        if (seq === this.metricsSeq) {
          this.metricsBusy = "";
          if (this.view === "terminal" && !document.hidden && this.liveAlias() === alias) {
            this.metricsTimer = window.setTimeout(() => {
              this.metricsTimer = 0;
              this.refreshMetrics();
              this.loadSessions();
            }, Math.min(30000, 5000 * Math.pow(2, Math.min(this.metricsFailures, 3))));
          }
        }
      }
    },

    pushNet(alias, data) {
      const now = Date.now();
      if (!this.netSeries[alias]) this.netSeries[alias] = [];
      const series = this.netSeries[alias];
      const unavailable = !data.connected || data.netSampled === false || (data.notes || []).some((note) => /^net:/.test(note));
      const rate = (value) => !unavailable && Number.isFinite(value) && value >= 0 ? value : null;
      const point = { t: now, rxRate: rate(data.netRxRate), txRate: rate(data.netTxRate) };
      series.push(point);
      if (series.length > 24) series.shift();
      paintNetChart(series);
    },

    netRateText(direction) {
      const alias = this.liveAlias();
      if (!alias || this.metrics.alias !== alias || this.errors.metrics) return "—";
      const series = this.netSeries[alias] || [];
      const last = series[series.length - 1];
      const rate = last && last[direction === "tx" ? "txRate" : "rxRate"];
      return rate == null ? "—" : this.formatBytes(rate) + "/s";
    },

    metricsCaption() {
      if (!this.workspaceLive() || !this.metricsUpdated) return this.errors.metrics ? "监控暂不可用" : "";
      const seconds = Math.max(0, Math.floor((this.metricsClock - this.metricsUpdated) / 1000));
      const stale = !!this.errors.metrics || seconds > 15;
      return (stale ? "监控未更新 · " : "监控更新于 ") + (seconds < 1 ? "刚刚" : seconds + " 秒前");
    },

    pct(n) {
      if (n == null || n === "") return "—";
      const v = Number(n);
      if (!isFinite(v)) return "—";
      return Math.round(v) + "%";
    },

    memPct(mem) {
      if (!mem || mem.percent == null) return null;
      return mem.percent;
    },

    memText(mem) {
      if (!mem || !mem.total) return "—";
      return this.pct(mem.percent) + " · " + this.formatBytes(mem.used) + " / " + this.formatBytes(mem.total);
    },

    uptimeText() {
      return chineseUptime(this.metrics && this.metrics.uptime);
    },

    procMem(p) {
      if (!p || p.rss == null || p.rss === "") return "—";
      const kb = Number(p.rss);
      if (!isFinite(kb) || kb < 0) return "—";
      return formatKB(kb);
    },

    procCpu(p) {
      const n = Number(p && p.cpu);
      if (!isFinite(n)) return "—";
      const shown = Math.round(n * 10) / 10;
      const text = (shown % 1 === 0) ? String(shown) : shown.toFixed(1);
      return text + "%";
    },

    sortProcs(key) {
      if (this.procSort.key === key) this.procSort.dir = this.procSort.dir === "asc" ? "desc" : "asc";
      else this.procSort = { key: key, dir: key === "comm" ? "asc" : "desc" };
    },

    sortedProcs() {
      const rows = ((this.metrics && this.metrics.procs) || []).slice();
      const key = (this.procSort && this.procSort.key) || "cpu";
      const dir = this.procSort && this.procSort.dir === "asc" ? 1 : -1;
      rows.sort((a, b) => {
        if (key === "comm") return String(a.comm || "").localeCompare(String(b.comm || "")) * dir;
        const av = key === "mem" ? (Number(a.rss) || 0) : (Number(a.cpu) || 0);
        const bv = key === "mem" ? (Number(b.rss) || 0) : (Number(b.cpu) || 0);
        return (av - bv) * dir;
      });
      return rows.slice(0, 5);
    },

    procRows() {
      const rows = this.sortedProcs();
      const out = [];
      for (let i = 0; i < rows.length && out.length < 5; i++) out.push(rows[i]);
      while (out.length < 5) out.push({ empty: true, pid: "pad-" + out.length });
      return out;
    },

    openProcRow(p) {
      if (!p || p.empty) return;
      return this.openProc(p);
    },

    diskMountLabel(mount) {
      let m = String(mount || "").trim();
      if (!m) return "";
      while (m.length > 1 && m.endsWith("/")) m = m.slice(0, -1);
      return m;
    },

    visibleDisks() {
      const disks = (this.metrics && this.metrics.disks) || [];
      return disks.filter((d) => this.diskMountLabel(d && d.mount) === "/");
    },

    diskMeters() {
      const disks = this.visibleDisks();
      if (disks.length) return disks;
      return [{ mount: "/", percent: "", used: "", size: "" }];
    },

    procShort(p) {
      const raw = String((p && (p.comm || p.args)) || "").trim();
      const token = raw.split(/\s+/)[0] || "";
      if (!token) return "—";
      const slash = Math.max(token.lastIndexOf("/"), token.lastIndexOf("\\"));
      const base = slash >= 0 ? token.slice(slash + 1) : token;
      return base || "—";
    },

    diskPct(text) {
      const n = parseInt(String(text || ""), 10);
      return isFinite(n) ? n : null;
    },

    diskBytes(text, bytes) {
      if (bytes != null && bytes !== "" && isFinite(Number(bytes))) return Number(bytes);
      const raw = String(text == null ? "" : text).trim();
      if (!raw) return null;
      const n = Number(raw);
      if (!isFinite(n) || n < 0) return null;
      return n * 1024;
    },

    diskText(d) {
      if (!d) return "—";
      const pct = this.pct(this.diskPct(d.percent));
      const used = this.diskBytes(d.used, d.usedBytes);
      const total = this.diskBytes(d.size, d.sizeBytes);
      if (used == null || total == null) return pct;
      return pct + " · " + this.formatBytes(used) + " / " + this.formatBytes(total);
    },

    diskEmpty() { return this.visibleDisks().length === 0; },
    procEmpty() { return !this.metrics || !this.metrics.procs || this.metrics.procs.length === 0; },
    metricsPending() {
      return this.workspaceLive() && !(this.errors && this.errors.metrics) && !(this.metrics && this.metrics.connected);
    },

    noteText() {
      const notes = (this.metrics && this.metrics.notes) || [];
      return notes.length ? notes.join("；") : "";
    },

    netText() {
      const m = this.metrics || {};
      const alias = this.liveAlias();
      const series = (this.netSeries && this.netSeries[alias]) || [];
      const last = series.length ? series[series.length - 1] : null;
      let rate = "";
      if (last && (last.rxRate || last.txRate)) {
        rate = " · 收 " + this.formatBytes(last.rxRate) + "/s · 发 " + this.formatBytes(last.txRate) + "/s";
      }
      return "累计收 " + this.formatBytes(m.netRx) + " · 发 " + this.formatBytes(m.netTx) + rate;
    },

    procCmd(p) {
      if (!p) return "";
      return p.args || p.comm || "";
    },

    procState(stat) {
      const s = String(stat || "");
      if (!s) return "—";
      const gloss = { R: "运行", S: "睡眠", D: "不可中断", T: "停止", Z: "僵尸", I: "空闲", t: "跟踪停止" }[s.charAt(0)] || "";
      return gloss ? (s + " · " + gloss) : s;
    },

    procMemText() {
      const v = this.procView || {};
      const bits = [];
      if (v.mem) bits.push(v.mem);
      if (v.memPct) bits.push(v.memPct + "%");
      return bits.length ? bits.join(" · ") : "—";
    },

    async openProc(p) {
      if (!p) return;
      const pid = String(p.pid || "");
      this.procView = {
        pid: pid,
        ppid: p.ppid || "",
        user: p.user || "",
        cpu: this.procCpu(p),
        mem: this.procMem(p),
        memPct: p.mem || "",
        stat: p.stat || "",
        etime: p.etime || p.start || "",
        cmd: this.procCmd(p),
        cwd: "",
        cwdNote: ""
      };
      this.openDialog("proc");
      const alias = this.liveAlias();
      if (!alias || !/^\d+$/.test(pid)) {
        this.procView.cwdNote = "没有可用的工作目录";
        return;
      }
      try {
        const data = await this.postJSON("/api/metrics/proc", { alias: alias, pid: pid });
        if (!this.procView || this.procView.pid !== pid) return;
        if (data.args) this.procView.cmd = data.args;
        this.procView.cwd = data.cwd || "";
        this.procView.cwdNote = data.cwd ? "" : (data.note || "读不到工作目录");
      } catch (err) {
        if (this.procView && this.procView.pid === pid) this.procView.cwdNote = err.message || "读不到工作目录";
      }
    },

    formatBytes(n) {
      n = Number(n);
      if (!isFinite(n) || n < 0) n = 0;
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i++;
      }
      const shown = i === 0 ? String(Math.round(n)) : n.toFixed(1);
      return shown + " " + units[i];
    },

    barStyle(n) {
      let v = Number(n);
      if (!isFinite(v) || v < 0) v = 0;
      if (v > 100) v = 100;
      return "width:" + v + "%";
    },

    showFiles() {
      this.rememberFileScroll();
      this.abortRead("files");
      this.files.mode = "files";
      this.setError("files", "");
      if (this.liveAlias() && !this.files.path) this.refreshFiles();
      this.restoreFileScroll(Object.assign({}, this.fileScroll));
    },

    showHistory() {
      this.rememberFileScroll();
      this.files.mode = "history";
      this.setError("files", "");
      if (this.liveAlias()) this.loadHistory(this.liveAlias());
    },

    async openHistory(alias) {
      const name = alias || this.termAlias;
      this.files.mode = "history";
      this.termAlias = name;
      this.explicitAlias = name;
      this.show("terminal");
      await this.loadHistory(name);
    },

    async refreshFiles() {
      this.menu.open = false;
      const alias = this.liveAlias();
      if (!alias) {
        this.setError("files", "先打开终端或点「连接」。");
        return;
      }
      await this.listFiles(this.files.alias === alias && this.files.path ? this.files.path : ".");
    },

    cancelPathEdit(ev) {
      if (ev.isComposing || ev.keyCode === 229) return;
      ev.preventDefault(); this.pathDraft = this.files.path; this.pathError = "";
      ev.target.blur();
    },

    fileListKey(ev) {
      if (ev.target !== ev.currentTarget || ev.isComposing || ev.keyCode === 229 || ev.ctrlKey || ev.metaKey || ev.shiftKey || this.filesLoading || this.fileBusy) return;
      if (ev.key === "Backspace" && !ev.altKey || ev.altKey && ev.key === "ArrowUp") {
        ev.preventDefault(); if (this.files.parent) this.listFiles(this.files.parent); return;
      }
      if (ev.altKey) return;
      const entries = this.files.entries || [], index = entries.findIndex((e) => e.path === this.selectedPath);
      if (ev.key === "Enter") { if (index >= 0) { ev.preventDefault(); this.openEntry(entries[index]); } return; }
      let next;
      if (ev.key === "ArrowDown") next = Math.min(entries.length - 1, index + 1);
      else if (ev.key === "ArrowUp") next = index < 0 ? entries.length - 1 : Math.max(0, index - 1);
      else if (ev.key === "Home") next = 0;
      else if (ev.key === "End") next = entries.length - 1;
      else return;
      ev.preventDefault();
      if (entries[next]) {
        this.selectEntry(entries[next]);
        const list = ev.currentTarget;
        if (this.$nextTick) this.$nextTick(() => {
          const row = list.querySelector(".is-selected");
          if (row) row.scrollIntoView({ block: "nearest" });
        });
      }
    },

    fileRowClick(ev, entry) {
      this.selectEntry(entry);
      const list = ev.currentTarget.closest(".ws-table-wrap");
      if (list) list.focus({ preventScroll: true });
    },

    async jumpPath(ev) {
      if (ev && (ev.isComposing || ev.keyCode === 229)) return;
      const norm = normalizeRemotePath(this.files.path, this.pathDraft);
      if (norm.error) {
        this.pathError = norm.error;
        return;
      }
      this.pathError = "";
      this.pathDraft = norm.path;
      await this.listFiles(norm.path);
    },

    async listFiles(path) {
      const alias = this.liveAlias();
      if (!alias) {
        this.setError("files", "先打开终端或点「连接」。");
        return;
      }
      this.setError("files", "");
      const signal = this.replaceRead("files");
      const seq = this.filesReadSeq;
      const previousPath = this.files.path;
      const selected = this.selectedPath;
      this.rememberFileScroll();
      const scroll = Object.assign({}, this.fileScroll);
      this.filesLoading = true;
      this.filesPendingPath = path || ".";
      try {
        const data = await this.postRead("/api/files/list", { alias: alias, path: path || "." }, signal);
        if (seq !== this.filesReadSeq || this.liveAlias() !== alias) return;
        this.files.alias = alias;
        this.files.path = data.path || "";
        this.files.parent = data.parent || "";
        this.files.crumbs = data.crumbs || [];
        this.files.entries = data.entries || [];
        this.files.truncated = !!data.truncated;
        if (data.home) this.files.home = data.home;
        if (!this.pathFocused) this.pathDraft = this.files.path;
        this.pathError = "";
        this.selectedPath = previousPath === this.files.path && this.files.entries.some((e) => e.path === selected) ? selected : "";
        this.fileScroll.list = previousPath === this.files.path ? scroll.list : 0;
        this.restoreFileScroll(Object.assign({}, this.fileScroll));
        this.noteTree(this.files.path, this.files.entries);
        this.filesLoading = false;
        if ((this.files.path || "") !== "/") await this.ensureFsRoot();
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (seq !== this.filesReadSeq || this.liveAlias() !== alias) return;
        const msg = err.message || "列目录失败";
        this.setError("files", msg);
        if (msg.indexOf("不存在") >= 0 || msg.indexOf("not exist") >= 0 || msg.indexOf("no such file") >= 0) this.pathError = msg.indexOf("目录不存在") >= 0 ? msg : "目录不存在。";
      } finally {
        if (seq === this.filesReadSeq) this.filesLoading = false;
      }
    },

    treeLabel(path) {
      const p = String(path || "");
      if (!p || p === "/") return "/";
      const cut = p.lastIndexOf("/");
      const base = cut >= 0 ? p.slice(cut + 1) : p;
      return base || "/";
    },

    noteTree(abs, entries) {
      let path = String(abs || "");
      if (!path) return;
      if (path.charAt(0) !== "/") path = "/" + path;
      // FinalShell-style tree: always anchored at /, labels are basenames.
      const anchor = "/";
      this.treeRoot = anchor;
      if (!this.tree[anchor]) this.tree[anchor] = { name: "/", open: true, loaded: false, dirs: [] };
      else this.tree[anchor].name = "/";
      if (path !== anchor) {
        const parts = path.split("/").filter(Boolean);
        let parent = anchor;
        for (let i = 0; i < parts.length; i++) {
          const cur = parent === "/" ? "/" + parts[i] : parent + "/" + parts[i];
          if (!this.tree[parent]) this.tree[parent] = { name: this.treeLabel(parent), open: true, loaded: false, dirs: [] };
          this.tree[parent].open = true;
          this.tree[parent].name = this.treeLabel(parent);
          const dirs = this.tree[parent].dirs || [];
          let seen = false;
          for (let j = 0; j < dirs.length; j++) {
            if (dirs[j].path === cur) { dirs[j].name = parts[i]; seen = true; }
          }
          if (!seen) dirs.push({ name: parts[i], path: cur });
          this.tree[parent].dirs = dirs;
          if (!this.tree[cur]) this.tree[cur] = { name: parts[i], open: false, loaded: false, dirs: [] };
          else this.tree[cur].name = parts[i];
          parent = cur;
        }
      }
      const node = this.tree[path] || { name: this.treeLabel(path), open: true, loaded: false, dirs: [] };
      node.open = true;
      node.loaded = true;
      node.name = this.treeLabel(path);
      node.used = ++this.treeClock;
      node.dirs = [];
      const list = entries || [];
      for (let i = 0; i < list.length; i++) {
        if (!list[i].dir) continue;
        const child = String(list[i].path || "");
        const base = this.treeLabel(child || list[i].name);
        node.dirs.push({ name: base, path: child });
        if (this.tree[child]) this.tree[child].name = base;
      }
      this.tree[path] = node;
      this.pruneTree();
      this.tree = Object.assign({}, this.tree);
    },

    pruneTree() {
      const current = this.files.path || "/";
      let count = Object.keys(this.tree).length;
      let entries = Object.values(this.tree).reduce((n, node) => n + (node.dirs || []).length, 0);
      const candidates = Object.keys(this.tree).sort((a, b) => (this.tree[a].used || 0) - (this.tree[b].used || 0));
      for (const path of candidates) {
        if (count <= 32 && entries <= 8000) break;
        if (path === "/" || path === current || current.startsWith(path + "/") || !this.tree[path]) continue;
        for (const key of Object.keys(this.tree)) {
          if (key === path || key.startsWith(path + "/")) {
            entries -= (this.tree[key].dirs || []).length; count--; delete this.tree[key];
          }
        }
      }
    },

    async ensureFsRoot() {
      const node = this.tree["/"];
      if (node && node.loaded) return;
      if (this._rootLoad) return this._rootLoad;
      const alias = this.liveAlias();
      if (!alias) return;
      const seq = this.workspaceSeq;
      const app = this;
      this._rootLoad = (async () => {
        try {
          const data = await app.postRead("/api/files/list", { alias: alias, path: "/" });
          if (app.workspaceSeq !== seq || app.liveAlias() !== alias) return;
          app.noteTree(data.path || "/", data.entries || []);
        } catch (err) {
          // The directory that was opened stays visible if / cannot be listed.
        } finally {
          if (app.workspaceSeq === seq) app._rootLoad = null;
        }
      })();
      return this._rootLoad;
    },

    treeRows() {
      const rows = [];
      const root = this.treeRoot || "";
      const visited = new Set();
      const walk = (path, depth, name) => {
        if (visited.has(path)) return;
        visited.add(path);
        const node = this.tree[path];
        if (!node) { rows.push({ path: path, name: name || this.treeLabel(path), depth: depth, open: false }); return; }
        rows.push({ path: path, name: node.name || path, depth: depth, open: !!node.open });
        if (!node.open) return;
        const dirs = node.dirs || [];
        for (let i = 0; i < dirs.length; i++) walk(dirs[i].path, depth + 1, dirs[i].name);
      };
      if (root && this.tree[root]) walk(root, 0);
      return rows;
    },

    async toggleTree(row) {
      let node = this.tree[row.path];
      if (node && node.open) {
        node.open = false;
        this.tree = Object.assign({}, this.tree);
        return;
      }
      if (node && node.loaded) {
        node.open = true;
        node.used = ++this.treeClock;
        this.tree = Object.assign({}, this.tree);
        return;
      }
      const alias = this.liveAlias();
      if (!alias) return;
      if (node && node.pending) { node.open = true; return; }
      this.tree[row.path] = { name: row.name || this.treeLabel(row.path), open: true, loaded: false, dirs: [], pending: true, used: ++this.treeClock };
      node = this.tree[row.path];
      const seq = this.workspaceSeq;
      try {
        const data = await this.postRead("/api/files/list", { alias: alias, path: row.path });
        if (seq !== this.workspaceSeq || this.liveAlias() !== alias || this.tree[row.path] !== node || !node.open) return;
        this.noteTree(data.path || row.path, data.entries || []);
      } catch (err) {
        if (seq !== this.workspaceSeq || this.liveAlias() !== alias || this.tree[row.path] !== node || !node.open) return;
        node.open = false;
        this.toast(err.message || "无法展开目录", "bad");
      } finally {
        node.pending = false;
      }
    },

    fileScope() {
      const terminal = termMap.get(this.termActive);
      return { alias: this.liveAlias(), seq: this.workspaceSeq, dir: this.files.path,
        readSeq: this.filesReadSeq, tab: this.termActive, generation: terminal ? terminal.generation : 0 };
    },

    fileScopeCurrent(scope) {
      const current = this.fileScope();
      return !!scope && !!scope.alias && this.view === "terminal" && !this.filesLoading && this.files.mode !== "history" &&
        Object.keys(scope).every((key) => scope[key] === current[key]);
    },

    async editFileAction(action) {
      this.menu.open = false;
      if (this.fileBusy || action.done || (this.fileAction && this.fileAction.uncertain)) return;
      if (!action.path || !this.fileScopeCurrent(action.scope)) { this.toast("主机、连接或目录已变化，请重新选择文件。", "bad"); return; }
      this.fileBusy = true;
      this.fileAction = action;
      action = this.fileAction;
      action.message = "等待确认：" + action.scope.alias + " · " + action.path;
      let requested = false;
      try {
        const guard = () => {
          if (!this.fileScopeCurrent(action.scope)) {
            const err = new Error("主机、连接或目录已变化，操作已取消，请重新选择文件。");
            err.outcome = "not_started"; throw err;
          }
        };
        if (action.op === "remove") {
          if (!await this.askConfirm("主机：" + action.scope.alias + "\n删除：" + action.path + "\n此操作不能撤销，继续？")) { this.fileAction = null; return; }
        } else {
          const labels = { mkdir: "新建文件夹名称", touch: "新建文件名称", rename: "重命名为" };
          const name = await this.ask(labels[action.op] + "\n" + action.scope.alias + " · " + action.path, action.name || "");
          if (name == null) { this.fileAction = null; return; }
          action.name = String(name).trim();
          if (!action.name) { action.message = "请输入名称，输入已保留。"; return; }
        }
        guard();
        action.message = "正在处理：" + action.scope.alias + " · " + action.path;
        requested = true;
        this.persistPending();
        const data = await this.postJSON("/api/files/change", { alias: action.scope.alias, op: action.op, path: action.path, name: action.name || "" }, guard);
        if (data.outcome !== "completed" || !data.path) throw new Error("未收到完整文件操作结果");
        action.done = true;
        action.message = "已完成：" + action.scope.alias + " · " + data.path;
        // A successful write stays successful even if its directory refresh fails.
        if (this.fileScopeCurrent(action.scope)) {
          await this.listFiles(action.op === "remove" && action.path === action.scope.dir ? (this.files.parent || "/") : action.scope.dir);
          if (this.liveAlias() === action.scope.alias && this.files.path === action.scope.dir && this.workspaceSeq === action.scope.seq && action.op !== "remove") {
            this.selectedPath = (this.files.entries || []).some((entry) => entry.path === data.path) ? data.path : "";
            setTimeout(() => {
              if (this.selectedPath !== data.path || this.liveAlias() !== action.scope.alias || this.workspaceSeq !== action.scope.seq) return;
              const row = document.querySelector(".ws-table-wrap tr.is-selected");
              if (row) row.scrollIntoView({ block: "nearest" });
            }, 0);
          }
        }
        this.loadAudit();
      } catch (err) {
        if (action.done) { this.setError("files", "操作已完成，目录刷新失败：" + err.message); return; }
        action.uncertain = requested && err.outcome !== "not_started";
        action.message = action.scope.alias + " · " + action.path + "：" + (err.message || "操作失败") +
          (action.uncertain ? "；结果待确认，请核验远端文件，禁止直接重试。" : "；未执行，输入已保留。");
      } finally { this.fileBusy = false; this.persistPending(); }
    },

    async clearFileAction() {
      if (this.fileBusy) return;
      if (this.fileAction && this.fileAction.uncertain && !await this.askConfirm("请先核验原主机上的文件。清除提示不会撤销操作，确认已核验？")) return;
      this.fileAction = null;
      this.persistPending();
    },

    createEntry(kind) {
      return this.editFileAction({ op: kind === "dir" ? "mkdir" : "touch", path: this.files.path, name: "", scope: this.fileScope() });
    },

    renameEntry() {
      const entry = this.menu.entry;
      return this.editFileAction({ op: "rename", path: entry ? entry.path : "", name: entry ? entry.name : "", scope: this.fileScope() });
    },

    deleteEntry() {
      const entry = this.menu.entry;
      return this.editFileAction({ op: "remove", path: entry ? entry.path : "", name: "", scope: this.fileScope() });
    },

    openContext() {
      const entry = this.menu.entry;
      this.menu.open = false;
      if (!entry) {
        this.refreshFiles();
        return;
      }
      if (entry.dir) this.listFiles(entry.path);
      else this.wsDownload(entry);
    },

    dirEntries() {
      const out = [];
      const entries = this.files.entries || [];
      for (let i = 0; i < entries.length; i++) if (entries[i].dir) out.push(entries[i]);
      return out;
    },

    selectEntry(entry) {
      this.selectedPath = entry && entry.path ? entry.path : "";
    },

    openEntry(entry) {
      if (!entry) return;
      if (entry.dir) this.listFiles(entry.path);
      else this.wsDownload(entry);
    },

    pickUpload() {
      this.menu.open = false;
      const input = document.getElementById("ws-upload");
      if (input) input.click();
    },

    async wsUpload(ev) {
      const files = Array.from(ev.target.files || []);
      ev.target.value = "";
      await this.enqueueUploads(files, this.files.path);
    },

    patchTransfer(id, patch) {
      transferProgress.delete(id);
      const next = [];
      const items = this.transfers || [];
      let found = false;
      for (let i = 0; i < items.length; i++) {
        if (items[i].id === id) {
          found = true;
          next.push(Object.assign({}, items[i], patch));
        } else next.push(items[i]);
      }
      if (!found) next.push(Object.assign({ id: id }, patch));
      this.transfers = next;
      if (patch.active === false) this.pruneTransfers();
      if (patch.started != null || patch.active === false || patch.needsVerification != null) this.persistPending();
    },

    progressTransfer(id, patch) {
      transferProgress.set(id, Object.assign({}, transferProgress.get(id), patch));
      if (!transferPaintTimer) transferPaintTimer = setTimeout(() => this.flushTransferProgress(), 100);
    },

    flushTransferProgress() {
      clearTimeout(transferPaintTimer); transferPaintTimer = 0;
      const pending = Array.from(transferProgress.entries()); transferProgress.clear();
      for (const [id, patch] of pending) {
        if (this.transfers.some((item) => item.id === id && item.active)) this.patchTransfer(id, patch);
      }
    },

    transferNeedsVerification(item) {
      return !!item && (!!item.needsVerification || item.label === "结果待确认" || item.label === "已请求取消");
    },

    pruneTransfers(reserve) {
      const protectedCount = this.transfers.filter((item) => item.active || this.transferNeedsVerification(item)).length;
      const keep = Math.max(0, Math.min(TRANSFER_HISTORY, TRANSFER_LIMIT - protectedCount - (reserve || 0)));
      let settled = this.transfers.filter((item) => !item.active && !this.transferNeedsVerification(item)).length;
      this.transfers = this.transfers.filter((item) => item.active || this.transferNeedsVerification(item) || --settled < keep);
    },

    canQueueTransfers(count) {
      const protectedCount = this.transfers.filter((item) => item.active || this.transferNeedsVerification(item)).length;
      if (protectedCount + count > TRANSFER_LIMIT) {
        this.toast("本次选择超过队列余量（最多 256 项），请分批传输，或先核验旧记录。", "bad"); return false;
      }
      this.pruneTransfers(count); return true;
    },

    queueTransfer(item, run) {
      item.active = true; item.queued = true; item.label = "等待传输";
      this.patchTransfer(item.id, item);
      const promise = new Promise((resolve) => transferJobs.set(item.id, { run: run, resolve: resolve }));
      transferQueue.push(item.id); this.drainTransfers(); return promise;
    },

    transferAlive(id) {
      return this.transfers.some((item) => item.id === id && item.active);
    },

    async drainTransfers() {
      if (this.transferRunning) return;
      this.transferRunning = true;
      try {
        while (transferQueue.length) {
          const id = transferQueue.shift(), job = transferJobs.get(id);
          if (!job) continue;
          this.patchTransfer(id, { queued: false, label: "正在准备" });
          try { await job.run(); }
          catch (err) {
            const item = this.transfers.find((t) => t.id === id);
            if (item && item.active) this.finishTransfer(id, { label: item.started ? "结果待确认" : "失败", needsVerification: !!item.started, error: err.message || "传输失败" });
          } finally {
            transferJobs.delete(id);
            job.resolve(this.transfers.find((item) => item.id === id));
          }
        }
      } finally { this.transferRunning = false; }
    },

    cancelBatch(batch) {
      if (!batch) return;
      for (const item of this.transfers.filter((t) => t.active && t.batch === batch)) this.cancelTransfer(item.id);
    },

    async verifyTransfer(id) {
      const item = this.transfers.find((t) => t.id === id);
      if (!item || item.active || !this.transferNeedsVerification(item)) return;
      if (!await this.askConfirm("主机：" + item.alias + "\n文件：" + item.name + "\n目标：" + (item.local || item.remote || item.name) + "\n确认已核验目标文件？这不会重新传输或撤销操作。")) return;
      if (!this.transfers.some((t) => t.id === id && this.transferNeedsVerification(t))) return;
      this.finishTransfer(id, { needsVerification: false, label: "已核验", error: "" });
    },

    finishTransfer(id, patch) {
      this.patchTransfer(id, Object.assign({}, transferProgress.get(id), patch, { active: false }));
    },

    hasFinishedTransfers() {
      const items = this.transfers || [];
      for (let i = 0; i < items.length; i++) if (!items[i].active && !this.transferNeedsVerification(items[i])) return true;
      return false;
    },

    clearFinishedTransfers() {
      this.transfers = (this.transfers || []).filter((t) => t.active || this.transferNeedsVerification(t));
    },

    canOpenDownload(item) {
      return !!(item && !item.active && item.kind === "download" && String(item.local || "").trim());
    },

    async openDownloadFolder(item) {
      if (!this.canOpenDownload(item)) return;
      try {
        await this.postJSON("/api/download-dir/reveal", { path: item.local });
      } catch (err) {
        this.toast((err && err.message) || "打不开所在目录", "bad");
      }
    },

    transferSummary() {
      let running = 0, queued = 0, uncertain = 0;
      for (const t of this.transfers) {
        if (this.transferNeedsVerification(t)) uncertain++;
        else if (t.active) { if (t.started) running++; else queued++; }
      }
      return [running && running + " 运行", queued && queued + " 排队", uncertain && uncertain + " 待核验"].filter(Boolean).join(" · ");
    },

    transferDetail(item) {
      if (!item) return "";
      const loadedN = Number(item.loaded) || 0;
      const total = Number(item.total) || 0;
      const status = item.active && total > 0 && loadedN >= total && item.label === "写入远端" ? "等待远端提交确认" : (item.label || "");
      if (total > 0) {
        const bits = this.pct(this.itemPct(item)) + " · " + this.formatBytes(loadedN) + " / " + this.formatBytes(total);
        return bits + (status ? " · " + status : "");
      }
      if (loadedN > 0) return (status ? status + " · " : "") + this.formatBytes(loadedN);
      return status;
    },

    fileSize(entry) {
      if (!entry || entry.dir) return "—";
      return this.formatBytes(entry.size);
    },

    async enqueueUploads(fileList, remoteDir, explicitAlias, confirmText) {
      const alias = explicitAlias || this.liveAlias();
      if (!alias) {
        this.toast("先打开终端或点「连接」。", "bad");
        return;
      }
      const dest = remoteDir || (explicitAlias ? "" : this.files.path);
      if (!dest) {
        this.toast("先刷新目录，再上传。", "bad");
        return;
      }
      const files = [];
      const list = fileList || [];
      for (let i = 0; i < list.length; i++) files.push(list[i]);
      if (!files.length) return;
      if (!this.canQueueTransfers(files.length)) return;
      this.setError("files", "");
      const batch = operationID();
      const jobs = files.map((file) => {
        const id = "up" + operationID();
        return this.queueTransfer({ id: id, batch: batch, alias: alias, remote: dest, kind: "upload", name: file.name, total: file.size || 0, loaded: 0 }, async () => {
          await this.ensureSession();
          if (this.transferAlive(id)) await this.uploadOne(alias, file, dest, id, confirmText);
        });
      });
      files.length = 0;
      const results = await Promise.all(jobs);
      if (this.liveAlias() === alias && this.files.path === dest && this.files.mode !== "history") await this.listFiles(dest);
      return results;
    },

    uploadOne(alias, file, remoteDir, queuedID, initialConfirm) {
      const app = this;
      const id = queuedID || "up" + operationID();
      const item = { id: id, alias: alias, kind: "upload", name: file.name, loaded: 0, total: file.size || 0, active: true, label: "发送到本机" };
      this.patchTransfer(id, item);
      const alive = () => (app.transfers || []).some((t) => t.id === id && t.active);
      const commit = (patch, progress) => {
        if (!alive()) return;
        Object.assign(item, patch);
        if (progress) app.progressTransfer(id, patch);
        else app.patchTransfer(id, patch);
      };
      return new Promise((resolve) => {
        let authAsked = false, sessionRenewed = false;
        const send = (confirmText, overwrite) => {
          const xhr = new XMLHttpRequest();
          transferCtl.set(id, { abort() { xhr.abort(); transferCtl.delete(id); resolve(); } });
          const fd = new FormData();
          fd.set("alias", alias);
          fd.set("remote", remoteDir);
          fd.set("file", file, file.name);
          if (confirmText) fd.set("confirm", confirmText);
          if (overwrite) fd.set("overwrite", "true");
          xhr.open("POST", "/api/upload");
          if (app.csrf) xhr.setRequestHeader("X-CSRF-Token", app.csrf);
          xhr.setRequestHeader("Accept", "application/x-ndjson");
          const token = sessionStorage.getItem("sshCliBearer") || "";
          if (token) xhr.setRequestHeader("Authorization", "Bearer " + token);
          let seen = 0;
          let remoteStarted = false;
          const takeRemote = () => {
            if (!alive()) return;
            const text = xhr.responseText || "";
            if (text.length <= seen) return;
            const chunk = text.slice(seen);
            const lines = chunk.split("\n");
            if (lines.length < 2) return;
            seen += chunk.length - lines[lines.length - 1].length;
            for (let n = 0; n < lines.length - 1; n++) {
              const line = lines[n].trim();
              if (!line) continue;
              let msg = null;
              try { msg = JSON.parse(line); } catch (err) { continue; }
              if (msg && msg.ok == null && msg.loaded != null) {
                remoteStarted = true;
                commit({ loaded: msg.loaded, total: msg.total || item.total || 0, active: true, label: "写入远端" }, true);
              }
            }
          };
          xhr.onprogress = takeRemote;
          xhr.onreadystatechange = () => { if (xhr.readyState >= 3) takeRemote(); };
          xhr.upload.onprogress = (ev) => {
            if (alive() && !remoteStarted && ev.lengthComputable && ev.total > 0) {
              commit({
                loaded: Math.min(file.size || 0, Math.round((file.size || 0) * ev.loaded / ev.total)),
                total: file.size || 0,
                active: true,
                label: ev.loaded === ev.total ? "本机接收完成，等待远端确认" : "发送到本机"
              }, true);
            }
          };
          xhr.onerror = () => {
            if (!alive()) { transferCtl.delete(id); resolve(); return; }
            commit({ active: false, needsVerification: true, label: "结果待确认", error: "连接中断，远端可能已经写入。请核验目标文件，不要直接重试。" });
            transferCtl.delete(id);
            app.toast(file.name + " 上传失败", "bad");
            resolve();
          };
          xhr.onabort = () => {
            commit({ active: false, needsVerification: true, label: "已请求取消", error: "请求已停止，远端可能已经写入。请核验目标文件。" });
            transferCtl.delete(id);
            resolve();
          };
          xhr.onload = async () => {
            if (!alive()) { transferCtl.delete(id); resolve(); return; }
            if (xhr.status === 403 && xhr.getResponseHeader && xhr.getResponseHeader("X-SSH-CLI-Session-Expired") === "1") {
              commit({ started: false, label: "正在恢复会话" });
              try {
                if (sessionRenewed) throw new Error("会话恢复失败，请刷新页面。");
                sessionRenewed = true; app.csrf = ""; await app.ensureSession();
                if (alive()) { send(confirmText, overwrite); return; }
              } catch (err) { commit({ active: false, label: "失败", error: err.message }); }
              transferCtl.delete(id); resolve(); return;
            }
            if (xhr.status === 401) {
              commit({ started: false, label: "等待身份验证" });
              try {
                if (authAsked) throw new Error("身份验证失败，请检查 Bearer token。");
                authAsked = true; await app.requestBearer();
                if (alive()) { send(confirmText, overwrite); return; }
              } catch (err) { commit({ active: false, label: "失败", error: err.message }); }
              transferCtl.delete(id); resolve(); return;
            }
            let data = {};
            const raw = String(xhr.responseText || "").trim();
            try {
              data = raw ? lastJSONObject(raw) : {};
              app.noteAudit(data);
              if (typeof data.ok !== "boolean") throw new Error("missing final result");
            } catch (err) {
              commit({ active: false, needsVerification: true, label: "结果待确认", error: "未收到完整传输结果，请核验目标文件，不要直接重试。" });
              transferCtl.delete(id);
              app.toast(file.name + "：" + plainBodyMessage(raw, xhr.statusText), "bad");
              resolve();
              return;
            }
            if ((xhr.status === 409 || data.needsOverwrite) && data.needsOverwrite && !overwrite) {
              commit({ label: "等待覆盖确认" });
              const accepted = await app.askConfirm("主机 " + alias + " 已有文件：" + data.path + "\n覆盖后无法恢复原内容，继续？");
              if (accepted && alive()) { send(confirmText, true); return; }
              commit({ active: false, label: "已取消" });
              transferCtl.delete(id);
              resolve();
              return;
            }
            if ((xhr.status === 409 || data.needsConfirm) && data.needsConfirm && !confirmText) {
              commit({ label: "等待人工确认" });
              const typed = await app.ask((data.error || "需要确认") + "\n主机：" + alias + "\n路径：" + remoteDir + "\n请输入：" + (data.confirm || alias));
              if (typed == null) {
                commit({ active: false, label: "已取消" });
                transferCtl.delete(id);
                resolve();
                return;
              }
              if (!alive()) { transferCtl.delete(id); resolve(); return; }
              send(typed, overwrite);
              return;
            }
            transferCtl.delete(id);
            if (xhr.status < 200 || xhr.status >= 300 || data.ok === false) {
              const unknown = data.outcome === "unknown" || xhr.status >= 500;
              commit({ active: false, needsVerification: unknown, label: unknown ? "结果待确认" : "失败", error: friendlyError(data.error, xhr.statusText || "上传失败") + (unknown ? "；目标文件可能部分写入，请核验后再重试。" : "") });
              app.toast(file.name + "：" + (data.error || xhr.statusText || "上传失败"), "bad");
            } else {
              commit({ active: false, loaded: item.total || item.loaded, label: "完成" });
            }
            resolve();
          };
          try { commit({ started: true, label: "发送到本机" }); xhr.send(fd); } catch (err) { xhr.onerror(); }
        };
        send(initialConfirm || "");
      });
    },

    async wsDownload(entry, explicitAlias) {
      this.menu.open = false;
      const alias = explicitAlias || this.liveAlias();
      if (!alias || !entry || !entry.path) return;
      this.setError("files", "");
      if (!this.canQueueTransfers(1)) return;
      const id = "dn" + operationID();
      const local = this.downloadDir || "", target = Object.assign({}, entry);
      return this.queueTransfer({ id: id, alias: alias, kind: "download", name: target.name || "download", remote: target.path, local: local }, async () => {
        await this.ensureSession();
        if (this.transferAlive(id)) await this.downloadOne(target, alias, id, local);
      });
    },

    async downloadOne(entry, alias, id, local) {
      const name = entry.name || "download";
      const known = !entry.dir && Number(entry.size) > 0 ? Number(entry.size) : 0;
      this.patchTransfer(id, { id: id, alias: alias, kind: "download", name: name, loaded: 0, total: known, active: true, label: "下载中" });
      const ctrl = new AbortController();
      transferCtl.set(id, ctrl);
      let confirmText = "";
      try {
        for (let attempt = 0; attempt < 4; attempt++) {
          const res = await this.api("/api/download", {
            method: "POST",
            signal: ctrl.signal,
            headers: { "Content-Type": "application/json", "Accept": "application/x-ndjson" },
            body: JSON.stringify({ alias: alias, path: entry.path, local: local, confirm: confirmText })
          }, () => {
            if (!this.transferAlive(id)) { const err = new Error("已取消"); err.name = "AbortError"; throw err; }
            this.patchTransfer(id, { started: true, label: "下载中" });
          });
          const ctype = String(res.headers.get("content-type") || "");
          const data = ctype.indexOf("ndjson") >= 0
            ? await readNDJSON(res, (msg) => {
              if (ctrl.signal.aborted) return;
              this.progressTransfer(id, { loaded: Number(msg.loaded) || 0, total: Number(msg.total) || known, active: true, label: "下载中" });
            })
            : await this.parseJSON(res);
          this.noteAudit(data);
          checkRead(ctrl.signal);
          if (res.status === 409 && data.needsConfirm && !confirmText) {
            this.patchTransfer(id, { label: "等待人工确认" });
            const typed = await this.ask((data.error || "需要确认") + "\n主机：" + alias + "\n路径：" + entry.path + "\n请输入：" + (data.confirm || alias));
            if (typed == null) {
              const cancel = new Error("已取消");
              cancel.name = "AbortError";
              throw cancel;
            }
            confirmText = String(typed);
            checkRead(ctrl.signal);
            continue;
          }
          if (!res.ok || data.ok !== true) {
            const err = new Error(friendlyError(data.error, res.statusText || "传输结果未确认，请核验目标文件。"));
            err.knownFailure = data.ok === false && data.outcome !== "unknown";
            throw err;
          }
          const saved = data.local || "";
          const label = saved ? ("已保存到 " + saved) : "完成";
          const current = Object.assign({}, (this.transfers || []).find((t) => t.id === id), transferProgress.get(id));
          let totalBytes = Number(current.total) || known || 0;
          let loadedBytes = Number(current.loaded) || 0;
          if (totalBytes > 0) loadedBytes = totalBytes;
          this.finishTransfer(id, { loaded: loadedBytes, total: totalBytes, label: label, local: saved, kind: "download" });
          if (saved) this.toast(label);
          return;
        }
        throw new Error("下载失败");
      } catch (err) {
        if (err && err.name === "AbortError") {
          const item = this.transfers.find((t) => t.id === id);
          if (item && item.active) this.finishTransfer(id, { label: "已取消" });
        } else {
          const known = err.knownFailure || err.outcome === "not_started";
          this.finishTransfer(id, { needsVerification: !known, label: known ? "失败" : "结果待确认", error: (err.message || "下载失败") + (known ? "" : "；请核验本机保存目录，不要直接重试。") });
          this.toast((entry.name || "文件") + "：" + (err.message || "下载失败"), "bad");
        }
      } finally {
        transferCtl.delete(id);
      }
    },

    saveBlob(blob, name) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name || "download";
      a.click();
      URL.revokeObjectURL(url);
    },

    cancelTransfer(id) {
      const items = this.transfers || [];
      let active = false;
      for (let i = 0; i < items.length; i++) if (items[i].id === id && items[i].active) active = true;
      if (!active) return;
      const ctl = transferCtl.get(id);
      const item = items.find((t) => t.id === id);
      const waiting = item && (!item.started || item.queued || String(item.label || "").indexOf("等待") === 0);
      this.finishTransfer(id, { needsVerification: !waiting, queued: false, label: waiting ? "已取消" : "已请求取消", error: waiting ? "" : "请求已停止，目标文件可能已经写入。请核验后再重试。" });
      if (!ctl) {
        const job = transferJobs.get(id), index = transferQueue.indexOf(id);
        if (index >= 0) { transferQueue.splice(index, 1); transferJobs.delete(id); if (job) job.resolve(this.transfers.find((t) => t.id === id)); }
      }
      if (ctl && ctl.abort) ctl.abort();
    },

    itemPct(item) {
      if (!item) return 0;
      const label = String(item.label || "");
      const done = !item.active && (label === "完成" || label.indexOf("已保存") === 0);
      const total = Number(item.total) || 0;
      const loaded = Number(item.loaded) || 0;
      if (!total) return done ? 100 : 0;
      if (done) return 100;
      return (100 * loaded) / total;
    },

    transferPct() {
      const items = this.transfers || [];
      let loaded = 0;
      let total = 0;
      let active = false;
      for (let i = 0; i < items.length; i++) {
        if (!items[i].active && items[i].label !== "完成") continue;
        active = true;
        loaded += Number(items[i].loaded) || 0;
        total += Number(items[i].total) || 0;
      }
      if (!active || !total) return 0;
      return (100 * loaded) / total;
    },

    hasLocalFiles(ev) {
      const types = ev && ev.dataTransfer && ev.dataTransfer.types;
      if (!types) return false;
      for (let i = 0; i < types.length; i++) if (types[i] === "Files") return true;
      return false;
    },

    dragEnter(ev) {
      if (!this.hasLocalFiles(ev)) return;
      this.drop.over = true;
      this.drop.label = "松开以上传到当前目录";
    },

    dragOver(ev, target) {
      if (ev && ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
      this.dragPoint = { x: ev.clientX, y: ev.clientY };
      if (this.hasLocalFiles(ev)) {
        this.drop.over = true;
        this.drop.target = target || "";
        this.drop.label = target ? "松开以上传到这个目录" : "松开以上传到当前目录";
      }
    },

    dragLeave(ev) {
      const next = ev.relatedTarget;
      const stage = ev.currentTarget;
      if (next && stage && stage.contains && stage.contains(next)) return;
      this.drop.over = false;
      this.drop.target = "";
    },

    async dropFiles(ev, target) {
      this.drop.over = false;
      this.drop.target = "";
      const raw = ev.dataTransfer ? ev.dataTransfer.getData("application/x-ssh-cli-file") : "";
      if (raw) {
        this.wsInternalDrop = true;
        if (target === "download") {
          try { const entry = JSON.parse(raw); await this.wsDownload(entry, entry.alias); } catch (err) { this.toast("无法下载", "bad"); }
        }
        return;
      }
      const dest = target && target !== "download" ? target : this.files.path;
      await this.enqueueUploads(ev.dataTransfer ? ev.dataTransfer.files : [], dest);
    },

    dragRemoteStart(ev, entry) {
      if (!entry || entry.dir) {
        if (ev.dataTransfer) ev.dataTransfer.effectAllowed = "none";
        return;
      }
      this.wsInternalDrop = false;
      this.dragAlias = this.liveAlias();
      this.dragPoint = { x: ev.clientX, y: ev.clientY };
      ev.dataTransfer.effectAllowed = "copy";
      ev.dataTransfer.setData("application/x-ssh-cli-file", JSON.stringify({ alias: this.liveAlias(), path: entry.path, name: entry.name }));
      ev.dataTransfer.setData("text/plain", entry.path || entry.name || "");
    },

    dragRemoteEnd(ev, entry) {
      if (!entry || entry.dir) return;
      if (this.wsInternalDrop) {
        this.wsInternalDrop = false;
        return;
      }
      const box = document.querySelector("[data-view='terminal']");
      if (!box || !this.dragPoint) return;
      const r = box.getBoundingClientRect();
      const p = this.dragPoint;
      const outside = p.x < r.left || p.x > r.right || p.y < r.top || p.y > r.bottom;
      if (!outside) return;
      this.toast("已按命令行方式下载到保存目录");
      this.wsDownload(entry, this.dragAlias);
    },

    openMenu(ev, entry) {
      if (entry) this.selectedPath = entry.path || "";
      const menuW = 240;
      const menuH = 380;
      let x = ev.clientX;
      let y = ev.clientY;
      const vw = window.innerWidth || 0;
      const vh = window.innerHeight || 0;
      if (x + menuW > vw - 8) x = Math.max(8, vw - menuW - 8);
      if (y + menuH > vh - 8) y = Math.max(8, y - menuH);
      if (y + menuH > vh - 8) y = Math.max(8, vh - menuH - 8);
      if (x < 8) x = 8;
      if (y < 8) y = 8;
      this.menu = { open: true, x: x, y: y, entry: entry || null, newOpen: false };
      const app = this;
      const place = () => {
        const el = document.querySelector(".ws-menu");
        if (!el || !app.menu.open) return;
        const r = el.getBoundingClientRect();
        let nx = app.menu.x;
        let ny = app.menu.y;
        if (r.right > window.innerWidth - 8) nx -= r.right - window.innerWidth + 8;
        if (r.bottom > window.innerHeight - 8) ny -= r.bottom - window.innerHeight + 8;
        if (nx < 8) nx = 8;
        if (ny < 8) ny = 8;
        if (nx !== app.menu.x || ny !== app.menu.y) app.menu = Object.assign({}, app.menu, { x: nx, y: ny });
      };
      if (this.$nextTick) this.$nextTick(place);
      else setTimeout(place, 0);
      const close = (e) => {
        if (e.type === "keydown" && e.key !== "Escape") return;
        if (e.type === "click" && e.target && e.target.closest && e.target.closest(".ws-menu")) return;
        app.menu.open = false;
        document.removeEventListener("click", close, true);
        document.removeEventListener("keydown", close);
      };
      setTimeout(() => {
        document.addEventListener("click", close, true);
        document.addEventListener("keydown", close);
      }, 0);
    },

    menuStyle() {
      return "left:" + (this.menu.x || 0) + "px;top:" + (this.menu.y || 0) + "px";
    },

    async copyPath() {
      const entry = this.menu.entry;
      const path = (entry && entry.path) || this.files.path || "";
      this.menu.open = false;
      if (!path) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(path);
        else throw new Error("clipboard");
        this.toast("已复制路径");
      } catch (err) {
        this.toast(path);
      }
    },

    toast(text, kind) {
      const id = "n" + Date.now().toString(36) + this.toasts.length;
      this.toasts.push({ id: id, text: text, kind: kind || "" });
      const app = this;
      setTimeout(() => {
        app.toasts = app.toasts.filter((t) => t.id !== id);
      }, 4200);
    },

    markTabIdle(id) {
      const tabs = this.termTabs || [];
      for (let i = 0; i < tabs.length; i++) if (tabs[i].id === id) tabs[i].busy = false;
    },

    tabBusy(tab) {
      if (!tab) return false;
      if (tab.busy) return true;
      const items = this.transfers || [];
      for (let i = 0; i < items.length; i++) {
        if (items[i].active && items[i].alias === tab.alias) return true;
      }
      return false;
    },

    workspaceSession() {
      const alias = this.panelAlias();
      if (!alias) return "未选择主机";
      if (!this.workspaceLive()) return "未打开终端 · 点「打开」或「连接」后显示概况和文件";
      const items = this.sessions || [];
      for (let i = 0; i < items.length; i++) {
        if (items[i].alias !== alias) continue;
        const idle = items[i].status === "busy" ? "忙碌，暂不因空闲关闭" : ("空闲剩余 " + this.formatLeft(items[i].idleLeftSec));
        return (items[i].status === "busy" ? "忙碌" : "已连接") + " · " + idle + " · 最长剩余 " + this.formatLeft(items[i].lifeLeftSec);
      }
      return "未连接 · 点「连接」或「打开」";
    },

    async openWorkspaceHost() {
      const alias = this.panelAlias();
      if (!alias) {
        this.toast("先选择一台主机。", "bad");
        return;
      }
      try {
        await this.postJSON("/api/sessions/open", { alias: alias });
        this.workspaceClosedAlias = "";
        this.explicitAlias = alias;
        this.termAlias = alias;
        await this.loadSessions();
        this.syncWorkspace();
        this.toast("已连接 " + alias);
      } catch (err) {
        this.toast(err.message || "连接失败", "bad");
      }
    },

    async closeWorkspaceHost() {
      const alias = this.panelAlias();
      if (!alias) return;
      this.workspaceClosedAlias = alias;
      if (this.explicitAlias === alias) this.explicitAlias = "";
      const tabs = (this.termTabs || []).slice();
      for (let i = 0; i < tabs.length; i++) if (tabs[i].alias === alias) this.closeTab(tabs[i].id);
      try {
        await this.postJSON("/api/sessions/close", { alias: alias });
        await this.loadSessions();
      } catch (err) {
        this.toast(err.message || "断开失败", "bad");
      }
      this.syncWorkspace();
    },

    async loadHistory(alias) {
      const name = String(alias || this.liveAlias() || "").trim();
      if (!name || !this.workspaceLive()) {
        this.setError("files", "先打开终端或点「连接」。");
        return;
      }
      this.files.mode = "history";
      this.setError("files", "");
      const signal = this.replaceRead("files");
      const seq = this.filesReadSeq;
      this.filesLoading = true;
      try {
        const data = await this.postRead("/api/history", { alias: name, lines: 100 }, signal);
        if (seq !== this.filesReadSeq || this.liveAlias() !== name) return;
        data.lines = data.lines || [];
        data.entries = data.entries || [];
        data.notes = data.notes || [];
        this.historyView = data;
        this.restoreFileScroll(Object.assign({}, this.fileScroll));
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (seq !== this.filesReadSeq || this.liveAlias() !== name) return;
        this.historyView = { alias: name, found: false, status: "error", lines: [], notes: [], error: err.message || "读取历史失败" };
        this.setError("files", err.message || "读取历史失败");
      } finally {
        if (seq === this.filesReadSeq) this.filesLoading = false;
      }
    },

    historyCaption() {
      const h = this.historyView || {};
      if (h.alias !== this.liveAlias()) return this.filesLoading ? "正在读取历史…" : "";
      if (h.suppressed) return "这个环境不允许把历史带回本机。";
      if (!h.path && !h.error) return "只读最近命令。不会修改远端历史。内容可能含密钥，常见片段已打码。";
      const bits = [];
      if (h.path) bits.push(h.path);
      if (h.shell) bits.push(h.shell);
      if (h.status && h.status !== "ok") bits.push(h.status);
      if (h.truncated) bits.push("已截断");
      const entries = h.entries || [];
      let timed = false;
      for (let i = 0; i < entries.length; i++) if (entries[i].time) timed = true;
      if (entries.length && !timed) bits.push("无执行时间：bash 需 HISTTIMEFORMAT 才有 #unix 行；zsh / fish 有记录时会显示");
      bits.push("只读，可能含密钥");
      return bits.join(" · ");
    },

    historyText() {
      const h = this.historyView || {};
      if (h.alias !== this.liveAlias()) return this.filesLoading ? "正在读取历史…" : "";
      const entries = h.entries || [];
      if (entries.length) {
        const rows = [];
        for (let i = 0; i < entries.length; i++) {
          const cmd = entries[i].command || "";
          rows.push(entries[i].time ? (entries[i].time + "  " + cmd) : cmd);
        }
        return rows.join("\n");
      }
      const lines = h.lines || [];
      if (lines.length) return lines.join("\n");
      const notes = (h.notes || []).join("\n");
      return h.error || notes || "没有读到 shell 历史。";
    },

    subject(rec) {
      if (!rec) return "";
      if (rec.command) return rec.command;
      if (rec.src || rec.dst) return (rec.src || "") + " → " + (rec.dst || "");
      return "";
    },

    statusBadge(status) {
      if (status === "ok") return "badge bg-green-lt";
      if (status === "denied") return "badge bg-red-lt";
      if (status === "timeout" || status === "auth" || status === "connect") return "badge bg-yellow-lt";
      return "badge bg-secondary-lt";
    },

    auditRowClass(rec) {
      if (!rec || rec.status === "ok") return "";
      if (rec.status === "denied") return "table-danger";
      return "table-warning";
    },

    openAuditHost(rec) {
      if (rec && rec.host) this.openHost(rec.host);
    },

    nextId() {
      this.seq += 1;
      return this.seq;
    },

    rulesFrom(items) {
      const out = [];
      for (const text of items || []) out.push({ id: this.nextId(), text: text });
      return out;
    },

    rulesText(list) {
      const out = [];
      for (const rule of list || []) {
        const text = String(rule.text || "").trim();
        if (text) out.push(text);
      }
      return out;
    },

    addRule(list) {
      list.push({ id: this.nextId(), text: "" });
    },

    removeRule(list, id) {
      const idx = list.findIndex((rule) => rule.id === id);
      if (idx >= 0) list.splice(idx, 1);
    },

    rulePayload(form) {
      return {
        allow: form.allowMode === "list" ? this.rulesText(form.allow) : null,
        deny: this.rulesText(form.deny),
        confirm: this.rulesText(form.confirm)
      };
    },

    lines(text) {
      return String(text || "").split("\n").map((s) => s.trim()).filter(Boolean);
    },

    commaList(text) {
      return String(text || "").split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    },

    blankHost() {
      return {
        editing: false, alias: "", group: "", host: "", port: "", user: "", password: "", identity: "", agent: false, agentKey: "",
        policy: "", tags: "", useVia: false, via: "", allowMode: "all", allow: [], deny: [], confirm: [], setDefault: false
      };
    },

    blankGroup() {
      return {
        editing: false, envWas: "", name: "", label: "", env: "", policy: "",
        allowMode: "all", allow: [], deny: [], confirm: [], protected: ""
      };
    },

    blankPolicy() {
      return { editing: false, modeKind: "create", title: "添加命名策略", name: "", mode: "", allowMode: "all", allow: [], deny: [], confirm: [] };
    },

    blankEnv() {
      return { editing: false, name: "", label: "", color: "", maxMode: "standard", defaultPolicy: "" };
    },

    openHostForm(h) {
      if (!h) {
        this.hostForm = this.blankHost();
        if (this.catalog.groups && this.catalog.groups.length) this.hostForm.group = this.sortedGroups()[0].name;
      } else {
        this.hostForm = {
          editing: true,
          alias: h.alias,
          group: h.group,
          host: h.host,
          port: h.port || "",
          user: h.user || "",
          password: "",
          identity: "",
          agent: h.auth === "agent",
          agentKey: h.agentKey || "",
          policy: h.policy || "",
          tags: (h.tags || []).join(","),
          useVia: !!h.via,
          via: h.via || "",
          allowMode: h.allowSet ? "list" : "all",
          allow: this.rulesFrom(h.allow),
          deny: this.rulesFrom(h.deny),
          confirm: this.rulesFrom(h.confirm),
          setDefault: !!h.default
        };
      }
      this.setError("hostForm", "");
      this.openDialog("host");
    },

    async saveHost() {
      this.setError("hostForm", "");
      const form = this.hostForm;
      if (form.useVia && this.jumpChoices().length === 0) {
        this.setError("hostForm", "还没有其他主机可以当跳板。先添加那台跳板并保存，再回来编辑。");
        return;
      }
      if (form.useVia && !String(form.via || "").trim()) {
        this.setError("hostForm", "请选择一台已经保存的跳板。");
        return;
      }
      if (form.editing) {
        const prev = this.hostByAlias(String(form.alias || "").trim());
        const nextVia = form.useVia ? String(form.via || "").trim() : "";
        const prevVia = prev && prev.via ? prev.via : "";
        if (nextVia !== prevVia && !await this.askConfirm("跳板改了之后，这台主机已经打开的连接会断开。保存吗？")) return;
      }
      const body = Object.assign({
        alias: String(form.alias || "").trim(),
        group: form.group,
        host: String(form.host || "").trim(),
        user: String(form.user || "").trim(),
        policy: form.policy || "",
        tags: this.commaList(form.tags),
        via: form.useVia ? String(form.via || "").trim() : "",
        setDefault: !!form.setDefault
      }, this.rulePayload(form));
      if (String(form.port) !== "") body.port = Number(form.port);
      if (!form.agent && form.password) body.password = form.password;
      if (form.agent) { body.agent = true; body.agentKey = String(form.agentKey || "").trim(); }
      if (!form.agent && String(form.identity || "").trim()) body.identity = String(form.identity).trim();
      try {
        await this.postJSON(form.editing ? "/api/hosts/update" : "/api/hosts", body);
        this.closeDialogs();
        await this.loadCatalog();
      } catch (err) {
        this.setError("hostForm", err.message);
      }
    },

    async removeHost(alias) {
      if (!await this.askConfirm("删除主机 " + alias + "？")) return;
      this.setError("hosts", "");
      try {
        await this.postJSON("/api/hosts/remove", { alias: alias });
        await this.loadCatalog();
      } catch (err) {
        this.setError("hosts", err.message);
      }
    },

    openGroupForm(g) {
      if (!g) {
        this.groupForm = this.blankGroup();
        if (this.catalog.envs && this.catalog.envs.length) this.groupForm.env = this.sortedEnvs()[0].name;
      } else {
        this.groupForm = {
          editing: true,
          envWas: g.env,
          name: g.name,
          label: g.label || "",
          env: g.env,
          policy: g.policy || "",
          allowMode: g.allowSet ? "list" : "all",
          allow: this.rulesFrom(g.allow),
          deny: this.rulesFrom(g.deny),
          confirm: this.rulesFrom(g.confirm),
          protected: (g.protectedPaths || []).join("\n")
        };
      }
      this.setError("groupForm", "");
      this.openDialog("group");
    },

    async saveGroup() {
      this.setError("groupForm", "");
      const form = this.groupForm;
      if (form.editing && form.envWas === "prod" && form.env !== "prod") {
        if (!await this.askConfirm("把分组 " + form.name + " 的环境从 prod 改成 " + form.env + "？这会改变该组主机的权限天花板。")) return;
      }
      const body = Object.assign({
        name: String(form.name || "").trim(),
        label: String(form.label || "").trim(),
        env: form.env,
        policy: form.policy || "",
        protectedPaths: this.lines(form.protected)
      }, this.rulePayload(form));
      try {
        await this.postJSON(form.editing ? "/api/groups/update" : "/api/groups", body);
        this.closeDialogs();
        await this.loadCatalog();
      } catch (err) {
        this.setError("groupForm", err.message);
      }
    },

    async removeGroup(name) {
      if (!await this.askConfirm("删除空分组 " + name + "？")) return;
      this.setError("groups", "");
      try {
        await this.postJSON("/api/groups/remove", { name: name });
        await this.loadCatalog();
      } catch (err) {
        this.setError("groups", err.message);
      }
    },

    openPolicyForm(p) {
      if (!p) {
        this.policyForm = this.blankPolicy();
      } else {
        const create = p.builtin && !p.overridden;
        this.policyForm = {
          editing: true,
          modeKind: create ? "create" : "update",
          title: create ? "覆盖内置 " + p.name : "编辑 " + p.name,
          name: p.name,
          mode: p.mode || "",
          allowMode: p.allowSet ? "list" : "all",
          allow: this.rulesFrom(p.allow),
          deny: this.rulesFrom(p.deny),
          confirm: this.rulesFrom(p.confirm)
        };
      }
      this.setError("policyForm", "");
      this.openDialog("policy");
    },

    async savePolicy() {
      this.setError("policyForm", "");
      const form = this.policyForm;
      const body = Object.assign({
        name: String(form.name || "").trim(),
        mode: form.mode || ""
      }, this.rulePayload(form));
      try {
        await this.postJSON(form.modeKind === "update" ? "/api/policies/update" : "/api/policies", body);
        this.closeDialogs();
        await this.loadCatalog();
        this.loadOps();
      } catch (err) {
        this.setError("policyForm", err.message);
      }
    },

    async removePolicy(p) {
      const msg = p.overridden ? "恢复内置策略 " + p.name + "？" : "删除策略 " + p.name + "？";
      if (!await this.askConfirm(msg)) return;
      this.setError("policy", "");
      try {
        await this.postJSON("/api/policies/remove", { name: p.name });
        await this.loadCatalog();
      } catch (err) {
        this.setError("policy", err.message);
      }
    },

    openEnvForm(e) {
      if (!e) {
        this.envForm = this.blankEnv();
      } else {
        this.envForm = {
          editing: true,
          name: e.name,
          label: e.label || "",
          color: e.color || "",
          maxMode: e.maxMode || "standard",
          defaultPolicy: e.defaultPolicy || ""
        };
      }
      this.setError("envForm", "");
      this.openDialog("env");
    },

    async saveEnv() {
      this.setError("envForm", "");
      const form = this.envForm;
      const body = {
        name: String(form.name || "").trim(),
        label: String(form.label || "").trim(),
        color: String(form.color || "").trim(),
        maxMode: form.maxMode,
        defaultPolicy: form.defaultPolicy || ""
      };
      try {
        await this.postJSON(form.editing ? "/api/envs/update" : "/api/envs", body);
        this.closeDialogs();
        await this.loadCatalog();
      } catch (err) {
        this.setError("envForm", err.message);
      }
    },

    async removeEnv(name) {
      if (!await this.askConfirm("删除环境 " + name + "？仍被分组使用时会失败。")) return;
      this.setError("envs", "");
      try {
        await this.postJSON("/api/envs/remove", { name: name });
        await this.loadCatalog();
      } catch (err) {
        this.setError("envs", err.message);
      }
    },

    syncTagDrafts() {
      const next = {};
      for (const h of this.catalog.hosts || []) next[h.alias] = (h.tags || []).join(",");
      this.tagDraft = next;
    },

    async saveHostTags(alias) {
      this.setError("tags", "");
      try {
        await this.postJSON("/api/hosts/update", { alias: alias, tags: this.commaList(this.tagDraft[alias] || "") });
        await this.loadCatalog();
      } catch (err) {
        this.setError("tags", err.message);
      }
    },

    async applyGroupTags(group, which) {
      const tags = this.commaList(this.tagBulk[group] || "");
      if (!tags.length) {
        this.setError("tags", "先填写标签");
        return;
      }
      this.setError("tags", "");
      const body = { group: group };
      body[which] = tags;
      try {
        await this.postJSON("/api/groups/tags", body);
        this.tagBulk[group] = "";
        await this.loadCatalog();
      } catch (err) {
        this.setError("tags", err.message);
      }
    },

    hostKeys() {
      return (this.detail && this.detail.knownHosts) || [];
    },

    async removeKnown(marker) {
      if (!await this.askConfirm("清除这台主机的信任 " + marker + "？下次连接会重新记录第一把钥匙。")) return;
      this.setError("known", "");
      try {
        await this.postJSON("/api/known-hosts/remove", { marker: marker });
        if (this.view === "host") await this.loadHost();
        else await this.loadKnown();
      } catch (err) {
        this.setError("known", err.message);
      }
    },

    async openSession(alias) {
      if (!alias) {
        this.setError("sessions", "先选择主机。");
        return;
      }
      this.setError("sessions", "");
      try {
        await this.postJSON("/api/sessions/open", { alias: alias });
        this.show("sessions");
        await this.loadSessions();
      } catch (err) {
        this.setError("sessions", err.message);
        this.show("sessions");
      }
    },

    async closeSession(alias) {
      this.setError("sessions", "");
      try {
        await this.postJSON("/api/sessions/close", { alias: alias });
        await this.loadSessions();
      } catch (err) {
        this.setError("sessions", err.message);
      }
    },

    tickSessions() {
      this.metricsClock = Date.now();
      for (const item of this.sessions) {
        if (item.status !== "busy" && item.idleLeftSec > 0) item.idleLeftSec -= 1;
        if (item.lifeLeftSec > 0) item.lifeLeftSec -= 1;
      }
    },

    formatLeft(sec) {
      const n = Number(sec);
      if (!isFinite(n)) return "";
      if (n < 0) return "忙碌，暂不因空闲关闭";
      const s = Math.max(0, Math.floor(n));
      const m = Math.floor(s / 60);
      const r = s % 60;
      if (m <= 0) return r + " 秒";
      return m + " 分 " + r + " 秒";
    },

    idleText(item) {
      if (item.status === "busy") return "忙碌，暂不因空闲关闭";
      return this.formatLeft(item.idleLeftSec);
    },

    applyExecResult(data) {
      if (data.outcome === "not_started") {
        this.execUncertain = false;
        this.setError("operate", data.error || "命令未执行，可修改后重新提交。");
        return;
      }
      if (data.outcome !== "completed" || typeof data.exitCode !== "number") throw new Error(data.error || "未收到完整执行结果");
      this.execUncertain = false;
      const snapshot = this.execSnapshot;
      this.operateOut = (snapshot ? snapshot.alias + " · " + snapshot.command + "\n" : "") + "exit " + data.exitCode + "\n" +
        (data.stdoutSuppressed ? (data.notice || "noDataOutflow: command output discarded") : (data.stdout || "") + (data.stderr || "")) +
        (data.truncated ? "\n[输出已截断，每路最多 64 KiB]" : "");
      if (snapshot && this.exec.alias === snapshot.alias && this.exec.command === snapshot.command) {
        this.exec.command = ""; this.exec.confirm = "";
      }
      this.setError("operate", "");
      this.noteAudit(data);
      this.loadAudit();
    },

    async operationResult(id) {
      const data = await this.readJSON(await this.api("/api/operations/" + id));
      if (data.state === "running") throw new Error("操作仍在执行，请稍后查询。请勿重复执行。");
      if (data.state !== "complete" || !data.result) throw new Error("执行结果未知，请核验远端状态。请勿重复执行。");
      this.noteAudit(data.result);
      return data.result;
    },

    async checkExecResult() {
      if (this.execBusy || !this.execOperationID) return;
      this.execBusy = true;
      try { this.applyExecResult(await this.operationResult(this.execOperationID)); }
      catch (err) { this.setError("operate", err.message); }
      finally { this.execBusy = false; this.persistPending(); }
    },

    async clearExecOperation() {
      if (this.execBusy || !await this.askConfirm("请先核验原主机上的命令结果。清除记录后重新执行可能重复写入，确认已核验？")) return;
      this.execUncertain = false; this.execOperationID = ""; this.execSnapshot = null; this.persistPending();
      this.setError("operate", "");
    },

    async runExec() {
      if (this.execBusy || this.execUncertain) return;
      this.execBusy = true;
      this.setError("operate", "");
      this.operateOut = "";
      try {
        const payload = {
          alias: this.exec.alias,
          command: this.exec.command,
          timeout: this.exec.timeout || this.draft.commandTimeout || "",
          confirm: this.exec.confirm || "",
          allowOutflow: !!this.exec.allowOutflow,
          operationId: operationID()
        };
        this.execSnapshot = payload;
        this.execOperationID = payload.operationId; this.persistPending();
        this.applyExecResult(await this.postJSON("/api/exec", payload));
      } catch (err) {
        this.execUncertain = err.outcome !== "not_started" && err.outcome !== "completed";
        this.setError("operate", err.message + (this.execUncertain ? "；请查询原操作结果并核验远端状态，不要直接重复执行。" : err.outcome === "completed" ? "；远端操作已结束，请核对返回结果。" : "；未执行，可修改后重新提交。"));
      } finally {
        this.execBusy = false; this.persistPending();
      }
    },

    async upload(ev) {
      if (this.uploadBusy) return;
      this.uploadBusy = true;
      this.setError("operate", "");
      const fd = new FormData(ev.target);
      try {
        const results = await this.enqueueUploads([fd.get("file")], String(fd.get("remote") || ""), String(fd.get("alias") || ""), String(fd.get("confirm") || ""));
        if (!results) return;
        const item = results[0];
        if (item && item.label === "完成") {
          const current = new FormData(ev.target);
          if (["alias", "remote", "confirm", "file"].every((key) => current.get(key) === fd.get(key))) ev.target.reset();
          this.operateOut = "上传完成"; this.loadAudit();
        }
        else this.setError("operate", item ? item.label + "：" + (item.error || item.name) : "请检查传输队列。");
      } catch (err) { this.setError("operate", err.message); }
      finally { this.uploadBusy = false; }
    },

    async download(ev) {
      const fd = new FormData(ev.target);
      const remote = String(fd.get("path") || "");
      await this.wsDownload({ path: remote, name: remote.split("/").pop() || "download" }, String(fd.get("alias") || ""));
    },

    async runRelay() {
      this.setError("relay", "");
      try {
        const data = await this.postJSON("/api/relay", {
          from: this.relay.from,
          fromPath: this.relay.fromPath,
          to: this.relay.to,
          toPath: this.relay.toPath,
          confirm: this.relay.confirm || "",
          allowCrossEnv: !!this.relay.allowCrossEnv
        });
        this.operateOut = "relay " + data.algo + " " + data.sum + " " + data.bytes + " bytes";
        this.relay.fromPath = "";
        this.relay.toPath = "";
        this.relay.confirm = "";
        this.loadAudit();
      } catch (err) {
        this.setError("relay", err.message);
      }
    },

    toggleHost(alias, checked) {
      this.selected[alias] = !!checked;
    },

    togglePage(checked) {
      this.pickAll = !!checked;
      for (const h of this.filteredHosts()) this.selected[h.alias] = !!checked;
    },

    selectedAliases() {
      const out = [];
      for (const alias of Object.keys(this.selected)) {
        if (this.selected[alias]) out.push(alias);
      }
      return out;
    },

    selectedText() {
      const aliases = this.selectedAliases();
      if (!aliases.length) return "还没有选中主机。回到表格勾选后再打开。";
      return "将在这些主机上执行：" + aliases.join(", ");
    },

    openBatch() {
      if (!this.batchBusy && !this.batchUncertain) {
        this.batchOut = "";
        this.batchPreview = null;
        this.batchPreviewKey = "";
        this.setError("batch", "");
      }
      this.openDialog("batch");
    },

    batchPayload() {
      return {
        aliases: this.selectedAliases(),
        command: this.batchCommand,
        timeout: this.exec.timeout || this.draft.commandTimeout || "",
        parallel: Number(this.batchParallel || 2),
        skipDenied: !!this.batchSkip,
        allowCrossEnv: !!this.batchCross,
        allowOutflow: !!this.exec.allowOutflow,
        confirms: {}
      };
    },

    async previewBatch() {
      if (this.batchBusy || this.batchUncertain) return;
      this.batchBusy = true;
      this.batchPreview = null;
      try {
        const payload = this.batchPayload();
        const data = await this.postJSON("/api/exec/preview", payload);
        this.batchPreview = data;
        this.batchPreviewKey = JSON.stringify(payload);
        this.batchOut = data.notice + "\n\n" + data.hosts.map((h) => h.alias + " · " + h.env + " · " + h.user + "@" + h.address + " · " + h.mode + " · " + (!h.allowed ? "拒绝：" + h.reason : h.needsConfirm ? "需要确认" : "允许") + (h.outputSuppressed ? " · 不带回输出" : "")).join("\n");
      } catch (err) { this.batchOut = this.explain(err.message); }
      finally { this.batchBusy = false; this.persistPending(); }
    },

    async checkBatchResult() {
      if (this.batchBusy || !this.batchOperationID) return;
      this.batchBusy = true;
      try {
        const result = await this.operationResult(this.batchOperationID);
        this.batchUncertain = result.outcome === "unknown" || (result.results || []).some((row) => row.outcome === "unknown");
        this.batchPreview = null;
        this.batchOut = result.results ? batchSummary(result.results).text : (result.error || "操作结束");
      } catch (err) { this.batchOut = this.explain(err.message); }
      finally { this.batchBusy = false; this.persistPending(); }
    },

    async clearBatchOperation() {
      if (this.batchBusy || !await this.askConfirm("请先核验远端状态。清除记录后重新执行可能重复写入，确认已核验？")) return;
      this.batchUncertain = false;
      this.batchOperationID = ""; this.persistPending();
      this.batchPreview = null;
      this.batchOut = "";
    },

    async submitBatch() {
      if (this.batchBusy || this.batchUncertain) return;
      const payload = this.batchPayload();
      if (!this.batchPreview || this.batchPreviewKey !== JSON.stringify(payload)) { await this.previewBatch(); return; }
      if (!this.batchPreview.canExecute) { this.batchOut += "\n预检未通过，请调整后重新预检。"; return; }
      payload.planDigest = this.batchPreview.planDigest;
      payload.operationId = operationID();
      this.batchOperationID = payload.operationId; this.persistPending();
      this.batchBusy = true;
      let sent = false;
      this.batchOut = "正在执行，请勿重复提交。";
      try {
        let data;
        for (let attempt = 0; attempt < 8; attempt++) {
          sent = true;
          const res = await this.api("/api/exec/batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });
          data = await this.parseJSON(res);
          if (res.status === 202) {
            this.batchUncertain = true;
            this.batchOut = "操作已接收，请查询结果。";
            return;
          }
          if (res.status === 409 && data.needsConfirm) {
            sent = false;
            if (data.confirmField === "outflowConfirm") {
              const typed = await this.ask((data.error || "需要确认") + "\n请输入：" + data.confirm);
              if (typed == null) throw new Error(data.error || "已取消");
              payload.outflowConfirm = typed;
              continue;
            }
            const pending = data.aliases || payload.aliases;
            for (let i = 0; i < pending.length; i++) {
              const alias = pending[i];
              if (payload.confirms[alias]) continue;
              const typed = await this.ask("主机 " + alias + " 需要确认。请输入主机别名。\n命令：" + payload.command);
              if (typed == null) throw new Error("已取消");
              payload.confirms[alias] = String(typed).trim();
            }
            continue;
          }
          if (!res.ok || data.ok === false) {
            sent = res.status >= 500;
            if (data.planChanged) this.batchPreview = null;
            throw new Error(friendlyError(data.error, res.statusText));
          }
          break;
        }
        if (!data || !data.results) throw new Error("确认未完成，请重新预检。");
        this.batchOut = batchSummary(data.results).text;
        this.batchUncertain = data.results.some((row) => row.outcome === "unknown");
        this.batchPreview = null;
        this.loadAudit();
        this.loadDashboard();
      } catch (err) {
        this.batchUncertain = sent;
        this.batchOut = this.explain(err.message) + (sent ? "\n执行结果未知，请查询操作记录并核验远端状态，不要重复执行。" : "");
      } finally { this.batchBusy = false; this.persistPending(); }
    },

    batchCommand: "",
    batchParallel: 2,
    batchSkip: false,
    batchCross: false,

    looksSecret(text) {
      return /(^|\n)\s*(password|secret|masterkey|master_key)\s*:/i.test(String(text || ""));
    },

    async exportBundle() {
      this.setError("bundle", "");
      try {
        const data = await this.readJSON(await this.api("/api/config/export"));
        const yaml = data.yaml || "";
        if (this.looksSecret(yaml)) throw new Error("导出里出现了明文口令字段，已停止显示");
        this.bundleYaml = yaml;
      } catch (err) {
        this.setError("bundle", err.message);
      }
    },

    async importBundle() {
      this.setError("bundle", "");
      if (this.looksSecret(this.bundleImport)) {
        this.setError("bundle", "导入文本含有 password、secret 或 masterKey 字段。配置包不能带明文口令。");
        return;
      }
      try {
        await this.postJSON("/api/config/import", { yaml: this.bundleImport });
        this.bundleImport = "";
        await this.loadCatalog();
        this.setError("bundle", "");
      } catch (err) {
        this.setError("bundle", err.message);
      }
    },

    async cleanupOps() {
      await this.cleanupAudit();
      await this.loadOps();
    },

    hmacText() {
      return hmacView(this.ops && this.ops.hmac, this.dash && this.dash.hmac).text;
    },

    hmacClass() {
      return hmacView(this.ops && this.ops.hmac, this.dash && this.dash.hmac).className;
    },

    anyDialog() {
      return this.hostPickerOpen || Object.values(this.dialog).some(Boolean);
    },

    openDialog(name) {
      if (this.hostPickerOpen) this.closeHostPicker();
      if (!this.anyDialog()) dialogReturnFocus = document.activeElement;
      this.dialog[name] = true;
      document.body.classList.add("overflow-hidden");
      setTimeout(() => {
        const modal = this.activeDialog();
        if (!modal) return;
        const target = Array.from(modal.querySelectorAll("input:not([type=checkbox]), textarea, select, button:not(.btn-close)")).find((el) => !el.disabled && el.getClientRects().length);
        (target || modal).focus();
      }, 0);
    },

    activeDialog() {
      return Array.from(document.querySelectorAll('[role="dialog"]')).filter((el) => el.getClientRects().length).pop();
    },

    dialogKey(ev) {
      if (this.hostPickerOpen) {
        if (ev.key === "Escape") { ev.preventDefault(); this.closeHostPicker(); }
        return; // The native dialog manages its own Tab cycle.
      }
      if (ev.key === "Escape") { ev.preventDefault(); this.closeDialogs(); return; }
      if (ev.key !== "Tab") return;
      const modal = this.activeDialog();
      if (!modal) return;
      const items = Array.from(modal.querySelectorAll('button, input, select, textarea, a[href], [tabindex="0"]')).filter((el) => !el.disabled && el.getClientRects().length);
      const first = items[0] || modal, last = items[items.length - 1] || modal;
      if (!modal.contains(document.activeElement) || (ev.shiftKey && document.activeElement === first) || (!ev.shiftKey && document.activeElement === last)) {
        ev.preventDefault(); (ev.shiftKey ? last : first).focus();
      }
    },

    ask(message, value, kind) {
      return new Promise((resolve) => {
        promptQueue.push({ message: message, value: value || "", kind: kind || "text", resolve: resolve });
        this.nextPrompt();
      });
    },

    askConfirm(message) { return this.ask(message, "", "confirm"); },

    nextPrompt() {
      if (promptResolve || !promptQueue.length) return;
      const next = promptQueue.shift();
      promptResolve = next.resolve;
      this.confirmView = { message: next.message, value: next.value, kind: next.kind };
      this.openDialog("confirm");
    },

    answerPrompt(accepted) {
      const resolve = promptResolve;
      const value = this.confirmView.kind === "confirm" ? !!accepted : (accepted ? this.confirmView.value : null);
      promptResolve = null;
      this.dialog.confirm = false;
      if (resolve) resolve(value);
      this.restoreDialogFocus();
      this.nextPrompt();
    },

    restoreDialogFocus() {
      setTimeout(() => {
        if (!this.anyDialog()) {
          document.body.classList.remove("overflow-hidden");
          if (dialogReturnFocus && dialogReturnFocus.isConnected) dialogReturnFocus.focus();
        } else {
          const modal = this.activeDialog();
          if (modal) modal.focus();
        }
      }, 0);
    },

    closeDialogs() {
      if (this.hostPickerOpen) { this.closeHostPicker(); return; }
      if (this.dialog.confirm) { this.answerPrompt(false); return; }
      Object.keys(this.dialog).forEach((key) => { this.dialog[key] = false; });
      this.restoreDialogFocus();
    },

    sortedHosts() {
      return (this.catalog.hosts || []).slice().sort((a, b) => String(a.alias).localeCompare(String(b.alias)));
    },

    hostFilterState(scope) { return scope === "terminal" ? this.termFilter : this.hostFilter; },

    hostMatches(h, scope, except) {
      const f = this.hostFilterState(scope);
      if (except !== "env" && f.env.length && !f.env.includes(h.env)) return false;
      if (except !== "group" && f.group.length && !f.group.includes(h.group)) return false;
      const q = String(scope === "terminal" ? f.query : this.q.hosts).trim().toLowerCase();
      if (!q) return true;
      const group = this.groupByName(h.group), env = (this.catalog.envs || []).find(e => e.name === h.env);
      return [h.alias, h.group, group && group.label, h.env, env && env.label, h.host, h.user, h.via, (h.tags || []).join(" ")].join(" ").toLowerCase().includes(q);
    },

    hostFacetOptions(scope, kind) {
      const counts = Object.create(null), available = Object.create(null);
      for (const h of this.catalog.hosts || []) {
        available[h[kind]] = true;
        if (this.hostMatches(h, scope, kind)) counts[h[kind]] = (counts[h[kind]] || 0) + 1;
      }
      const items = kind === "env" ? this.sortedEnvs() : this.sortedGroups();
      const order = ["dev", "test", "preprod", "prod"];
      if (kind === "env") items.sort((a, b) => {
        const ai = order.indexOf(a.name), bi = order.indexOf(b.name);
        return (ai < 0 ? 4 : ai) - (bi < 0 ? 4 : bi) || a.name.localeCompare(b.name);
      });
      return items.map(item => ({ value: item.name, label: item.label ? item.label + (kind === "env" && order.includes(item.name) ? "" : " · " + item.name) : item.name, title: item.label ? item.label + " · " + item.name : item.name, count: counts[item.name] || 0, available: !!available[item.name] }));
    },

    toggleHostFilter(scope, kind, value) {
      if (kind !== "env" && kind !== "group") return;
      const f = this.hostFilterState(scope);
      f[kind] = !value ? [] : f[kind].includes(value) ? f[kind].filter(v => v !== value) : f[kind].concat(value);
      if (scope === "terminal") this.hostPickerFilterChanged();
      else { this.pickAll = false; this.resetPage("hosts"); }
    },

    clearHostFilters(scope) {
      const f = this.hostFilterState(scope); f.env = []; f.group = [];
      if (scope === "terminal") { f.query = ""; this.hostPickerFilterChanged(); }
      else { this.q.hosts = ""; this.pickAll = false; this.resetPage("hosts"); }
    },

    reconcileHostFilters() {
      for (const scope of ["hosts", "terminal"]) for (const kind of ["env", "group"]) {
        const names = new Set((this.catalog[kind === "env" ? "envs" : "groups"] || []).map(x => x.name));
        const f = this.hostFilterState(scope); f[kind] = f[kind].filter(value => names.has(value));
      }
    },

    hostSelectionSummary() {
      const selected = this.selectedAliases(), visible = new Set(this.matchHosts().map(h => h.alias));
      const hidden = selected.filter(alias => !visible.has(alias)).length;
      return "已选 " + selected.length + " 台" + (hidden ? "，其中 " + hidden + " 台不在当前筛选中" : "");
    },

    terminalHostCaption() {
      const host = this.hostByAlias(this.termAlias);
      return host ? [host.env, this.groupCaption(this.groupByName(host.group)) || host.group].join(" · ") : "按环境、分组查找";
    },

    terminalHostMatches() { return this.sortedHosts().filter(h => this.hostMatches(h, "terminal")); },
    terminalHostChoices() { return this.terminalHostMatches().slice(0, this.hostPickerLimit); },

    hostPickerFilterChanged() {
      this.hostPickerLimit = 40;
      if (this.hostPickerOpen) this.$nextTick(() => this.positionHostPicker());
    },

    openHostPicker() {
      const dialog = document.getElementById("terminal-host-picker");
      if (!dialog || typeof dialog.showModal !== "function") { this.show("hosts"); return; }
      this.hostPickerLimit = 40; this.hostPickerOpen = true;
      if (!dialog.open) dialog.showModal();
      if (typeof ResizeObserver !== "undefined" && !hostPickerResize) {
        hostPickerResize = new ResizeObserver(() => { if (this.hostPickerOpen) this.positionHostPicker(); });
        hostPickerResize.observe(dialog);
      }
      this.$nextTick(() => {
        if (!this.hostPickerOpen || !dialog.open) return;
        this.positionHostPicker();
        const input = document.getElementById("terminal-host-search");
        if (input) input.focus();
      });
    },

    closeHostPicker() {
      const dialog = document.getElementById("terminal-host-picker");
      if (dialog && dialog.open) dialog.close();
      this.hostPickerClosed();
      const trigger = document.getElementById("terminal-host-choice");
      if (trigger && this.view === "terminal" && trigger.getClientRects().length) trigger.focus({ preventScroll: true });
    },

    hostPickerClosed() {
      const dialog = document.getElementById("terminal-host-picker");
      if (dialog && dialog.open) return; // Ignore an older close event after a rapid reopen.
      this.hostPickerOpen = false;
      if (hostPickerResize) { hostPickerResize.disconnect(); hostPickerResize = null; }
    },

    positionHostPicker() {
      const dialog = document.getElementById("terminal-host-picker"), trigger = document.getElementById("terminal-host-choice");
      if (!dialog || !dialog.open || !trigger) return;
      const viewport = window.visualViewport, width = viewport ? viewport.width : window.innerWidth, height = viewport ? viewport.height : window.innerHeight;
      const x = viewport ? viewport.offsetLeft : 0, y = viewport ? viewport.offsetTop : 0;
      dialog.style.width = Math.max(0, Math.min(520, width - 24)) + "px";
      dialog.style.maxHeight = Math.max(0, height - 24) + "px";
      const anchor = trigger.getBoundingClientRect(), box = dialog.getBoundingClientRect();
      dialog.style.left = (x + Math.max(12, Math.min(anchor.right - x - box.width, width - box.width - 12))) + "px";
      dialog.style.top = (y + Math.max(12, Math.min(anchor.bottom - y + 6, height - box.height - 12))) + "px";
    },

    hostPickerBackdrop(ev) {
      if (ev.target !== ev.currentTarget) return;
      const r = ev.currentTarget.getBoundingClientRect();
      if (ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom) this.closeHostPicker();
    },

    chooseTerminalHost(alias) {
      if (!this.terminalHostMatches().some(h => h.alias === alias)) return;
      this.termAlias = alias; this.onTermHost(); this.closeHostPicker();
    },

    moreTerminalHosts() {
      const previous = this.hostPickerLimit; this.hostPickerLimit += 40;
      this.$nextTick(() => {
        this.positionHostPicker();
        const rows = document.querySelectorAll("#terminal-host-picker .host-choice");
        if (rows[previous]) rows[previous].focus();
      });
    },

    hostPickerKey(ev) {
      if (ev.isComposing || ev.keyCode === 229 || ev.ctrlKey || ev.metaKey || ev.altKey) return;
      const search = ev.target && ev.target.id === "terminal-host-search";
      if (search && ev.key === "Enter") {
        ev.preventDefault();
        const matches = this.terminalHostMatches();
        if (matches.length === 1) { this.chooseTerminalHost(matches[0].alias); return; }
      } else if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(ev.key) || (search && ev.key !== "ArrowDown")) return;
      const rows = Array.from(ev.currentTarget.querySelectorAll(".host-choice"));
      const index = rows.indexOf(ev.target);
      if (!search && index < 0) return;
      ev.preventDefault();
      if (ev.key === "ArrowUp" && index === 0) { document.getElementById("terminal-host-search").focus(); return; }
      const target = ev.key === "Home" ? 0 : ev.key === "End" ? rows.length - 1 : search ? 0 : Math.max(0, Math.min(rows.length - 1, index + (ev.key === "ArrowUp" ? -1 : 1)));
      if (rows[target]) rows[target].focus();
    },

    sortedGroups() {
      return (this.catalog.groups || []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
    },

    sortedEnvs() {
      return (this.catalog.envs || []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
    },

    sortedPolicies() {
      return (this.catalog.policies || []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
    },

    matchHosts() {
      return this.sortedHosts().filter(h => this.hostMatches(h, "hosts"));
    },

    filteredHosts() {
      return this.slicePage(this.matchHosts(), "hosts");
    },

    hostTotal() {
      return this.matchHosts().length;
    },

    matchGroups() {
      const q = String(this.q.groups || "").trim().toLowerCase();
      return this.sortedGroups().filter((g) => {
        if (!q) return true;
        const blob = [g.name, g.label || "", g.env, g.policy || ""].join(" ").toLowerCase();
        return blob.indexOf(q) >= 0;
      });
    },

    filteredGroups() {
      return this.slicePage(this.matchGroups(), "groups");
    },

    groupTotal() {
      return this.matchGroups().length;
    },

    matchTagGroups() {
      const q = String(this.q.tags || "").trim().toLowerCase();
      return this.sortedGroups().filter((g) => {
        if (!q) return true;
        const hosts = this.hostsIn(g.name);
        let blob = g.name + " " + (g.label || "") + " " + g.env;
        for (const h of hosts) blob += " " + h.alias + " " + (h.tags || []).join(" ");
        return blob.toLowerCase().indexOf(q) >= 0;
      });
    },

    filteredTagGroups() {
      return this.slicePage(this.matchTagGroups(), "tags");
    },

    tagTotal() {
      return this.matchTagGroups().length;
    },

    hostsIn(name) {
      return this.sortedHosts().filter((h) => h.group === name);
    },

    matchEnvs() {
      const q = String(this.q.envs || "").trim().toLowerCase();
      return this.sortedEnvs().filter((e) => {
        if (!q) return true;
        return (e.name + " " + (e.label || "")).toLowerCase().indexOf(q) >= 0;
      });
    },

    filteredEnvs() {
      return this.slicePage(this.matchEnvs(), "envs");
    },

    envTotal() {
      return this.matchEnvs().length;
    },

    matchPolicies() {
      const q = String(this.q.policy || "").trim().toLowerCase();
      return (this.catalog.policies || []).filter((p) => !q || String(p.name).toLowerCase().indexOf(q) >= 0);
    },

    filteredPolicies() {
      return this.slicePage(this.matchPolicies(), "policy");
    },

    policyTotal() {
      return this.matchPolicies().length;
    },

    matchKnown() {
      const q = String(this.q.known || "").trim().toLowerCase();
      return (this.known || []).filter((entry) => {
        if (!q) return true;
        return (entry.marker + " " + entry.keyType + " " + entry.fingerprint).toLowerCase().indexOf(q) >= 0;
      });
    },

    filteredKnown() {
      return this.slicePage(this.matchKnown(), "known");
    },

    knownTotal() {
      return this.matchKnown().length;
    },

    filteredSessions() {
      return this.slicePage(this.sessions || [], "sessions");
    },

    sessionTotal() {
      return (this.sessions || []).length;
    },

    slicePage(rows, key) {
      const st = this.pages[key];
      const size = st.size || DEFAULT_PAGE_SIZE;
      const pages = Math.max(1, Math.ceil(rows.length / size) || 1);
      const page = Math.min(Math.max(1, st.page), pages);
      const start = (page - 1) * size;
      return rows.slice(start, start + size);
    },

    pageCount(key) {
      const totals = {
        hosts: this.hostTotal(),
        groups: this.groupTotal(),
        tags: this.tagTotal(),
        envs: this.envTotal(),
        policy: this.policyTotal(),
        known: this.knownTotal(),
        sessions: this.sessionTotal()
      };
      const size = this.pages[key].size || DEFAULT_PAGE_SIZE;
      return Math.max(1, Math.ceil((totals[key] || 0) / size) || 1);
    },

    pageMeta(key) {
      const totals = {
        hosts: this.hostTotal(),
        groups: this.groupTotal(),
        tags: this.tagTotal(),
        envs: this.envTotal(),
        policy: this.policyTotal(),
        known: this.knownTotal(),
        sessions: this.sessionTotal()
      };
      return "共 " + (totals[key] || 0) + " 条";
    },

    pageFrac(key) {
      return this.pages[key].page + " / " + this.pageCount(key);
    },

    prevPage(key) {
      if (this.pages[key].page > 1) this.pages[key].page -= 1;
    },

    nextPage(key) {
      if (this.pages[key].page < this.pageCount(key)) this.pages[key].page += 1;
    },

    setPage(key, n) {
      const max = this.pageCount(key);
      const page = Math.min(Math.max(1, Number(n) || 1), max);
      this.pages[key].page = page;
    },

    pageWindow(key) {
      return this._pageWindow(this.pages[key].page, this.pageCount(key));
    },

    _pageWindow(current, total) {
      const pages = Math.max(1, total || 1);
      const cur = Math.min(Math.max(1, current || 1), pages);
      const start = Math.max(1, Math.min(cur - 1, pages - 2));
      const end = Math.min(pages, start + 2);
      const out = [];
      for (let i = start; i <= end; i++) out.push(i);
      return out.length ? out : [1];
    },

    goPage(key) {
      const n = parseInt(String(this.pages[key].jump || "").trim(), 10);
      if (!Number.isFinite(n) || n < 1) return;
      const page = Math.min(Math.floor(n), this.pageCount(key));
      this.pages[key].jump = String(page);
      this.pages[key].page = page;
    },

    resetPage(key) {
      this.pages[key].page = 1;
    },

    setPageSize(key) {
      const size = Number(this.pages[key].size);
      this.pages[key].size = PAGE_SIZES.indexOf(size) >= 0 ? size : DEFAULT_PAGE_SIZE;
      this.pages[key].page = 1;
    },

    clampPage(key) {
      const pages = this.pageCount(key);
      if (this.pages[key].page > pages) this.pages[key].page = pages;
      if (this.pages[key].page < 1) this.pages[key].page = 1;
    },

    clampAll() {
      for (const key of Object.keys(this.pages)) this.clampPage(key);
    },

    allowLabel(row) {
      if (!row || !row.allowSet) return "全集";
      if (!row.allow || !row.allow.length) return "（空）";
      return row.allow.join(", ");
    },

    listLabel(items) {
      if (!items || !items.length) return "";
      return items.join(", ");
    },

    sourceLabel(p) {
      if (p.overridden) return "覆盖内置";
      if (p.builtin) return "内置";
      return "自定义";
    },

    policyOption(p) {
      if (p.overridden) return p.name + "（已覆盖）";
      if (p.builtin) return p.name + "（内置）";
      return p.name;
    },

    groupCaption(g) {
      if (!g) return "";
      return g.label ? g.name + " / " + g.label : g.name;
    },

    groupByName(name) {
      return (this.catalog.groups || []).find((g) => g.name === name);
    },

    envBadge(color) {
      const known = { green: "badge bg-green-lt", yellow: "badge bg-yellow-lt", orange: "badge bg-orange-lt", red: "badge bg-red-lt", blue: "badge bg-blue-lt" };
      return known[color] || "badge bg-secondary-lt";
    },

    policySummary(policy) {
      if (!policy) return "";
      if (policy.allowUniversal) return "全集";
      if (policy.allowEmpty) return "空列表";
      return (policy.allow || []).join(", ");
    },

    capText(policy) {
      const caps = (policy && policy.capabilities) || {};
      const up = caps.upload ? "可上传" : "不可上传";
      const down = caps.download ? "可下载" : "不可下载";
      return up + " / " + down;
    },

    relayCap(policy) {
      const caps = (policy && policy.capabilities) || {};
      return caps.relay || "未单独设置";
    },

    outflowText(policy) {
      if (policy && policy.noDataOutflow) return "禁止带回输出，除非确认 outflow";
      return "允许";
    },

    joinList(items, empty) {
      if (!items || !items.length) return empty;
      return items.join(", ");
    },

    warnText(policy) {
      if (!policy || !policy.warnings || !policy.warnings.length) return "";
      return policy.warnings.join(" ");
    },

    sessionLine() {
      const items = this.detail.sessions || [];
      if (!items.length) return "这台主机在这个进程里没有打开的会话。";
      return "当前会话：" + items.map((s) => (s.status || "open") + "，空闲剩余 " + (s.idleLeft || "")).join("；");
    },

    auditSummary() {
      const stats = this.audit.stats || {};
      return "日志 " + (stats.files || 0) + " 个文件，" + (stats.entries || 0) + " 条，" + (stats.bytes || 0) + " 字节 · 筛选 " + (this.audit.total || 0) + " 条";
    },

    dashEntries() {
      if (this.dash && this.dash.auditCli != null) return this.dash.auditCli;
      return 0;
    },

    opsEntries() {
      return (this.ops.audit && this.ops.audit.entries) || 0;
    },

    taggedCount() {
      return (this.catalog.hosts || []).filter((h) => h.tags && h.tags.length).length;
    }
  };
}

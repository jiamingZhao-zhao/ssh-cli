const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZES = [10, 20, 50];
const termMap = new Map();
const transferCtl = new Map();
let chartDays = null;
let chartOps = null;
let netChart = null;
let rangePicker = null;
let suppressRange = false;
const promptQueue = [];
let promptResolve = null;
let dialogReturnFocus = null;

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
  if (!res.body || !res.body.getReader) return lastJSONObject(await res.text());
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
  return finalMsg || {};
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
    rx.push(Math.round(rows[i].rxRate || 0));
    tx.push(Math.round(rows[i].txRate || 0));
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
        { type: "bar", label: "收", data: rx, backgroundColor: "rgba(0,82,204,0.55)", borderRadius: 3, order: 2 },
        { type: "line", label: "发", data: tx, borderColor: "#36b37e", backgroundColor: "transparent", tension: 0.25, pointRadius: 2, borderWidth: 2, order: 1 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { position: "bottom", labels: { color: theme.ink, boxWidth: 10 } } },
      scales: {
        x: { ticks: { color: theme.ink, maxTicksLimit: 6 }, grid: { color: theme.grid } },
        y: { beginAtZero: true, ticks: { color: theme.ink }, grid: { color: theme.grid } }
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
    workspaceCache: Object.create(null),
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
    ws: { side: 280, lower: 280 },
    metrics: { alias: "", connected: false, address: "", port: "", user: "", hostname: "", uptime: "", load: "", cpuPercent: null, mem: null, swap: null, procs: [], disks: [], notes: [], netRx: 0, netTx: 0, netRxRate: 0, netTxRate: 0 },
    netSeries: {},
    metricsTimer: 0,
    metricsSeq: 0,
    metricsBusy: "",
    metricsFailures: 0,
    metricsUpdated: 0,
    readAbort: {},
    files: { alias: "", mode: "files", path: "", parent: "", home: "", crumbs: [], entries: [], truncated: false },
    procView: { pid: "", ppid: "", user: "", cpu: "", mem: "", memPct: "", stat: "", etime: "", cmd: "", cwd: "", cwdNote: "" },
    drop: { over: false, target: "", label: "" },
    transfers: [],
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
      });
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) this.stopMetrics();
        else if (this.view === "terminal") this.startMetrics();
      });
      window.addEventListener("beforeunload", (ev) => {
        if (this.termTabs.some((tab) => tab.state === "connected") || this.transfers.some((t) => t.active) || this.batchBusy || this.batchUncertain) {
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
      if (prefs.wsLower >= 160 && prefs.wsLower <= 520) this.ws.lower = prefs.wsLower;
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
      const parsed = this.readHash(name);
      const view = this.viewAlias[parsed.view] || "home";
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
        return m + "。打开主机详情看命中的规则。内置硬拒绝不能在页面里关闭。";
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

    async api(url, options) {
      const opts = Object.assign({ credentials: "same-origin" }, options || {});
      const method = String(opts.method || "GET").toUpperCase();
      if (method !== "GET" && method !== "HEAD" && !this.csrf) await this.ensureSession();
      const headers = Object.assign({}, opts.headers || {});
      const token = sessionStorage.getItem("sshCliBearer") || "";
      if (token) headers.Authorization = "Bearer " + token;
      if (this.csrf) headers["X-CSRF-Token"] = this.csrf;
      opts.headers = headers;
      let res = await fetch(url, opts);
      if (res.status === 401) {
        const typed = await this.ask("这个监听地址要求 Bearer token。请粘贴启动 ssh-cli ui 时打印的那一行。", "", "password");
        if (typed == null || !String(typed).trim()) throw new Error("需要 Bearer token");
        sessionStorage.setItem("sshCliBearer", String(typed).trim());
        headers.Authorization = "Bearer " + String(typed).trim();
        opts.headers = headers;
        res = await fetch(url, opts);
      }
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
        return JSON.parse(trimmed);
      } catch (err) {
        throw new Error(plainBodyMessage(trimmed, res.statusText));
      }
    },

    async readJSON(res) {
      const data = await this.parseJSON(res);
      if (!res.ok || data.ok === false) throw new Error(friendlyError(data && data.error, res.statusText));
      return data;
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
      const ctrl = this.readAbort && this.readAbort[key];
      if (ctrl) ctrl.abort();
      if (this.readAbort) delete this.readAbort[key];
    },

    async postRead(url, body, signal) {
      await this.ensureSession();
      const res = await this.api(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
        signal: signal
      });
      return this.readJSON(res);
    },

    async postJSON(url, body) {
      await this.ensureSession();
      const payload = Object.assign({}, body);
      for (let attempt = 0; attempt < 4; attempt++) {
        const res = await this.api(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await this.parseJSON(res);
        if (res.status === 409 && data.needsConfirm) {
          const typed = await this.ask((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
          if (typed == null) throw new Error(data.error || "已取消");
          if (data.confirmField) payload[data.confirmField] = typed;
          else payload.confirm = typed;
          payload.humanConfirm = payload.humanConfirm || typed;
          continue;
        }
        if (!res.ok || data.ok === false) throw new Error(friendlyError(data.error, res.statusText));
        return data;
      }
      throw new Error("确认失败");
    },

    async loadCatalog() {
      this.setError("hosts", "");
      try {
        this.catalog = await this.readJSON(await this.api("/api/catalog"));
        if (!this.catalog.hosts) this.catalog.hosts = [];
        if (!this.catalog.groups) this.catalog.groups = [];
        if (!this.catalog.envs) this.catalog.envs = [];
        if (!this.catalog.policies) this.catalog.policies = [];
        this.syncTagDrafts();
        if (!this.exec.alias && this.catalog.hosts.length) this.exec.alias = this.catalog.hosts[0].alias;
        if (!this.termAlias && this.catalog.hosts.length) this.termAlias = this.catalog.hosts[0].alias;
        if (!this.relay.from && this.catalog.hosts.length) {
          this.relay.from = this.catalog.hosts[0].alias;
          this.relay.to = this.catalog.hosts[0].alias;
        }
        this.clampAll();
      } catch (err) {
        this.setError("hosts", err.message);
      }
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
      this.setError("sessions", "");
      try {
        const data = await this.readJSON(await this.api("/api/sessions"));
        this.sessions = data.sessions || [];
        if (this.explicitAlias && !this.sessions.some((item) => item.alias === this.explicitAlias)) {
          this.explicitAlias = "";
          if (this.view === "terminal") this.syncWorkspace();
        }
        if (this.dash) this.dash.sessions = this.sessions.length;
        this.clampPage("sessions");
      } catch (err) {
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
      const id = "t" + Date.now().toString(36) + this.termTabs.length;
      const pane = document.createElement("div");
      pane.className = "term-pane";
      pane.dataset.id = id;
      screen.appendChild(pane);
      const term = new Terminal({
        cursorBlink: true,
        fontFamily: '"SF Mono", Menlo, Consolas, monospace',
        fontSize: 14,
        theme: { background: "#1d1d1f", foreground: "#f5f5f7", cursor: "#f5f5f7" }
      });
      const fit = new FitAddon.FitAddon();
      term.loadAddon(fit);
      term.open(pane);
      fit.fit();
      const app = this;
      let opened;
      try {
        opened = await this.postJSON("/api/terminal/open", { alias: alias, cols: term.cols || 80, rows: term.rows || 24 });
      } catch (err) {
        term.dispose();
        pane.remove();
        this.setError("terminal", err.message || "终端连接失败");
        return;
      }
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(proto + "//" + location.host + "/api/terminal/ws?ticket=" + encodeURIComponent(opened.ticket));
      ws.binaryType = "arraybuffer";
      const entry = { id: id, alias: alias, term: term, fit: fit, ws: ws, pane: pane, saw: false, hadError: false, maxLife: false };
      termMap.set(id, entry);
      this.termTabs.push({ id: id, alias: alias, busy: true, state: "connecting" });
      if (typeof ResizeObserver !== "undefined") {
        entry.observer = new ResizeObserver(() => { if (app.termActive === id) app.fitActive(); });
        entry.observer.observe(pane);
      }
      this.showPane(id);
      const closeLine = (ev) => {
        const code = ev && Number(ev.code);
        if (code) return "终端连接已断开 (" + code + ")";
        return "终端连接已断开";
      };
      const writeFrame = (data) => {
        if (typeof data === "string") term.write(data);
        else term.write(new Uint8Array(data));
      };
      ws.onmessage = (ev) => {
        entry.saw = true;
        app.markTabIdle(id);
        const text = typeof ev.data === "string" ? ev.data : "";
        if (text.indexOf("已达到最长时限") >= 0) {
          entry.maxLife = true;
          term.write(text);
          app.setError("terminal", "会话已达到最长时限，连接已关闭");
          app.toast("会话已达到最长时限，连接已关闭", "bad");
          return;
        }
        if (entry.maxLife) {
          writeFrame(ev.data);
          return;
        }
        app.setError("terminal", "");
        writeFrame(ev.data);
      };
      ws.onopen = () => {
        app.setTabState(id, "connected");
        app.syncWorkspace();
        fit.fit();
        term.focus();
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      };
      ws.onerror = () => {
        entry.hadError = true;
      };
      ws.onclose = (ev) => {
        app.setTabState(id, entry.maxLife ? "expired" : "closed");
        if (app.termActive === id) app.syncWorkspace();
        if (entry.maxLife) return;
        if (!entry.saw) {
          term.write("终端连接失败\r\n");
          app.setError("terminal", "终端连接失败");
          return;
        }
        term.write("\r\n" + closeLine(ev) + "\r\n");
      };
      term.onData((data) => {
        if (ws.readyState === 1) ws.send(new TextEncoder().encode(data));
      });
      term.onResize(({ cols, rows }) => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: cols, rows: rows }));
      });
    },

    showPane(id) {
      this.termActive = id;
      termMap.forEach((entry) => {
        entry.pane.classList.toggle("active", entry.id === id);
      });
      this.fitActive();
      this.syncWorkspace();
    },

    fitActive() {
      const entry = termMap.get(this.termActive);
      if (!entry) return;
      setTimeout(() => {
        if (!entry.pane.classList.contains("active")) return;
        entry.fit.fit();
        if (entry.ws && entry.ws.readyState === 1) {
          entry.ws.send(JSON.stringify({ type: "resize", cols: entry.term.cols, rows: entry.term.rows }));
        }
      }, 30);
    },

    closeTab(id) {
      const entry = termMap.get(id);
      if (entry) {
        if (entry.observer) entry.observer.disconnect();
        entry.ws.onclose = null;
        try { entry.ws.close(); } catch (err) { /* already closed */ }
        entry.term.dispose();
        entry.pane.remove();
        termMap.delete(id);
      }
      this.termTabs = this.termTabs.filter((tab) => tab.id !== id);
      if (this.termActive === id) {
        const next = this.termTabs[this.termTabs.length - 1];
        this.termActive = next ? next.id : "";
        if (next) this.showPane(next.id);
        else this.syncWorkspace();
      }
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
      this.termTabs = this.termTabs.map((tab) => tab.id === id ? Object.assign({}, tab, { state: state, busy: false }) : tab);
    },

    terminalState() {
      const tab = this.termTabs.find((item) => item.id === this.termActive);
      return tab ? ({ connecting: "连接中", connected: "已连接", closed: "已断开", expired: "已到期" }[tab.state] || "已断开") : "未连接";
    },

    async reconnectTerminal() {
      const alias = this.tabAlias();
      if (!alias || this.termOpening) return;
      this.closeTab(this.termActive);
      await this.openTerminal(alias);
    },

    selectPanel(name) { this.panel = name; this.fitActive(); },

    rememberWorkspace() {
      if (!this.files.alias) return;
      delete this.workspaceCache[this.files.alias];
      this.workspaceCache[this.files.alias] = { files: Object.assign({}, this.files), tree: this.tree, root: this.treeRoot, draft: this.pathDraft };
      const keys = Object.keys(this.workspaceCache);
      if (keys.length > 16) delete this.workspaceCache[keys[0]];
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
      this.stopMetrics();
      this.abortRead("files");
      this.metricsSeq++;
      this.metrics = blankMetrics();
      this.files.alias = "";
      this.files.path = "";
      this.files.parent = "";
      this.files.crumbs = [];
      this.files.entries = [];
      this.files.truncated = false;
      this.files.home = "";
      this.tree = {};
      this.treeRoot = "";
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
      const lower = Math.max(160, Math.min(520, Number(this.ws && this.ws.lower) || 280));
      return "--ws-side:" + side + "px;--ws-lower:" + lower + "px";
    },

    overviewAddr() {
      const alias = this.panelAlias();
      const live = this.workspaceLive() && this.metrics && this.metrics.alias === alias ? this.metrics : null;
      if (live && live.address) return live.user + "@" + live.address + ":" + live.port;
      const h = this.hostByAlias(alias);
      if (!h) return "选择主机后显示地址";
      return (h.user || "") + "@" + (h.host || "") + ":" + (h.port || "");
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
    lowerStyle() { return "height:" + this.ws.lower + "px"; },

    beginSplit(which, ev) {
      const startX = ev.clientX;
      const startY = ev.clientY;
      const baseSide = this.ws.side;
      const baseLower = this.ws.lower;
      const app = this;
      const move = (e) => {
        if (which === "side") {
          app.ws.side = Math.max(220, Math.min(460, baseSide + (e.clientX - startX)));
        } else {
          app.ws.lower = Math.max(160, Math.min(520, baseLower - (e.clientY - startY)));
        }
      };
      const prevCursor = document.body.style.cursor;
      const prevSelect = document.body.style.userSelect;
      document.body.style.cursor = which === "side" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";
      const up = () => {
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
        document.body.style.cursor = prevCursor;
        document.body.style.userSelect = prevSelect;
        app.saveSplit();
        app.fitActive();
      };
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
        this.stopMetrics();
        this.metrics = blankMetrics();
        this.metricsFailures = 0;
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
        const saved = this.workspaceCache[alias];
        if (saved) {
          this.files = Object.assign({}, saved.files);
          this.tree = saved.tree;
          this.treeRoot = saved.root;
          this.pathDraft = saved.draft;
        }
        if (this.files.mode !== "history") this.refreshFiles();
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
        this.metricsFailures = 0;
        this.pushNet(alias, data.netRx, data.netTx);
        this.setError("metrics", "");
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (seq !== this.metricsSeq) return;
        this.metricsFailures++;
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

    pushNet(alias, rx, tx) {
      const now = Date.now();
      if (!this.netSeries[alias]) this.netSeries[alias] = [];
      const series = this.netSeries[alias];
      const prev = series.length ? series[series.length - 1] : null;
      const point = { t: now, rx: Number(rx) || 0, tx: Number(tx) || 0, rxRate: 0, txRate: 0 };
      if (prev && now > prev.t) {
        const dt = (now - prev.t) / 1000;
        if (dt > 0) {
          point.rxRate = Math.max(0, (point.rx - prev.rx) / dt);
          point.txRate = Math.max(0, (point.tx - prev.tx) / dt);
        }
      }
      series.push(point);
      if (series.length > 24) series.shift();
      paintNetChart(series);
    },

    sparkPoints() {
      const alias = this.activeTermAlias();
      const series = (this.netSeries && this.netSeries[alias]) || [];
      if (series.length < 2) return "0,34 160,34";
      const rates = [];
      for (let i = 1; i < series.length; i++) {
        const d = (series[i].rx - series[i - 1].rx) + (series[i].tx - series[i - 1].tx);
        rates.push(d > 0 ? d : 0);
      }
      let max = 1;
      for (let i = 0; i < rates.length; i++) if (rates[i] > max) max = rates[i];
      const pts = [];
      for (let i = 0; i < rates.length; i++) {
        const x = rates.length === 1 ? 0 : (160 * i) / (rates.length - 1);
        const y = 34 - (28 * rates[i]) / max;
        pts.push(x.toFixed(1) + "," + y.toFixed(1));
      }
      return pts.join(" ");
    },

    pct(n) {
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
      return rows.slice(0, 7);
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
      const n = Number(String(text || "").trim());
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
      this.files.mode = "files";
      this.setError("files", "");
      if (this.liveAlias() && !this.files.path) this.refreshFiles();
    },

    showHistory() {
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

    async jumpPath() {
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
      try {
        const data = await this.postRead("/api/files/list", { alias: alias, path: path || "." }, signal);
        if (this.liveAlias() !== alias) return;
        this.files.alias = alias;
        this.files.path = data.path || "";
        this.files.parent = data.parent || "";
        this.files.crumbs = data.crumbs || [];
        this.files.entries = data.entries || [];
        this.files.truncated = !!data.truncated;
        if (data.home) this.files.home = data.home;
        if (!this.pathFocused) this.pathDraft = this.files.path;
        this.pathError = "";
        this.noteTree(this.files.path, this.files.entries);
        if ((this.files.path || "") !== "/") await this.ensureFsRoot();
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (this.liveAlias() !== alias) return;
        const msg = err.message || "列目录失败";
        this.setError("files", msg);
        if (msg.indexOf("不存在") >= 0 || msg.indexOf("not exist") >= 0 || msg.indexOf("no such file") >= 0) this.pathError = msg.indexOf("目录不存在") >= 0 ? msg : "目录不存在。";
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
      node.dirs = [];
      const list = entries || [];
      for (let i = 0; i < list.length; i++) {
        if (!list[i].dir) continue;
        const child = String(list[i].path || "");
        const base = this.treeLabel(child || list[i].name);
        node.dirs.push({ name: base, path: child });
        if (!this.tree[child]) this.tree[child] = { name: base, open: false, loaded: false, dirs: [] };
        else this.tree[child].name = base;
      }
      this.tree[path] = node;
      this.tree = Object.assign({}, this.tree);
    },

    async ensureFsRoot() {
      const node = this.tree["/"];
      if (node && node.loaded) return;
      if (this._rootLoad) return this._rootLoad;
      const alias = this.liveAlias();
      if (!alias) return;
      const app = this;
      this._rootLoad = (async () => {
        try {
          const data = await app.postRead("/api/files/list", { alias: alias, path: "/" });
          if (app.liveAlias() !== alias) return;
          app.noteTree(data.path || "/", data.entries || []);
        } catch (err) {
          // The directory that was opened stays visible if / cannot be listed.
        } finally {
          app._rootLoad = null;
        }
      })();
      return this._rootLoad;
    },

    treeRows() {
      const rows = [];
      const root = this.treeRoot || "";
      const walk = (path, depth) => {
        const node = this.tree[path];
        if (!node) return;
        rows.push({ path: path, name: node.name || path, depth: depth, open: !!node.open });
        if (!node.open) return;
        const dirs = node.dirs || [];
        for (let i = 0; i < dirs.length; i++) walk(dirs[i].path, depth + 1);
      };
      if (root && this.tree[root]) walk(root, 0);
      return rows;
    },

    async toggleTree(row) {
      const node = this.tree[row.path];
      if (node && node.open) {
        node.open = false;
        this.tree = Object.assign({}, this.tree);
        return;
      }
      if (node && node.loaded) {
        node.open = true;
        this.tree = Object.assign({}, this.tree);
        return;
      }
      const alias = this.liveAlias();
      if (!alias) return;
      try {
        const data = await this.postJSON("/api/files/list", { alias: alias, path: row.path });
        this.noteTree(data.path || row.path, data.entries || []);
      } catch (err) {
        this.toast(err.message || "无法展开目录", "bad");
      }
    },

    async fileChange(op, path, name) {
      this.menu.open = false;
      const alias = this.liveAlias();
      if (!alias) {
        this.toast("先打开终端或点「连接」。", "bad");
        return;
      }
      try {
        await this.postJSON("/api/files/change", { alias: alias, op: op, path: path, name: name || "" });
        const cur = this.files.path || path;
        await this.listFiles(op === "remove" && path === cur ? (this.files.parent || "/") : cur);
      } catch (err) {
        this.toast(err.message || "操作失败", "bad");
      }
    },

    async createEntry(kind) {
      const parent = this.files.path;
      this.menu.open = false;
      if (!parent) {
        this.toast("先打开一个目录。", "bad");
        return;
      }
      const name = await this.ask(kind === "dir" ? "新建文件夹名称" : "新建文件名称");
      if (name == null) return;
      if (!String(name).trim()) {
        this.toast("请输入名称。", "bad");
        return;
      }
      await this.fileChange(kind === "dir" ? "mkdir" : "touch", parent, String(name).trim());
    },

    async renameEntry() {
      const entry = this.menu.entry;
      this.menu.open = false;
      if (!entry || !entry.path) {
        this.toast("先选中一项。", "bad");
        return;
      }
      const name = await this.ask("重命名为", entry.name || "");
      if (name == null) return;
      if (!String(name).trim()) {
        this.toast("请输入名称。", "bad");
        return;
      }
      await this.fileChange("rename", entry.path, String(name).trim());
    },

    async deleteEntry() {
      const entry = this.menu.entry;
      this.menu.open = false;
      if (!entry || !entry.path) {
        this.toast("先选中一项。", "bad");
        return;
      }
      if (!await this.askConfirm("删除 " + (entry.name || entry.path) + " ？此操作不能撤销。")) return;
      await this.fileChange("remove", entry.path, "");
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
      const files = ev.target.files;
      ev.target.value = "";
      await this.enqueueUploads(files, this.files.path);
    },

    patchTransfer(id, patch) {
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
    },

    finishTransfer(id, patch) {
      this.patchTransfer(id, Object.assign({ active: false }, patch));
    },

    hasFinishedTransfers() {
      const items = this.transfers || [];
      for (let i = 0; i < items.length; i++) if (!items[i].active) return true;
      return false;
    },

    clearFinishedTransfers() {
      this.transfers = (this.transfers || []).filter((t) => t.active);
    },

    transferDetail(item) {
      if (!item) return "";
      const loadedN = Number(item.loaded) || 0;
      const total = Number(item.total) || 0;
      const status = item.label || "";
      if (total > 0) {
        const bits = this.pct(this.itemPct(item)) + " · " + this.formatBytes(loadedN) + " / " + this.formatBytes(total);
        if (!item.active && status && status !== "下载中" && status !== "上传中" && status !== "写入远端") return bits + " · " + status;
        return bits;
      }
      if (loadedN > 0) return (status ? status + " · " : "") + this.formatBytes(loadedN);
      return status;
    },

    fileSize(entry) {
      if (!entry || entry.dir) return "—";
      return this.formatBytes(entry.size);
    },

    async enqueueUploads(fileList, remoteDir) {
      const alias = this.liveAlias();
      if (!alias) {
        this.toast("先打开终端或点「连接」。", "bad");
        return;
      }
      const dest = remoteDir || this.files.path;
      if (!dest) {
        this.toast("先刷新目录，再上传。", "bad");
        return;
      }
      const files = [];
      const list = fileList || [];
      for (let i = 0; i < list.length; i++) files.push(list[i]);
      if (!files.length) return;
      this.setError("files", "");
      await this.ensureSession();
      for (let i = 0; i < files.length; i++) {
        await this.uploadOne(alias, files[i], dest);
      }
      if (this.files.path) await this.listFiles(this.files.path);
    },

    uploadOne(alias, file, remoteDir) {
      const app = this;
      const id = "up" + Date.now().toString(36) + Math.floor(Math.random() * 1000);
      const item = { id: id, alias: alias, name: file.name, loaded: 0, total: file.size || 0, active: true, label: "上传中" };
      this.patchTransfer(id, item);
      const commit = (patch) => {
        Object.assign(item, patch);
        app.patchTransfer(id, patch);
      };
      return new Promise((resolve) => {
        const send = (confirmText, overwrite) => {
          const xhr = new XMLHttpRequest();
          transferCtl.set(id, xhr);
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
          const takeRemote = () => {
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
                commit({ loaded: msg.loaded, total: msg.total || item.total || 0, active: true, label: "写入远端" });
              }
            }
          };
          xhr.onprogress = takeRemote;
          xhr.onreadystatechange = () => { if (xhr.readyState >= 3) takeRemote(); };
          xhr.upload.onprogress = (ev) => {
            if (ev.lengthComputable) {
              commit({
                loaded: ev.loaded,
                total: ev.total,
                active: true,
                label: ev.loaded === ev.total ? "已发送到本机，正在写入远端…" : "发送到本机 " + app.pct(ev.total ? (100 * ev.loaded) / ev.total : 0)
              });
            }
          };
          xhr.onerror = () => {
            commit({ active: false, label: "失败" });
            app.finishTransfer(id, { label: "失败" });
            transferCtl.delete(id);
            app.toast(file.name + " 上传失败", "bad");
            resolve();
          };
          xhr.onabort = () => {
            commit({ active: false, label: "已取消" });
            app.finishTransfer(id, { label: "已取消" });
            transferCtl.delete(id);
            resolve();
          };
          xhr.onload = async () => {
            let data = {};
            const raw = String(xhr.responseText || "").trim();
            try {
              data = raw ? lastJSONObject(raw) : {};
            } catch (err) {
              commit({ active: false, label: "失败" });
              app.finishTransfer(id, { label: "失败" });
              transferCtl.delete(id);
              app.toast(file.name + "：" + plainBodyMessage(raw, xhr.statusText), "bad");
              resolve();
              return;
            }
            if ((xhr.status === 409 || data.needsOverwrite) && data.needsOverwrite && !overwrite) {
              const accepted = await app.askConfirm("主机 " + alias + " 已有文件：" + data.path + "\n覆盖后无法恢复原内容，继续？");
              if (accepted && item.active) { send(confirmText, true); return; }
              commit({ active: false, label: "已取消" });
              app.finishTransfer(id, { label: "已取消" });
              transferCtl.delete(id);
              resolve();
              return;
            }
            if ((xhr.status === 409 || data.needsConfirm) && data.needsConfirm && !confirmText) {
              const typed = await app.ask((data.error || "需要确认") + "\n主机：" + alias + "\n路径：" + remoteDir + "\n请输入：" + (data.confirm || alias));
              if (typed == null) {
                commit({ active: false, label: "已取消" });
                app.finishTransfer(id, { label: "已取消" });
                transferCtl.delete(id);
                resolve();
                return;
              }
              if (!item.active) { resolve(); return; }
              send(typed, overwrite);
              return;
            }
            transferCtl.delete(id);
            if (xhr.status < 200 || xhr.status >= 300 || data.ok === false) {
              commit({ active: false, label: "失败" });
              app.finishTransfer(id, { label: "失败" });
              app.toast(file.name + "：" + (data.error || xhr.statusText || "上传失败"), "bad");
            } else {
              commit({ active: false, loaded: item.total || item.loaded, label: "完成" });
              app.finishTransfer(id, { loaded: item.total || item.loaded, label: "完成" });
            }
            resolve();
          };
          xhr.send(fd);
        };
        send("");
      });
    },

    async wsDownload(entry, explicitAlias) {
      this.menu.open = false;
      const alias = explicitAlias || this.liveAlias();
      if (!alias || !entry || !entry.path) return;
      this.setError("files", "");
      await this.ensureSession();
      const id = "dn" + Date.now().toString(36) + Math.floor(Math.random() * 1000);
      const name = entry.name || "download";
      const known = !entry.dir && Number(entry.size) > 0 ? Number(entry.size) : 0;
      this.patchTransfer(id, { id: id, alias: alias, name: name, loaded: 0, total: known, active: true, label: "下载中" });
      const ctrl = new AbortController();
      transferCtl.set(id, ctrl);
      let confirmText = "";
      try {
        for (let attempt = 0; attempt < 4; attempt++) {
          const res = await this.api("/api/download", {
            method: "POST",
            signal: ctrl.signal,
            headers: { "Content-Type": "application/json", "Accept": "application/x-ndjson" },
            body: JSON.stringify({ alias: alias, path: entry.path, local: this.downloadDir || "", confirm: confirmText })
          });
          const ctype = String(res.headers.get("content-type") || "");
          const data = ctype.indexOf("ndjson") >= 0
            ? await readNDJSON(res, (msg) => {
              this.patchTransfer(id, { loaded: Number(msg.loaded) || 0, total: Number(msg.total) || known, active: true, label: "下载中" });
            })
            : await this.parseJSON(res);
          if (res.status === 409 && data.needsConfirm && !confirmText) {
            const typed = await this.ask((data.error || "需要确认") + "\n主机：" + alias + "\n路径：" + entry.path + "\n请输入：" + (data.confirm || alias));
            if (typed == null) {
              const cancel = new Error("已取消");
              cancel.name = "AbortError";
              throw cancel;
            }
            confirmText = String(typed);
            continue;
          }
          if (!res.ok || data.ok === false) throw new Error(friendlyError(data.error, res.statusText));
          const saved = data.local || "";
          const label = saved ? ("已保存到 " + saved) : "完成";
          const current = (this.transfers || []).find((t) => t.id === id) || {};
          let totalBytes = Number(current.total) || known || 0;
          let loadedBytes = Number(current.loaded) || 0;
          if (totalBytes > 0) loadedBytes = totalBytes;
          this.patchTransfer(id, { loaded: loadedBytes, total: totalBytes, active: false, label: label });
          this.finishTransfer(id, { loaded: loadedBytes, total: totalBytes, label: label });
          if (saved) this.toast(label);
          return;
        }
        throw new Error("下载失败");
      } catch (err) {
        if (err && err.name === "AbortError") {
          this.patchTransfer(id, { active: false, label: "已取消" });
          this.finishTransfer(id, { label: "已取消" });
        } else {
          this.patchTransfer(id, { active: false, label: "失败" });
          this.finishTransfer(id, { label: "失败" });
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
      if (ctl && ctl.abort) ctl.abort();
      this.finishTransfer(id, { label: "已取消" });
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
          try { await this.wsDownload(JSON.parse(raw)); } catch (err) { this.toast("无法下载", "bad"); }
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
      this.dragPoint = { x: ev.clientX, y: ev.clientY };
      ev.dataTransfer.effectAllowed = "copy";
      ev.dataTransfer.setData("application/x-ssh-cli-file", JSON.stringify({ path: entry.path, name: entry.name }));
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
      this.wsDownload(entry);
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
      try {
        const data = await this.postRead("/api/history", { alias: name, lines: 100 }, signal);
        if (this.liveAlias() !== name) return;
        data.lines = data.lines || [];
        data.entries = data.entries || [];
        data.notes = data.notes || [];
        this.historyView = data;
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (this.liveAlias() !== name) return;
        this.historyView = { alias: name, found: false, status: "error", lines: [], notes: [], error: err.message || "读取历史失败" };
        this.setError("files", err.message || "读取历史失败");
      }
    },

    historyCaption() {
      const h = this.historyView || {};
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
        editing: false, alias: "", group: "", host: "", port: "", user: "", password: "", identity: "",
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
      if (form.password) body.password = form.password;
      if (String(form.identity || "").trim()) body.identity = String(form.identity).trim();
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

    async runExec() {
      this.setError("operate", "");
      this.operateOut = "";
      try {
        const data = await this.postJSON("/api/exec", {
          alias: this.exec.alias,
          command: this.exec.command,
          timeout: this.exec.timeout || this.draft.commandTimeout || "",
          confirm: this.exec.confirm || "",
          allowOutflow: !!this.exec.allowOutflow
        });
        if (data.stdoutSuppressed) this.operateOut = "exit " + data.exitCode + "\n" + (data.notice || "noDataOutflow: command output discarded");
        else this.operateOut = "exit " + data.exitCode + "\n" + (data.stdout || "") + (data.stderr || "");
        this.exec.command = "";
        this.exec.confirm = "";
        this.loadAudit();
      } catch (err) {
        this.setError("operate", err.message);
      }
    },

    async upload(ev) {
      this.setError("operate", "");
      const fd = new FormData(ev.target);
      try {
        for (let attempt = 0; attempt < 4; attempt++) {
          const res = await this.api("/api/upload", { method: "POST", body: fd });
          const data = await this.parseJSON(res);
          if (res.status === 409 && data.needsOverwrite) {
            if (!await this.askConfirm("主机：" + fd.get("alias") + "\n覆盖文件：" + data.path + "\n覆盖后无法恢复原内容，继续？")) return;
            fd.set("overwrite", "true"); continue;
          }
          if (res.status === 409 && data.needsConfirm) {
            const typed = await this.ask(data.error + "\n请输入：" + data.confirm);
            if (typed == null) return;
            fd.set("confirm", typed); continue;
          }
          if (!res.ok || data.ok === false) throw new Error(friendlyError(data.error, res.statusText));
          ev.target.reset(); this.operateOut = "上传完成"; this.loadAudit(); return;
        }
        throw new Error("确认未完成");
      } catch (err) { this.setError("operate", err.message); }
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
      finally { this.batchBusy = false; }
    },

    async checkBatchResult() {
      if (this.batchBusy || !this.batchOperationID) return;
      this.batchBusy = true;
      try {
        const data = await this.readJSON(await this.api("/api/operations/" + this.batchOperationID));
        if (data.state === "running") { this.batchOut = "操作仍在执行，请稍后查询。请勿重复执行。"; return; }
        if (data.state !== "complete") throw new Error("执行结果未知，请核验远端状态。请勿重复执行。");
        this.batchUncertain = false;
        this.batchPreview = null;
        this.batchOut = data.result.results ? batchSummary(data.result.results).text : (data.result.error || "操作结束");
      } catch (err) { this.batchOut = this.explain(err.message); }
      finally { this.batchBusy = false; }
    },

    async clearBatchOperation() {
      if (this.batchBusy || !await this.askConfirm("请先核验远端状态。清除记录后重新执行可能重复写入，确认已核验？")) return;
      this.batchUncertain = false;
      this.batchOperationID = "";
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
      this.batchOperationID = payload.operationId;
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
        this.batchPreview = null;
        this.loadAudit();
        this.loadDashboard();
      } catch (err) {
        this.batchUncertain = sent;
        this.batchOut = this.explain(err.message) + (sent ? "\n执行结果未知，请查询操作记录并核验远端状态，不要重复执行。" : "");
      } finally { this.batchBusy = false; }
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
      return Object.values(this.dialog).some(Boolean);
    },

    openDialog(name) {
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
      if (this.dialog.confirm) { this.answerPrompt(false); return; }
      Object.keys(this.dialog).forEach((key) => { this.dialog[key] = false; });
      this.restoreDialogFocus();
    },

    sortedHosts() {
      return (this.catalog.hosts || []).slice().sort((a, b) => String(a.alias).localeCompare(String(b.alias)));
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
      const q = String(this.q.hosts || "").trim().toLowerCase();
      return this.sortedHosts().filter((h) => {
        if (!q) return true;
        const blob = [h.alias, h.group, h.host, h.user, h.env, h.via || "", (h.tags || []).join(" ")].join(" ").toLowerCase();
        return blob.indexOf(q) >= 0;
      });
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

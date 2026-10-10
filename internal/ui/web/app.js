const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZES = [10, 20, 50];
const termMap = new Map();
const transferCtl = new Map();
let chartDays = null;
let chartOps = null;
let rangePicker = null;
let suppressRange = false;

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
    auditFilter: { op: "", host: "", group: "", env: "", status: "", source: "cli", since: "", until: "" },
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
    dialog: { host: false, group: false, policy: false, env: false, batch: false, detail: false },
    wizard: "export",
    bundleYaml: "",
    bundleImport: "",
    cleanupNote: "",
    operateOut: "",
    batchOut: "",
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
    ws: { side: 280, lower: 280 },
    metrics: { alias: "", connected: false, address: "", port: "", user: "", hostname: "", uptime: "", load: "", cpuPercent: null, mem: null, swap: null, procs: [], disks: [], notes: [], netRx: 0, netTx: 0, netRxRate: 0, netTxRate: 0 },
    netSeries: {},
    metricsTimer: 0,
    metricsSeq: 0,
    readAbort: {},
    files: { alias: "", mode: "files", path: "", parent: "", crumbs: [], entries: [], truncated: false },
    drop: { over: false, target: "", label: "" },
    transfers: [],
    toasts: [],
    menu: { open: false, x: 0, y: 0, entry: null },
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
      known: "known",
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
      this.ensureSession();
      const parsed = this.readHash(location.hash.replace(/^#/, ""));
      this.show(parsed.view || "home");
      this.loadCatalog();
      this.loadKnown();
      this.loadAudit();
      this.loadSessions();
      window.addEventListener("hashchange", () => {
        const next = this.readHash(location.hash.replace(/^#/, ""));
        this.show(next.view || "home");
      });
      document.addEventListener("keydown", (ev) => {
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
      setInterval(() => this.tickSessions(), 1000);
      setInterval(() => {
        if (this.view === "sessions") this.loadSessions();
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
        return m + "。连接失败。核对地址和端口，确认本机能访问该主机。主机密钥变了就到「已知主机密钥」删除旧记录后再试。";
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
        const typed = window.prompt("这个监听地址要求 Bearer token。请粘贴启动 ssh-cli ui 时打印的那一行。");
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
          const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
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
      try {
        this.detail = await this.readJSON(await this.api("/api/hosts/detail?alias=" + encodeURIComponent(this.currentHost)));
        if (!this.detail.policy) this.detail.policy = { capabilities: {} };
        if (!this.detail.policy.capabilities) this.detail.policy.capabilities = {};
        if (!this.detail.audit) this.detail.audit = [];
        if (!this.detail.sessions) this.detail.sessions = [];
      } catch (err) {
        this.setError("host", err.message);
      }
    },

    async loadSessions() {
      this.setError("sessions", "");
      try {
        const data = await this.readJSON(await this.api("/api/sessions"));
        this.sessions = data.sessions || [];
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
      const name = String(alias || this.termAlias || "").trim();
      this.termAlias = name;
      this.show("terminal");
      if (!name) {
        this.setError("terminal", "先选择一台主机。");
        return;
      }
      this.setError("terminal", "");
      await new Promise((resolve) => setTimeout(resolve, 40));
      await this.mountTerm(name);
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
      const entry = { id: id, alias: alias, term: term, fit: fit, ws: ws, pane: pane, saw: false, hadError: false };
      termMap.set(id, entry);
      this.termTabs.push({ id: id, alias: alias, busy: true });
      this.showPane(id);
      const closeLine = (ev) => {
        const code = ev && Number(ev.code);
        if (code) return "终端连接已断开 (" + code + ")";
        return "终端连接已断开";
      };
      ws.onmessage = (ev) => {
        entry.saw = true;
        app.markTabIdle(id);
        app.setError("terminal", "");
        if (typeof ev.data === "string") term.write(ev.data);
        else term.write(new Uint8Array(ev.data));
      };
      ws.onopen = () => {
        fit.fit();
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      };
      ws.onerror = () => {
        entry.hadError = true;
      };
      ws.onclose = (ev) => {
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

    activeTermAlias() {
      const tabs = this.termTabs || [];
      for (let i = 0; i < tabs.length; i++) {
        if (tabs[i].id === this.termActive) return tabs[i].alias;
      }
      return this.termAlias || "";
    },

    hostByAlias(alias) {
      const hosts = (this.catalog && this.catalog.hosts) || [];
      for (let i = 0; i < hosts.length; i++) {
        if (hosts[i].alias === alias) return hosts[i];
      }
      return null;
    },

    overviewAddr() {
      const live = this.metrics && this.metrics.alias === this.activeTermAlias() ? this.metrics : null;
      if (live && live.address) return live.user + "@" + live.address + ":" + live.port;
      const h = this.hostByAlias(this.activeTermAlias());
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
      const alias = this.activeTermAlias();
      if (!alias) {
        this.stopMetrics();
        this.abortRead("files");
        return;
      }
      if (this.files.alias !== alias) {
        this.abortRead("files");
        this.files.alias = alias;
        this.files.path = "";
        this.files.parent = "";
        this.files.crumbs = [];
        this.files.entries = [];
        this.files.truncated = false;
        if (this.files.mode !== "history") this.refreshFiles();
      }
      if (this.files.mode === "history" && this.historyView.alias !== alias) this.loadHistory(alias);
      this.startMetrics();
    },

    startMetrics() {
      this.refreshMetrics();
      if (this.metricsTimer) return;
      const app = this;
      this.metricsTimer = window.setInterval(() => {
        if (app.view !== "terminal") {
          app.stopMetrics();
          return;
        }
        app.refreshMetrics();
        app.loadSessions();
      }, 5000);
    },

    stopMetrics() {
      this.abortRead("metrics");
      if (this.metricsTimer) {
        window.clearInterval(this.metricsTimer);
        this.metricsTimer = 0;
      }
    },

    async refreshMetrics() {
      const alias = this.activeTermAlias();
      if (!alias || this.view !== "terminal") return;
      const seq = ++this.metricsSeq;
      const signal = this.replaceRead("metrics");
      try {
        const data = await this.postRead("/api/metrics", { alias: alias }, signal);
        if (seq !== this.metricsSeq || this.activeTermAlias() !== alias) return;
        data.procs = data.procs || [];
        data.disks = data.disks || [];
        data.notes = data.notes || [];
        this.metrics = data;
        this.pushNet(alias, data.netRx, data.netTx);
        this.setError("metrics", "");
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (seq !== this.metricsSeq) return;
        this.metrics.connected = false;
        this.metrics.alias = alias;
        this.setError("metrics", err.message || "概况暂时不可用");
      }
    },

    pushNet(alias, rx, tx) {
      if (!this.netSeries[alias]) this.netSeries[alias] = [];
      const series = this.netSeries[alias];
      series.push({ rx: Number(rx) || 0, tx: Number(tx) || 0 });
      if (series.length > 24) series.shift();
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

    diskPct(text) {
      const n = parseInt(String(text || ""), 10);
      return isFinite(n) ? n : null;
    },

    diskEmpty() { return !this.metrics || !this.metrics.disks || this.metrics.disks.length === 0; },
    procEmpty() { return !this.metrics || !this.metrics.procs || this.metrics.procs.length === 0; },
    metricsPending() {
      return !!this.activeTermAlias() && !(this.errors && this.errors.metrics) && !(this.metrics && this.metrics.connected);
    },

    noteText() {
      const notes = (this.metrics && this.metrics.notes) || [];
      return notes.length ? notes.join("；") : "";
    },

    netText() {
      const m = this.metrics || {};
      return "收 " + this.formatBytes(m.netRx) + " · 发 " + this.formatBytes(m.netTx);
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
      if (this.activeTermAlias() && !this.files.path) this.refreshFiles();
    },

    showHistory() {
      this.files.mode = "history";
      this.setError("files", "");
      this.loadHistory(this.activeTermAlias());
    },

    async openHistory(alias) {
      this.files.mode = "history";
      this.termAlias = alias || this.termAlias;
      this.show("terminal");
      await this.loadHistory(alias || this.activeTermAlias());
    },

    async refreshFiles() {
      const alias = this.activeTermAlias();
      if (!alias) {
        this.setError("files", "先选择一台主机。");
        return;
      }
      await this.listFiles(this.files.alias === alias && this.files.path ? this.files.path : ".");
    },

    async listFiles(path) {
      const alias = this.activeTermAlias();
      if (!alias) {
        this.setError("files", "先选择一台主机。");
        return;
      }
      this.setError("files", "");
      const signal = this.replaceRead("files");
      try {
        const data = await this.postRead("/api/files/list", { alias: alias, path: path || "." }, signal);
        if (this.activeTermAlias() !== alias) return;
        this.files.alias = alias;
        this.files.path = data.path || "";
        this.files.parent = data.parent || "";
        this.files.crumbs = data.crumbs || [];
        this.files.entries = data.entries || [];
        this.files.truncated = !!data.truncated;
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (this.activeTermAlias() !== alias) return;
        this.setError("files", err.message || "列目录失败");
      }
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

    async enqueueUploads(fileList, remoteDir) {
      const alias = this.activeTermAlias();
      if (!alias) {
        this.toast("先选择一台主机。", "bad");
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
      this.transfers.push(item);
      return new Promise((resolve) => {
        const send = (confirmText) => {
          const xhr = new XMLHttpRequest();
          transferCtl.set(id, xhr);
          const fd = new FormData();
          fd.set("alias", alias);
          fd.set("remote", remoteDir);
          fd.set("file", file, file.name);
          if (confirmText) fd.set("confirm", confirmText);
          xhr.open("POST", "/api/upload");
          if (app.csrf) xhr.setRequestHeader("X-CSRF-Token", app.csrf);
          const token = sessionStorage.getItem("sshCliBearer") || "";
          if (token) xhr.setRequestHeader("Authorization", "Bearer " + token);
          xhr.upload.onprogress = (ev) => {
            if (ev.lengthComputable) {
              item.loaded = ev.loaded;
              item.total = ev.total;
              item.label = app.pct(ev.total ? (100 * ev.loaded) / ev.total : 0);
            }
          };
          xhr.onerror = () => {
            item.active = false;
            item.label = "失败";
            transferCtl.delete(id);
            app.toast(file.name + " 上传失败", "bad");
            resolve();
          };
          xhr.onabort = () => {
            item.active = false;
            item.label = "已取消";
            transferCtl.delete(id);
            resolve();
          };
          xhr.onload = () => {
            let data = {};
            const raw = String(xhr.responseText || "").trim();
            try {
              data = raw ? JSON.parse(raw) : {};
            } catch (err) {
              item.active = false;
              item.label = "失败";
              transferCtl.delete(id);
              app.toast(file.name + "：" + plainBodyMessage(raw, xhr.statusText), "bad");
              resolve();
              return;
            }
            if (xhr.status === 409 && data.needsConfirm && !confirmText) {
              const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + (data.confirm || alias));
              if (typed == null) {
                item.active = false;
                item.label = "已取消";
                transferCtl.delete(id);
                resolve();
                return;
              }
              send(typed);
              return;
            }
            transferCtl.delete(id);
            item.active = false;
            if (xhr.status < 200 || xhr.status >= 300 || data.ok === false) {
              item.label = "失败";
              app.toast(file.name + "：" + (data.error || xhr.statusText || "上传失败"), "bad");
            } else {
              item.loaded = item.total || item.loaded;
              item.label = "完成";
            }
            resolve();
          };
          xhr.send(fd);
        };
        send("");
      });
    },

    async wsDownload(entry) {
      this.menu.open = false;
      const alias = this.activeTermAlias();
      if (!alias || !entry || !entry.path) return;
      this.setError("files", "");
      await this.ensureSession();
      const id = "dn" + Date.now().toString(36);
      const item = { id: id, alias: alias, name: entry.name || "download", loaded: 0, total: 0, active: true, label: "下载中" };
      this.transfers.push(item);
      const ctrl = new AbortController();
      transferCtl.set(id, ctrl);
      try {
        const res = await this.api("/api/download", {
          method: "POST",
          signal: ctrl.signal,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alias: alias, path: entry.path })
        });
        if (!res.ok) {
          const data = await this.parseJSON(res);
          throw new Error(friendlyError(data.error, res.statusText));
        }
        const total = Number(res.headers.get("Content-Length")) || 0;
        item.total = total;
        const reader = res.body && res.body.getReader ? res.body.getReader() : null;
        const chunks = [];
        if (!reader) {
          const blob = await res.blob();
          item.loaded = blob.size;
          this.saveBlob(blob, entry.name || "download");
        } else {
          while (true) {
            const step = await reader.read();
            if (step.done) break;
            chunks.push(step.value);
            item.loaded += step.value.length;
            item.label = total ? this.pct((100 * item.loaded) / total) : this.formatBytes(item.loaded);
          }
          this.saveBlob(new Blob(chunks), entry.name || "download");
        }
        item.active = false;
        item.label = "完成";
      } catch (err) {
        item.active = false;
        if (err && err.name === "AbortError") {
          item.label = "已取消";
        } else {
          item.label = "失败";
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
      const ctl = transferCtl.get(id);
      if (ctl && ctl.abort) ctl.abort();
      const items = this.transfers || [];
      for (let i = 0; i < items.length; i++) {
        if (items[i].id === id) {
          items[i].active = false;
          items[i].label = "已取消";
        }
      }
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
      this.toast("浏览器不能把文件直接放进系统文件夹，已改为下载");
      this.wsDownload(entry);
    },

    openMenu(ev, entry) {
      if (entry) this.selectedPath = entry.path || "";
      this.menu = { open: true, x: ev.clientX, y: ev.clientY, entry: entry || null };
      const app = this;
      const close = (e) => {
        if (e.type === "keydown" && e.key !== "Escape") return;
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
      const alias = this.activeTermAlias();
      if (!alias) return "未选择主机";
      const items = this.sessions || [];
      for (let i = 0; i < items.length; i++) {
        if (items[i].alias !== alias) continue;
        const idle = items[i].status === "busy" ? "忙碌，暂不因空闲关闭" : ("空闲剩余 " + this.formatLeft(items[i].idleLeftSec));
        return (items[i].status === "busy" ? "忙碌" : "已连接") + " · " + idle + " · 最长剩余 " + this.formatLeft(items[i].lifeLeftSec);
      }
      return "未连接 · 点「连接」或「打开」";
    },

    async openWorkspaceHost() {
      const alias = this.activeTermAlias();
      if (!alias) {
        this.toast("先选择一台主机。", "bad");
        return;
      }
      try {
        await this.postJSON("/api/sessions/open", { alias: alias });
        await this.loadSessions();
        this.toast("已连接 " + alias);
      } catch (err) {
        this.toast(err.message || "连接失败", "bad");
      }
    },

    async closeWorkspaceHost() {
      const alias = this.activeTermAlias();
      if (!alias) return;
      const tabs = (this.termTabs || []).slice();
      for (let i = 0; i < tabs.length; i++) if (tabs[i].alias === alias) this.closeTab(tabs[i].id);
      try {
        await this.postJSON("/api/sessions/close", { alias: alias });
        await this.loadSessions();
      } catch (err) {
        this.toast(err.message || "断开失败", "bad");
      }
    },

    async loadHistory(alias) {
      const name = String(alias || this.activeTermAlias() || "").trim();
      if (!name) {
        this.setError("files", "先选择一台主机。");
        return;
      }
      this.files.mode = "history";
      this.setError("files", "");
      const signal = this.replaceRead("files");
      try {
        const data = await this.postRead("/api/history", { alias: name, lines: 100 }, signal);
        if (this.activeTermAlias() !== name) return;
        data.lines = data.lines || [];
        data.notes = data.notes || [];
        this.historyView = data;
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (this.activeTermAlias() !== name) return;
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
      bits.push("只读，可能含密钥");
      return bits.join(" · ");
    },

    historyText() {
      const h = this.historyView || {};
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
        if (nextVia !== prevVia && !window.confirm("跳板改了之后，这台主机已经打开的连接会断开。保存吗？")) return;
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
      if (!window.confirm("删除主机 " + alias + "？")) return;
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
        if (!window.confirm("把分组 " + form.name + " 的环境从 prod 改成 " + form.env + "？这会改变该组主机的权限天花板。")) return;
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
      if (!window.confirm("删除空分组 " + name + "？")) return;
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
      if (!window.confirm(msg)) return;
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
      if (!window.confirm("删除环境 " + name + "？仍被分组使用时会失败。")) return;
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

    async removeKnown(marker) {
      if (!window.confirm("删除已知主机密钥 " + marker + "？下次连接会重新记录第一把钥匙。")) return;
      this.setError("known", "");
      try {
        await this.postJSON("/api/known-hosts/remove", { marker: marker });
        await this.loadKnown();
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
      await this.ensureSession();
      const fd = new FormData(ev.target);
      try {
        let res = await this.api("/api/upload", { method: "POST", body: fd });
        let data = await this.parseJSON(res);
        if (res.status === 409 && data.needsConfirm) {
          const typed = window.prompt(data.error + "\n请输入：" + data.confirm);
          if (typed == null) throw new Error(data.error);
          fd.set("confirm", typed);
          res = await this.api("/api/upload", { method: "POST", body: fd });
          data = await this.parseJSON(res);
        }
        if (!res.ok || data.ok === false) throw new Error(friendlyError(data.error, res.statusText));
        ev.target.reset();
        this.operateOut = "上传完成";
        this.loadAudit();
      } catch (err) {
        this.setError("operate", err.message);
      }
    },

    async download(ev) {
      this.setError("operate", "");
      await this.ensureSession();
      const fd = new FormData(ev.target);
      try {
        const res = await this.api("/api/download", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alias: fd.get("alias"), path: fd.get("path") })
        });
        if (!res.ok) {
          const data = await this.parseJSON(res);
          throw new Error(friendlyError(data.error, res.statusText));
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "download";
        a.click();
        URL.revokeObjectURL(url);
        ev.target.reset();
        this.loadAudit();
      } catch (err) {
        this.setError("operate", err.message);
      }
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
      this.batchOut = "";
      this.setError("batch", "");
      this.openDialog("batch");
    },

    async submitBatch() {
      const aliases = this.selectedAliases();
      if (!aliases.length) {
        this.batchOut = "先勾选主机。一次最多 16 台。";
        return;
      }
      const payload = {
        aliases: aliases,
        command: this.batchCommand,
        timeout: this.exec.timeout || this.draft.commandTimeout || "",
        parallel: Number(this.batchParallel || 2),
        skipDenied: !!this.batchSkip,
        allowCrossEnv: !!this.batchCross,
        allowOutflow: !!this.exec.allowOutflow,
        confirms: {}
      };
      this.batchOut = "";
      try {
        let data;
        for (let attempt = 0; attempt < 8; attempt++) {
          const res = await this.api("/api/exec/batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });
          data = await this.parseJSON(res);
          if (res.status === 409 && data.needsConfirm) {
            if (data.confirmField === "outflowConfirm") {
              const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + data.confirm);
              if (typed == null) throw new Error(data.error || "已取消");
              payload.outflowConfirm = typed;
              continue;
            }
            const pending = data.aliases || aliases;
            for (let i = 0; i < pending.length; i++) {
              const alias = pending[i];
              if (payload.confirms[alias]) continue;
              const typed = window.prompt("主机 " + alias + " 需要确认。请输入主机别名。");
              if (typed == null) throw new Error("已取消");
              payload.confirms[alias] = String(typed).trim();
            }
            continue;
          }
          if (!res.ok || data.ok === false) throw new Error(friendlyError(data.error, res.statusText));
          break;
        }
        const lines = (data.results || []).map((row) => {
          const head = (row.alias || "") + " " + (row.ok ? "ok" : "失败");
          if (row.stdoutSuppressed) return head + "\n" + (row.notice || "输出已丢弃");
          return head + (row.error ? "\n" + row.error : "") + (row.stdout ? "\n" + row.stdout : "") + (row.stderr ? "\n" + row.stderr : "");
        });
        this.batchOut = lines.join("\n\n") || "没有结果";
        this.loadAudit();
        this.loadDashboard();
      } catch (err) {
        this.batchOut = this.explain(err.message);
      }
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
        this.wizard = "export";
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
      const hmac = this.ops.hmac || this.dash.hmac || {};
      const status = hmac.status || "unsigned";
      const map = {
        ok: "HMAC 有效。policy.mac 和当前策略一致。",
        unsigned: "还没有签名。需要时在命令行运行 ssh-cli policy sign。",
        "needs-resign": "policy.mac 是旧版，不含连接信息。运行 ssh-cli policy sign 重签。",
        missing: "配置标记为已签名，但 policy.mac 不在。恢复文件，或运行 ssh-cli policy unsign。",
        mismatch: "HMAC 不一致，配置会被拒绝加载。先核对 policy.mac，不要继续放宽策略。",
        error: "读不到 HMAC 状态。"
      };
      return (map[status] || status) + (hmac.error ? " " + hmac.error : "");
    },

    hmacClass() {
      const status = (this.ops.hmac && this.ops.hmac.status) || (this.dash.hmac && this.dash.hmac.status) || "unsigned";
      if (status === "ok") return "alert alert-success";
      if (status === "unsigned") return "alert alert-info";
      if (status === "needs-resign") return "alert alert-warning";
      return "alert alert-danger";
    },

    anyDialog() {
      return this.dialog.host || this.dialog.group || this.dialog.policy || this.dialog.env || this.dialog.batch || this.dialog.detail;
    },

    openDialog(name) {
      this.dialog[name] = true;
      document.body.classList.add("overflow-hidden");
    },

    closeDialogs() {
      this.dialog.host = false;
      this.dialog.group = false;
      this.dialog.policy = false;
      this.dialog.env = false;
      this.dialog.batch = false;
      this.dialog.detail = false;
      document.body.classList.remove("overflow-hidden");
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

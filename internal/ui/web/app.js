const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZES = [10, 20, 50];

const termMap = new Map();
const charts = { days: null, ops: null };
let rangePicker = null;
let csrfToken = "";
let pagersBound = false;

function formatStamp(raw) {
  if (raw == null || raw === "") return "";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return String(raw);
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

function lines(text) {
  return String(text || "").split("\n").map((s) => s.trim()).filter(Boolean);
}

function commaList(text) {
  return String(text || "").split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
}

function byName(a, b) {
  return String(a.name || a.alias || "").localeCompare(String(b.name || b.alias || ""));
}

function ruleBody(form) {
  return {
    allow: form.allowMode === "list" ? lines(form.allow) : null,
    deny: lines(form.deny),
    confirm: lines(form.confirm)
  };
}

function blankHost() {
  return {
    alias: "", group: "", host: "", port: "", user: "", password: "", identity: "",
    policy: "", tags: "", allowMode: "all", allow: "", deny: "", confirm: "", setDefault: false
  };
}

function blankGroup() {
  return {
    name: "", label: "", env: "", policy: "", allowMode: "all", allow: "", deny: "", confirm: "", protectedPaths: ""
  };
}

function blankPolicy() {
  return { name: "", mode: "", allowMode: "all", allow: "", deny: "", confirm: "" };
}

function prepareCatalog(data) {
  for (const h of data.hosts || []) h.tagsText = (h.tags || []).join(",");
  for (const g of data.groups || []) g.bulkTag = "";
  for (const e of data.envs || []) {
    e.labelEdit = e.label || "";
    e.colorEdit = e.color || "";
    e.maxModeEdit = e.maxMode || "standard";
    e.policyEdit = e.defaultPolicy || "";
  }
}

function authHeaders(extra) {
  const headers = Object.assign({}, extra || {});
  const token = sessionStorage.getItem("sshCliBearer") || "";
  if (token) headers.Authorization = "Bearer " + token;
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  return headers;
}

async function apiFetch(url, options) {
  const opts = Object.assign({ credentials: "same-origin" }, options || {});
  const baseHeaders = opts.headers;
  opts.headers = authHeaders(baseHeaders);
  let res = await fetch(url, opts);
  if (res.status === 401) {
    const typed = window.prompt("这个监听地址要求 Bearer token。请粘贴启动 ssh-cli ui 时打印的那一行。");
    if (typed == null || !typed.trim()) throw new Error("需要 Bearer token");
    sessionStorage.setItem("sshCliBearer", typed.trim());
    opts.headers = authHeaders(baseHeaders);
    res = await fetch(url, opts);
  }
  return res;
}

async function readJSON(res) {
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
  return data;
}

async function ensureSession() {
  if (csrfToken) return;
  const data = await readJSON(await apiFetch("/api/session"));
  csrfToken = data.csrf || "";
}

async function postJSON(url, body) {
  await ensureSession();
  const payload = Object.assign({}, body);
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await apiFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.status === 409 && data.needsConfirm) {
      const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
      if (typed == null) throw new Error(data.error || "已取消");
      if (data.confirmField) payload[data.confirmField] = typed;
      else if (Array.isArray(payload.confirm)) payload.humanConfirm = typed;
      else payload.confirm = typed;
      payload.humanConfirm = payload.humanConfirm || typed;
      continue;
    }
    if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
    return data;
  }
  throw new Error("确认失败");
}

document.addEventListener("alpine:init", () => {
  Alpine.data("sshApp", () => ({
    view: "dash",
    navOpen: false,
    titles: {
      dash: "工作台",
      terminal: "终端",
      hosts: "主机",
      groups: "分组",
      tags: "标签",
      envs: "环境",
      policy: "危险命令",
      known: "已知主机密钥",
      audit: "审计",
      sessions: "会话",
      operate: "执行",
      relay: "中继",
      bundle: "导入导出"
    },
    catalog: { envs: [], groups: [], hosts: [], policies: [] },
    sessions: [],
    known: [],
    errors: {
      dash: "", terminal: "", hosts: "", groups: "", tags: "", envs: "", policy: "",
      known: "", audit: "", sessions: "", operate: "", relay: "", bundle: ""
    },
    filter: { hosts: "", groups: "", tags: "", envs: "", policy: "", known: "" },
    page: { hosts: 1, groups: 1, tags: 1, envs: 1, policy: 1, known: 1, sessions: 1 },
    pageSize: {
      hosts: DEFAULT_PAGE_SIZE,
      groups: DEFAULT_PAGE_SIZE,
      tags: DEFAULT_PAGE_SIZE,
      envs: DEFAULT_PAGE_SIZE,
      policy: DEFAULT_PAGE_SIZE,
      known: DEFAULT_PAGE_SIZE,
      sessions: DEFAULT_PAGE_SIZE
    },
    pageSizes: PAGE_SIZES,
    modal: "",
    hostForm: blankHost(),
    hostEditing: false,
    groupForm: blankGroup(),
    groupEditing: false,
    groupEnvWas: "",
    policyForm: blankPolicy(),
    policyMode: "",
    policyTitle: "添加命名策略",
    envForm: { name: "", label: "", color: "", maxMode: "standard", defaultPolicy: "" },
    detail: { title: "", text: "" },
    tabs: [],
    activeTab: "",
    termAlias: "",
    auditFilter: { op: "", source: "", host: "", status: "" },
    auditSince: "",
    auditUntil: "",
    auditPage: 1,
    auditPageSize: DEFAULT_PAGE_SIZE,
    auditRows: [],
    auditPages: 1,
    auditSummary: "",
    overview: { days: [], ops: [], recent: [] },
    operateOut: "",
    relayNote: "",
    bundleYAML: "",

    boot() {
      const hash = (location.hash || "").replace("#", "");
      this.view = this.titles[hash] ? hash : "dash";
      window.addEventListener("hashchange", () => {
        const name = location.hash.replace("#", "");
        if (this.titles[name] && name !== this.view) this.go(name);
      });
      window.addEventListener("resize", () => this.fitTab(this.activeTab));
      this.$watch("activeTab", (id) => {
        this.showPane(id);
        this.$nextTick(() => this.fitTab(id));
      });
      this.bindPagers();
      this.start();
    },

    async start() {
      try {
        await ensureSession();
        await this.loadCatalog();
        await Promise.all([this.loadDash(), this.loadKnown(), this.loadSessions(), this.loadAudit()]);
      } catch (err) {
        this.errors.dash = err.message || String(err);
      }
      this.$nextTick(() => this.mountPicker());
    },

    bindPagers() {
      if (pagersBound) return;
      pagersBound = true;
      document.addEventListener("click", (ev) => {
        const btn = ev.target.closest && ev.target.closest("[data-pager-key]");
        if (!btn || btn.disabled) return;
        const app = Alpine.$data(document.body);
        const key = btn.getAttribute("data-pager-key");
        const dir = Number(btn.getAttribute("data-pager-dir") || "0");
        app.page[key] = Math.max(1, (app.page[key] || 1) + dir);
      });
      document.addEventListener("change", (ev) => {
        const sel = ev.target.closest && ev.target.closest("[data-pager-size]");
        if (!sel) return;
        const app = Alpine.$data(document.body);
        const key = sel.getAttribute("data-pager-size");
        const n = Number(sel.value);
        if (PAGE_SIZES.indexOf(n) >= 0) app.pageSize[key] = n;
        app.page[key] = 1;
      });
    },

    go(name) {
      if (!this.titles[name]) name = "dash";
      this.view = name;
      this.navOpen = false;
      if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
      if (name === "dash") this.loadDash();
      if (name === "audit") {
        this.$nextTick(() => this.mountPicker());
        this.loadAudit();
      }
      if (name === "sessions") this.loadSessions();
      if (name === "known") this.loadKnown();
      if (name === "terminal") this.$nextTick(() => this.fitTab(this.activeTab));
    },

    async loadCatalog() {
      const data = await readJSON(await apiFetch("/api/catalog"));
      prepareCatalog(data);
      this.catalog = data;
      if (!this.termAlias) {
        const hosts = (data.hosts || []).slice().sort(byName);
        if (hosts.length) this.termAlias = hosts[0].alias;
      }
    },

    async loadDash() {
      try {
        const data = await readJSON(await apiFetch("/api/audit/overview"));
        this.overview = {
          days: (data && data.days) || [],
          ops: (data && data.ops) || [],
          recent: (data && data.recent) || []
        };
        this.$nextTick(() => {
          if (this.view === "dash") this.renderCharts();
        });
      } catch (err) {
        this.errors.dash = err.message;
      }
    },

    renderCharts() {
      if (!window.Chart) return;
      const font = '-apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Segoe UI", sans-serif';
      Chart.defaults.font.family = font;
      Chart.defaults.color = "#6e6e73";
      const days = this.overview.days || [];
      const dayEl = document.getElementById("chart-days");
      if (charts.days) {
        charts.days.destroy();
        charts.days = null;
      }
      if (dayEl) {
        charts.days = new Chart(dayEl, {
          type: "bar",
          data: {
            labels: days.map((d) => d.date),
            datasets: [
              { label: "成功", data: days.map((d) => d.ok || 0), backgroundColor: "#34c759", borderRadius: 6, stack: "s" },
              { label: "拒绝", data: days.map((d) => d.denied || 0), backgroundColor: "#ff3b30", borderRadius: 6, stack: "s" },
              { label: "其他", data: days.map((d) => d.other || 0), backgroundColor: "#ff9f0a", borderRadius: 6, stack: "s" }
            ]
          },
          options: {
            responsive: true,
            plugins: { legend: { position: "bottom" } },
            scales: {
              x: { stacked: true, grid: { display: false } },
              y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
            }
          }
        });
      }
      const ops = this.overview.ops || [];
      const opEl = document.getElementById("chart-ops");
      if (charts.ops) {
        charts.ops.destroy();
        charts.ops = null;
      }
      if (opEl) {
        const palette = ["#0071e3", "#34c759", "#ff9f0a", "#ff3b30", "#5e5ce6", "#64d2ff", "#ac8e68", "#8e8e93"];
        charts.ops = new Chart(opEl, {
          type: "doughnut",
          data: {
            labels: ops.map((o) => o.op),
            datasets: [{
              data: ops.map((o) => o.count || 0),
              backgroundColor: ops.map((_, i) => palette[i % palette.length]),
              borderWidth: 0
            }]
          },
          options: { plugins: { legend: { position: "bottom" } }, cutout: "62%" }
        });
      }
    },

    async loadKnown() {
      this.errors.known = "";
      try {
        const data = await readJSON(await apiFetch("/api/known-hosts"));
        this.known = data.knownHosts || [];
      } catch (err) {
        this.errors.known = err.message;
      }
    },

    async loadSessions() {
      this.errors.sessions = "";
      try {
        const data = await readJSON(await apiFetch("/api/sessions"));
        this.sessions = data.sessions || [];
      } catch (err) {
        this.errors.sessions = err.message;
      }
    },

    async loadAudit() {
      this.errors.audit = "";
      const params = new URLSearchParams();
      if (this.auditSince) params.set("since", this.auditSince);
      if (this.auditUntil) params.set("until", this.auditUntil);
      ["op", "source", "host", "status"].forEach((key) => {
        if (this.auditFilter[key]) params.set(key, this.auditFilter[key]);
      });
      params.set("page", String(this.auditPage));
      params.set("pageSize", String(this.auditPageSize));
      try {
        const data = await readJSON(await apiFetch("/api/audit?" + params.toString()));
        this.auditRows = data.records || [];
        const stats = data.stats || {};
        const pageSize = data.pageSize || this.auditPageSize;
        this.auditPages = Math.max(1, Math.ceil((data.total || 0) / pageSize) || 1);
        this.auditPage = data.page || this.auditPage;
        this.auditSummary = "日志 " + (stats.files || 0) + " 个文件，" + (stats.entries || 0) + " 条，" + (stats.bytes || 0) + " 字节 · 筛选 " + (data.total || 0) + " 条";
      } catch (err) {
        this.errors.audit = err.message;
      }
    },

    mountPicker() {
      if (rangePicker || !window.Litepicker) return;
      const el = document.getElementById("audit-range");
      if (!el) return;
      rangePicker = new Litepicker({
        element: el,
        singleMode: false,
        numberOfMonths: 2,
        numberOfColumns: 2,
        format: "YYYY-MM-DD",
        lang: "zh-CN",
        setup: (picker) => {
          picker.on("selected", (date1, date2) => {
            this.auditSince = date1 && date1.format ? date1.format("YYYY-MM-DD") : "";
            this.auditUntil = date2 && date2.format ? date2.format("YYYY-MM-DD") : "";
            el.value = [this.auditSince, this.auditUntil].filter(Boolean).join(" — ");
          });
        }
      });
    },

    clearRange() {
      this.auditSince = "";
      this.auditUntil = "";
      const el = document.getElementById("audit-range");
      if (el) el.value = "";
      if (rangePicker && rangePicker.clearSelection) rangePicker.clearSelection();
    },

    async cleanupAudit() {
      this.errors.audit = "";
      try {
        const data = await postJSON("/api/audit/cleanup", {});
        await this.loadAudit();
        this.auditSummary = (this.auditSummary || "") + " · 已删除 " + (data.removed || 0) + " 条";
      } catch (err) {
        this.errors.audit = err.message;
      }
    },

    formatTime(raw) {
      return formatStamp(raw);
    },

    subject(rec) {
      if (!rec) return "";
      if (rec.command) return rec.command;
      if (rec.src || rec.dst) return (rec.src || "") + " → " + (rec.dst || "");
      return rec.result_summary || "";
    },

    openDetail(title, text) {
      this.detail = { title: title || "", text: text || "" };
      this.modal = "detail";
    },

    count(list) {
      return (list || []).length;
    },

    overviewTotal() {
      return (this.overview.days || []).reduce((n, d) => n + (d.ok || 0) + (d.denied || 0) + (d.other || 0), 0);
    },

    statusBadge(status) {
      if (status === "ok") return "bg-green-lt";
      if (status === "denied") return "bg-red-lt";
      return "bg-yellow-lt";
    },

    hit(q, parts) {
      const s = String(q || "").trim().toLowerCase();
      if (!s) return true;
      return (parts || []).join(" ").toLowerCase().includes(s);
    },

    sortedHosts() {
      return (this.catalog.hosts || []).slice().sort(byName);
    },

    sortedGroups() {
      return (this.catalog.groups || []).slice().sort(byName);
    },

    sortedEnvs() {
      return (this.catalog.envs || []).slice().sort(byName);
    },

    visibleHosts() {
      return this.sortedHosts().filter((h) => this.hit(this.filter.hosts, [h.alias, h.group, h.host, (h.tags || []).join(",")]));
    },

    visibleGroups() {
      return this.sortedGroups().filter((g) => this.hit(this.filter.groups, [g.name, g.label, g.env]));
    },

    visibleTags() {
      return this.sortedGroups().filter((g) => this.hit(this.filter.tags, this.tagHay(g)));
    },

    visibleEnvs() {
      return this.sortedEnvs().filter((e) => this.hit(this.filter.envs, [e.name, e.label]));
    },

    visiblePolicies() {
      return (this.catalog.policies || []).filter((p) => this.hit(this.filter.policy, [p.name]));
    },

    visibleKnown() {
      return (this.known || []).filter((k) => this.hit(this.filter.known, [k.marker, k.fingerprint, k.keyType]));
    },

    hostsIn(name) {
      return (this.catalog.hosts || []).filter((h) => h.group === name).sort(byName);
    },

    tagHay(g) {
      const hosts = this.hostsIn(g.name);
      return [g.name, g.label, g.env].concat(hosts.map((h) => h.alias + " " + (h.tagsText || (h.tags || []).join(","))));
    },

    allowLabel(row) {
      if (!row || !row.allowSet) return "全集";
      if (!row.allow || row.allow.length === 0) return "（空）";
      return row.allow.join(", ");
    },

    listLabel(items) {
      if (!items || items.length === 0) return "";
      return items.join(", ");
    },

    clampPage(key, total) {
      const size = this.pageSize[key] || DEFAULT_PAGE_SIZE;
      const pages = Math.max(1, Math.ceil((total || 0) / size) || 1);
      let page = this.page[key] || 1;
      if (page > pages) page = pages;
      if (page < 1) page = 1;
      if (this.page[key] !== page) queueMicrotask(() => { this.page[key] = page; });
      return { page, pages, size };
    },

    pageRows(rows, key) {
      const view = this.clampPage(key, (rows || []).length);
      const start = (view.page - 1) * view.size;
      return (rows || []).slice(start, start + view.size);
    },

    pagerHtml(key, total) {
      const view = this.clampPage(key, total);
      const opts = PAGE_SIZES.map((n) => `<option value="${n}"${n === view.size ? " selected" : ""}>${n}</option>`).join("");
      const prev = view.page <= 1 ? " disabled" : "";
      const next = view.page >= view.pages ? " disabled" : "";
      return `<span class="text-secondary">共 ${Number(total) || 0} 条</span>` +
        `<label class="text-secondary mb-0">每页 <select class="form-select form-select-sm d-inline-block w-auto" data-pager-size="${key}" aria-label="每页条数">${opts}</select></label>` +
        `<button type="button" class="btn btn-sm btn-outline-secondary" data-pager-key="${key}" data-pager-dir="-1"${prev}>上一页</button>` +
        `<span class="text-secondary">${view.page} / ${view.pages}</span>` +
        `<button type="button" class="btn btn-sm btn-outline-secondary" data-pager-key="${key}" data-pager-dir="1"${next}>下一页</button>`;
    },

    newHost() {
      const groups = this.sortedGroups();
      this.hostEditing = false;
      this.hostForm = blankHost();
      if (groups.length) this.hostForm.group = groups[0].name;
      this.errors.hosts = "";
      this.modal = "host";
    },

    editHost(h) {
      this.hostEditing = true;
      this.hostForm = {
        alias: h.alias,
        group: h.group,
        host: h.host,
        port: h.port || "",
        user: h.user,
        password: "",
        identity: "",
        policy: h.policy || "",
        tags: (h.tags || []).join(","),
        allowMode: h.allowSet ? "list" : "all",
        allow: (h.allow || []).join("\n"),
        deny: (h.deny || []).join("\n"),
        confirm: (h.confirm || []).join("\n"),
        setDefault: !!h.default
      };
      this.errors.hosts = "";
      this.modal = "host";
    },

    async saveHost() {
      this.errors.hosts = "";
      const body = Object.assign({
        alias: this.hostForm.alias.trim(),
        group: this.hostForm.group,
        host: this.hostForm.host.trim(),
        user: this.hostForm.user.trim(),
        policy: this.hostForm.policy,
        tags: commaList(this.hostForm.tags),
        setDefault: !!this.hostForm.setDefault
      }, ruleBody(this.hostForm));
      if (String(this.hostForm.port) !== "") body.port = Number(this.hostForm.port);
      if (this.hostForm.password) body.password = this.hostForm.password;
      if (String(this.hostForm.identity || "").trim()) body.identity = this.hostForm.identity.trim();
      try {
        await postJSON(this.hostEditing ? "/api/hosts/update" : "/api/hosts", body);
        this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.hosts = err.message;
      }
    },

    async removeHost(alias) {
      if (!window.confirm("删除主机 " + alias + "？")) return;
      this.errors.hosts = "";
      try {
        await postJSON("/api/hosts/remove", { alias });
        if (this.hostForm.alias === alias) this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.hosts = err.message;
      }
    },

    newGroup() {
      const envs = this.sortedEnvs();
      this.groupEditing = false;
      this.groupEnvWas = "";
      this.groupForm = blankGroup();
      if (envs.length) this.groupForm.env = envs[0].name;
      this.errors.groups = "";
      this.modal = "group";
    },

    editGroup(g) {
      this.groupEditing = true;
      this.groupEnvWas = g.env;
      this.groupForm = {
        name: g.name,
        label: g.label || "",
        env: g.env,
        policy: g.policy || "",
        allowMode: g.allowSet ? "list" : "all",
        allow: (g.allow || []).join("\n"),
        deny: (g.deny || []).join("\n"),
        confirm: (g.confirm || []).join("\n"),
        protectedPaths: (g.protectedPaths || []).join("\n")
      };
      this.errors.groups = "";
      this.modal = "group";
    },

    async saveGroup() {
      this.errors.groups = "";
      const name = this.groupForm.name.trim();
      const envName = this.groupForm.env;
      if (this.groupEditing && this.groupEnvWas === "prod" && envName !== "prod") {
        if (!window.confirm("把分组 " + name + " 的环境从 prod 改成 " + envName + "？这会改变该组主机的权限天花板。")) return;
      }
      const body = Object.assign({
        name,
        label: this.groupForm.label.trim(),
        env: envName,
        policy: this.groupForm.policy,
        protectedPaths: lines(this.groupForm.protectedPaths)
      }, ruleBody(this.groupForm));
      try {
        await postJSON(this.groupEditing ? "/api/groups/update" : "/api/groups", body);
        this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.groups = err.message;
      }
    },

    async removeGroup(name) {
      if (!window.confirm("删除空分组 " + name + "？")) return;
      this.errors.groups = "";
      try {
        await postJSON("/api/groups/remove", { name });
        if (this.groupForm.name === name) this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.groups = err.message;
      }
    },

    async saveHostTags(h) {
      this.errors.tags = "";
      try {
        await postJSON("/api/hosts/update", { alias: h.alias, tags: commaList(h.tagsText) });
        await this.loadCatalog();
      } catch (err) {
        this.errors.tags = err.message;
      }
    },

    async applyGroupTags(g, which) {
      const tags = commaList(g.bulkTag);
      if (!tags.length) {
        this.errors.tags = "先填写标签";
        return;
      }
      this.errors.tags = "";
      const body = { group: g.name };
      body[which] = tags;
      try {
        await postJSON("/api/groups/tags", body);
        await this.loadCatalog();
      } catch (err) {
        this.errors.tags = err.message;
      }
    },

    newPolicy() {
      this.policyMode = "create-free";
      this.policyTitle = "添加命名策略";
      this.policyForm = blankPolicy();
      this.errors.policy = "";
      this.modal = "policy";
    },

    editPolicy(p) {
      const override = p.builtin && !p.overridden;
      this.policyMode = override ? "create" : "update";
      this.policyTitle = override ? "覆盖内置 " + p.name : "编辑 " + p.name;
      this.policyForm = {
        name: p.name,
        mode: p.mode || "",
        allowMode: p.allowSet ? "list" : "all",
        allow: (p.allow || []).join("\n"),
        deny: (p.deny || []).join("\n"),
        confirm: (p.confirm || []).join("\n")
      };
      this.errors.policy = "";
      this.modal = "policy";
    },

    async savePolicy() {
      this.errors.policy = "";
      const body = Object.assign({
        name: this.policyForm.name.trim(),
        mode: this.policyForm.mode
      }, ruleBody(this.policyForm));
      try {
        await postJSON(this.policyMode === "update" ? "/api/policies/update" : "/api/policies", body);
        this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.policy = err.message;
      }
    },

    async removePolicy(p) {
      const msg = p.overridden ? "恢复内置策略 " + p.name + "？" : "删除策略 " + p.name + "？";
      if (!window.confirm(msg)) return;
      this.errors.policy = "";
      try {
        await postJSON("/api/policies/remove", { name: p.name });
        if (this.policyForm.name === p.name) this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.policy = err.message;
      }
    },

    async addEnv() {
      this.errors.envs = "";
      try {
        await postJSON("/api/envs", {
          name: this.envForm.name.trim(),
          label: this.envForm.label.trim(),
          color: this.envForm.color.trim(),
          maxMode: this.envForm.maxMode,
          defaultPolicy: this.envForm.defaultPolicy
        });
        this.envForm = { name: "", label: "", color: "", maxMode: "standard", defaultPolicy: "" };
        this.modal = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.envs = err.message;
      }
    },

    async saveEnv(e) {
      this.errors.envs = "";
      try {
        await postJSON("/api/envs/update", {
          name: e.name,
          label: e.labelEdit,
          color: e.colorEdit,
          maxMode: e.maxModeEdit,
          defaultPolicy: e.policyEdit
        });
        await this.loadCatalog();
      } catch (err) {
        this.errors.envs = err.message;
      }
    },

    async removeEnv(name) {
      if (!window.confirm("删除环境 " + name + "？仍被分组使用时会失败。")) return;
      this.errors.envs = "";
      try {
        await postJSON("/api/envs/remove", { name });
        await this.loadCatalog();
      } catch (err) {
        this.errors.envs = err.message;
      }
    },

    async removeKnown(marker) {
      if (!window.confirm("删除已知主机密钥 " + marker + "？下次连接会重新记录第一把钥匙。")) return;
      this.errors.known = "";
      try {
        await postJSON("/api/known-hosts/remove", { marker });
        await this.loadKnown();
      } catch (err) {
        this.errors.known = err.message;
      }
    },

    async closeSession(alias) {
      this.errors.sessions = "";
      try {
        await postJSON("/api/sessions/close", { alias });
        await this.loadSessions();
      } catch (err) {
        this.errors.sessions = err.message;
      }
    },

    async runExec(ev) {
      this.errors.operate = "";
      const fd = new FormData(ev.target);
      try {
        const data = await postJSON("/api/exec", {
          alias: fd.get("alias"),
          command: fd.get("command"),
          timeout: fd.get("timeout") || "",
          confirm: fd.get("confirm") || "",
          allowOutflow: fd.get("allowOutflow") === "on"
        });
        if (data.stdoutSuppressed) {
          this.operateOut = "exit " + data.exitCode + "\n" + (data.notice || "noDataOutflow: command output discarded");
        } else {
          this.operateOut = "exit " + data.exitCode + "\n" + (data.stdout || "") + (data.stderr || "");
        }
        ev.target.reset();
        await this.loadAudit();
      } catch (err) {
        this.errors.operate = err.message;
      }
    },

    async runUpload(ev) {
      this.errors.operate = "";
      await ensureSession();
      const fd = new FormData(ev.target);
      try {
        let res = await apiFetch("/api/upload", { method: "POST", body: fd });
        let data = await res.json();
        if (res.status === 409 && data.needsConfirm) {
          const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
          if (typed == null) throw new Error(data.error || "已取消");
          fd.set("confirm", typed);
          res = await apiFetch("/api/upload", { method: "POST", body: fd });
          data = await res.json();
        }
        if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
        ev.target.reset();
        this.operateOut = "上传完成";
        await this.loadAudit();
      } catch (err) {
        this.errors.operate = err.message;
      }
    },

    async runDownload(ev) {
      this.errors.operate = "";
      await ensureSession();
      const fd = new FormData(ev.target);
      try {
        const res = await apiFetch("/api/download", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alias: fd.get("alias"), path: fd.get("path") })
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || res.statusText);
        }
        const blob = await res.blob();
        const cd = res.headers.get("Content-Disposition") || "";
        const match = /filename="?([^";]+)"?/.exec(cd);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = match ? match[1] : "download";
        a.click();
        URL.revokeObjectURL(url);
        ev.target.reset();
        await this.loadAudit();
      } catch (err) {
        this.errors.operate = err.message;
      }
    },

    async runRelay(ev) {
      this.errors.relay = "";
      this.relayNote = "";
      const fd = new FormData(ev.target);
      try {
        const data = await postJSON("/api/relay", {
          from: fd.get("from"),
          fromPath: fd.get("fromPath"),
          to: fd.get("to"),
          toPath: fd.get("toPath"),
          confirm: fd.get("confirm") || "",
          allowCrossEnv: fd.get("allowCrossEnv") === "on"
        });
        ev.target.reset();
        this.relayNote = "relay " + data.algo + " " + data.sum + " " + data.bytes + " bytes";
        await this.loadAudit();
      } catch (err) {
        this.errors.relay = err.message;
      }
    },

    async exportBundle() {
      this.errors.bundle = "";
      try {
        const data = await readJSON(await apiFetch("/api/config/export"));
        this.bundleYAML = data.yaml || "";
      } catch (err) {
        this.errors.bundle = err.message;
      }
    },

    async importBundle() {
      this.errors.bundle = "";
      try {
        await postJSON("/api/config/import", { yaml: this.bundleYAML });
        this.bundleYAML = "";
        await this.loadCatalog();
      } catch (err) {
        this.errors.bundle = err.message;
      }
    },

    async openTerminal(alias) {
      this.errors.terminal = "";
      alias = String(alias || this.termAlias || "").trim();
      this.go("terminal");
      if (!alias) {
        this.errors.terminal = "先选择主机";
        return;
      }
      const id = "t" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      this.tabs.push({ id, alias });
      this.activeTab = id;
      await this.$nextTick();
      try {
        await this.mountTerm(id, alias);
      } catch (err) {
        this.errors.terminal = err.message || String(err);
        this.closeTab(id);
      }
    },

    async mountTerm(id, alias) {
      const screen = document.getElementById("term-screen");
      if (!screen || !window.Terminal || !window.FitAddon) throw new Error("终端组件没有加载");
      const pane = document.createElement("div");
      pane.className = "term-pane";
      pane.id = "term-pane-" + id;
      screen.appendChild(pane);
      this.showPane(id);
      const term = new Terminal({
        cursorBlink: true,
        fontFamily: '"SF Mono", ui-monospace, Menlo, Consolas, monospace',
        fontSize: 13,
        theme: { background: "#1d1d1f", foreground: "#f5f5f7", cursor: "#f5f5f7", selectionBackground: "#3a3a3c" }
      });
      const fit = new FitAddon.FitAddon();
      term.loadAddon(fit);
      term.open(pane);
      fit.fit();
      const data = await postJSON("/api/terminal/open", { alias, cols: term.cols || 80, rows: term.rows || 24 });
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(proto + "//" + location.host + "/api/terminal/ws?ticket=" + encodeURIComponent(data.ticket));
      ws.binaryType = "arraybuffer";
      const pending = [];
      termMap.set(id, { term, fit, ws, pane });
      term.onData((text) => {
        const bytes = new TextEncoder().encode(text);
        if (ws.readyState === WebSocket.OPEN) ws.send(bytes);
        else pending.push(bytes);
      });
      term.onResize(({ cols, rows }) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "resize", cols, rows }));
      });
      ws.onopen = () => {
        fit.fit();
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        for (const bytes of pending.splice(0)) {
          if (ws.readyState === WebSocket.OPEN) ws.send(bytes);
        }
      };
      ws.onmessage = (ev) => {
        if (!termMap.has(id)) return;
        if (ev.data instanceof ArrayBuffer) term.write(new Uint8Array(ev.data));
        else if (typeof ev.data === "string") term.write(ev.data);
      };
      ws.onerror = () => {
        if (termMap.has(id)) this.errors.terminal = "终端连接失败";
      };
      ws.onclose = () => {
        if (!termMap.has(id)) return;
        term.write("\r\n[连接已关闭]\r\n");
      };
    },

    showPane(id) {
      document.querySelectorAll("#term-screen .term-pane").forEach((el) => {
        el.hidden = el.id !== "term-pane-" + id;
      });
    },

    fitTab(id) {
      const rec = termMap.get(id);
      if (!rec) return;
      try { rec.fit.fit(); } catch (err) { /* pane may be hidden */ }
    },

    closeTab(id) {
      const rec = termMap.get(id);
      termMap.delete(id);
      if (rec) {
        try { rec.ws.close(); } catch (err) { /* already closed */ }
        try { rec.term.dispose(); } catch (err) { /* already disposed */ }
        if (rec.pane && rec.pane.parentNode) rec.pane.parentNode.removeChild(rec.pane);
      }
      this.tabs = this.tabs.filter((t) => t.id !== id);
      if (this.activeTab === id) this.activeTab = this.tabs.length ? this.tabs[this.tabs.length - 1].id : "";
    }
  }));
});

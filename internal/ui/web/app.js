const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZES = [10, 20, 50];

document.addEventListener("alpine:init", () => {
  Alpine.data("sshui", () => sshui());
});

function sshui() {
  return {
    view: "home",
    navOpen: false,
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
    audit: { records: [], page: 1, pageSize: DEFAULT_PAGE_SIZE, total: 0, stats: {} },
    auditFilter: { op: "", host: "", group: "", env: "", status: "", since: "", until: "" },
    col: { time: "", status: "", op: "", host: "", env: "", command: "", reason: "" },
    q: { hosts: "", groups: "", tags: "", envs: "", policy: "", known: "" },
    pages: {
      hosts: { page: 1, size: DEFAULT_PAGE_SIZE },
      groups: { page: 1, size: DEFAULT_PAGE_SIZE },
      tags: { page: 1, size: DEFAULT_PAGE_SIZE },
      envs: { page: 1, size: DEFAULT_PAGE_SIZE },
      policy: { page: 1, size: DEFAULT_PAGE_SIZE },
      known: { page: 1, size: DEFAULT_PAGE_SIZE },
      sessions: { page: 1, size: DEFAULT_PAGE_SIZE }
    },
    selected: {},
    pickAll: false,
    tagDraft: {},
    tagBulk: {},
    dialog: { host: false, group: false, policy: false, env: false, batch: false },
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
    titles: {
      home: "概览",
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
      relay: "中继",
      bundle: "运维",
      settings: "设置"
    },
    viewAlias: {
      "": "home",
      home: "home",
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

    applyLook() {
      this.theme = this.draft.theme === "dark" ? "dark" : "light";
      this.density = this.draft.density === "compact" ? "compact" : "comfortable";
      document.documentElement.setAttribute("data-bs-theme", this.theme);
      document.documentElement.setAttribute("data-theme", this.theme);
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
      if (view === "home") this.loadDashboard();
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

    async readJSON(res) {
      const data = await res.json();
      if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
      return data;
    },

    async ensureSession() {
      if (this.csrf) return;
      const data = await this.readJSON(await this.api("/api/session"));
      this.csrf = data.csrf || "";
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
        const data = await res.json();
        if (res.status === 409 && data.needsConfirm) {
          const typed = window.prompt((data.error || "需要确认") + "\n请输入：" + (data.confirm || ""));
          if (typed == null) throw new Error(data.error || "已取消");
          if (data.confirmField) payload[data.confirmField] = typed;
          else payload.confirm = typed;
          payload.humanConfirm = payload.humanConfirm || typed;
          continue;
        }
        if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
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
          const data = await res.json();
          throw new Error(data.error || res.statusText);
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
        time: rec.time || "",
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
        policy: "", tags: "", allowMode: "all", allow: [], deny: [], confirm: [], setDefault: false
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
      const body = Object.assign({
        alias: String(form.alias || "").trim(),
        group: form.group,
        host: String(form.host || "").trim(),
        user: String(form.user || "").trim(),
        policy: form.policy || "",
        tags: this.commaList(form.tags),
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
        let data = await res.json();
        if (res.status === 409 && data.needsConfirm) {
          const typed = window.prompt(data.error + "\n请输入：" + data.confirm);
          if (typed == null) throw new Error(data.error);
          fd.set("confirm", typed);
          res = await this.api("/api/upload", { method: "POST", body: fd });
          data = await res.json();
        }
        if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
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
          const data = await res.json();
          throw new Error(data.error || res.statusText);
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
          data = await res.json();
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
          if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
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
      return this.dialog.host || this.dialog.group || this.dialog.policy || this.dialog.env || this.dialog.batch;
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
        const blob = [h.alias, h.group, h.host, h.user, h.env, (h.tags || []).join(" ")].join(" ").toLowerCase();
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
      return (this.dash.audit && this.dash.audit.entries) || 0;
    },

    opsEntries() {
      return (this.ops.audit && this.ops.audit.entries) || 0;
    },

    taggedCount() {
      return (this.catalog.hosts || []).filter((h) => h.tags && h.tags.length).length;
    }
  };
}

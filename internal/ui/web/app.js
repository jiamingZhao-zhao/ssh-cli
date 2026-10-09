const hostsBody = document.querySelector("#hosts");
const auditBody = document.querySelector("#audit");
const groupSelect = document.querySelector("#group");
const hostPolicySelect = document.querySelector("#host-policy");
const form = document.querySelector("#host-form");
const formTitle = document.querySelector("#form-title");
const formError = document.querySelector("#form-error");
const catalogError = document.querySelector("#catalog-error");
const auditError = document.querySelector("#audit-error");
const groupForm = document.querySelector("#group-form");
const groupError = document.querySelector("#group-error");
const tagError = document.querySelector("#tag-error");
const policyForm = document.querySelector("#policy-form");
const policyError = document.querySelector("#policy-error");
const envForm = document.querySelector("#env-form");
const envError = document.querySelector("#env-error");
const knownBody = document.querySelector("#known");
const knownError = document.querySelector("#known-error");

let catalog = { envs: [], groups: [], hosts: [], policies: [] };
let csrfToken = "";
let editing = false;
let auditPage = 1;
let auditPageSize = 10;
const PAGE_SIZES = [10, 20, 50];
const DEFAULT_PAGE_SIZE = 10;
const pageState = {};
let editingGroup = false;
let editingPolicy = "";
let groupEnvWas = "";

function showError(el, msg) {
  if (!msg) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = msg;
}

async function readJSON(res) {
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || res.statusText);
  }
  return data;
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

function cell(text) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = "clip";
  span.textContent = text == null || text === "" ? "" : String(text);
  span.title = span.textContent;
  span.addEventListener("click", () => span.classList.toggle("open"));
  td.append(span);
  return td;
}

function lines(text) {
  return String(text || "").split("\n").map((s) => s.trim()).filter(Boolean);
}

function commaList(text) {
  return String(text || "").split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
}

function allowLabel(row) {
  if (!row || !row.allowSet) return "全集";
  if (!row.allow || row.allow.length === 0) return "（空）";
  return row.allow.join(", ");
}

function listLabel(items) {
  if (!items || items.length === 0) return "";
  return items.join(", ");
}

function byName(a, b) {
  return String(a.name || a.alias || "").localeCompare(String(b.name || b.alias || ""));
}

function option(value, label, selected) {
  const el = document.createElement("option");
  el.value = value;
  el.textContent = label;
  if (value === selected) el.selected = true;
  return el;
}

function policyChoices(selected) {
  const opts = [option("", "不引用", selected || "")];
  for (const p of catalog.policies || []) {
    let label = p.name;
    if (p.overridden) label += "（已覆盖）";
    else if (p.builtin) label += "（内置）";
    opts.push(option(p.name, label, selected || ""));
  }
  return opts;
}

function fillPolicySelect(select, selected) {
  const keep = selected != null ? selected : select.value;
  select.replaceChildren(...policyChoices(keep));
}

function fillEnvSelect(select, selected) {
  const keep = selected != null ? selected : select.value;
  const envs = (catalog.envs || []).slice().sort(byName);
  select.replaceChildren();
  if (envs.length === 0) {
    select.appendChild(option("", "先添加环境", ""));
    return;
  }
  for (const e of envs) {
    const label = e.name + (e.label ? " / " + e.label : "") + " / " + e.maxMode;
    select.appendChild(option(e.name, label, keep));
  }
}

function ruleBody(formEl) {
  const allowMode = formEl.elements.namedItem("allowMode").value;
  return {
    allow: allowMode === "list" ? lines(formEl.elements.namedItem("allow").value) : null,
    deny: lines(formEl.elements.namedItem("deny").value),
    confirm: lines(formEl.elements.namedItem("confirm").value)
  };
}

function fillRules(formEl, row) {
  formEl.elements.namedItem("allowMode").value = row && row.allowSet ? "list" : "all";
  formEl.elements.namedItem("allow").value = ((row && row.allow) || []).join("\n");
  formEl.elements.namedItem("deny").value = ((row && row.deny) || []).join("\n");
  formEl.elements.namedItem("confirm").value = ((row && row.confirm) || []).join("\n");
}

async function loadCatalog() {
  showError(catalogError, "");
  catalog = await readJSON(await apiFetch("/api/catalog"));
  renderGroups();
  renderTags();
  renderPolicies();
  renderEnvs();
  renderHosts();
  refreshChrome();
  fillChoices();
  applyFilters();
}

function renderGroups() {
  const body = document.querySelector("#group-rows");
  body.replaceChildren();
  const groups = (catalog.groups || []).slice().sort(byName);
  for (const g of groups) {
    const tr = document.createElement("tr");
    tr.append(
      cell(g.name),
      cell(g.label || ""),
      cell(g.env),
      cell(g.policy || ""),
      cell(allowLabel(g)),
      cell(listLabel(g.deny)),
      cell(listLabel(g.confirm)),
      cell(g.hosts)
    );
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = "编辑";
    edit.addEventListener("click", () => fillGroup(g));
    actions.append(edit);
    if (!g.hosts) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger";
      remove.textContent = "删除";
      remove.addEventListener("click", () => removeGroup(g.name));
      actions.append(document.createTextNode(" "), remove);
    }
    tr.append(actions);
    body.appendChild(tr);
  }
  fillEnvSelect(document.querySelector("#group-env"));
  fillPolicySelect(document.querySelector("#group-policy"));
}

function fillGroup(g) {
  editingGroup = true;
  groupEnvWas = g.env;
  document.querySelector("#group-form-title").textContent = "编辑 " + g.name;
  groupForm.elements.namedItem("name").value = g.name;
  groupForm.elements.namedItem("name").readOnly = true;
  groupForm.elements.namedItem("label").value = g.label || "";
  fillEnvSelect(document.querySelector("#group-env"), g.env);
  fillPolicySelect(document.querySelector("#group-policy"), g.policy || "");
  fillRules(groupForm, g);
  groupForm.elements.namedItem("protectedPaths").value = (g.protectedPaths || []).join("\n");
  showError(groupError, "");
  reveal(groupForm);
}

function resetGroupForm() {
  editingGroup = false;
  groupEnvWas = "";
  HTMLFormElement.prototype.reset.call(groupForm);
  groupForm.elements.namedItem("name").readOnly = false;
  document.querySelector("#group-form-title").textContent = "添加分组";
  showError(groupError, "");
}

async function removeGroup(name) {
  if (!window.confirm("删除空分组 " + name + "？")) return;
  showError(groupError, "");
  try {
    await postJSON("/api/groups/remove", { name });
    if (groupForm.elements.namedItem("name").value === name) resetGroupForm();
    await loadCatalog();
  } catch (err) {
    showError(groupError, err.message);
  }
}

function renderTags() {
  const body = document.querySelector("#tag-rows");
  body.replaceChildren();
  const groups = (catalog.groups || []).slice().sort(byName);
  const hosts = catalog.hosts || [];
  for (const g of groups) {
    const mine = hosts.filter((h) => h.group === g.name).sort(byName);
    const tr = document.createElement("tr");
    tr.append(cell(groupCaption(g)), cell(g.env));
    const hostsCell = document.createElement("td");
    if (mine.length === 0) {
      hostsCell.textContent = "还没有主机。标签不能写在分组上。";
    } else {
      for (const h of mine) {
        const line = document.createElement("div");
        line.className = "tag-line";
        const name = document.createElement("span");
        name.textContent = h.alias;
        const input = document.createElement("input");
        input.value = (h.tags || []).join(",");
        input.setAttribute("aria-label", h.alias + " 的标签");
        const save = document.createElement("button");
        save.type = "button";
        save.className = "secondary";
        save.textContent = "保存";
        save.addEventListener("click", () => saveHostTags(h.alias, input.value));
        line.append(name, input, save);
        hostsCell.append(line);
      }
    }
    const bulk = document.createElement("td");
    const bulkInput = document.createElement("input");
    bulkInput.placeholder = "app";
    bulkInput.setAttribute("aria-label", g.name + " 全组标签");
    bulk.append(bulkInput);
    const actions = document.createElement("td");
    const add = document.createElement("button");
    add.type = "button";
    add.textContent = "加到全组";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "secondary";
    remove.textContent = "从全组去掉";
    add.disabled = mine.length === 0;
    remove.disabled = mine.length === 0;
    add.addEventListener("click", () => applyGroupTags(g.name, bulkInput.value, "add"));
    remove.addEventListener("click", () => applyGroupTags(g.name, bulkInput.value, "remove"));
    actions.append(add, document.createTextNode(" "), remove);
    tr.append(hostsCell, bulk, actions);
    body.appendChild(tr);
  }
}

async function saveHostTags(alias, text) {
  showError(tagError, "");
  try {
    await postJSON("/api/hosts/update", { alias, tags: commaList(text) });
    await loadCatalog();
  } catch (err) {
    showError(tagError, err.message);
  }
}

async function applyGroupTags(group, text, which) {
  const tags = commaList(text);
  if (tags.length === 0) {
    showError(tagError, "先填写标签");
    return;
  }
  showError(tagError, "");
  const body = { group };
  body[which] = tags;
  try {
    await postJSON("/api/groups/tags", body);
    await loadCatalog();
  } catch (err) {
    showError(tagError, err.message);
  }
}

function sourceLabel(p) {
  if (p.overridden) return "覆盖内置";
  if (p.builtin) return "内置";
  return "自定义";
}

function renderPolicies() {
  const body = document.querySelector("#policy-rows");
  body.replaceChildren();
  for (const p of catalog.policies || []) {
    const tr = document.createElement("tr");
    tr.append(
      cell(p.name),
      cell(sourceLabel(p)),
      cell(p.mode || ""),
      cell(allowLabel(p)),
      cell(listLabel(p.deny)),
      cell(listLabel(p.confirm))
    );
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = p.builtin && !p.overridden ? "覆盖" : "编辑";
    edit.addEventListener("click", () => fillPolicy(p, p.builtin && !p.overridden ? "create" : "update"));
    actions.append(edit);
    if (p.overridden || !p.builtin) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger";
      remove.textContent = p.overridden ? "恢复内置" : "删除";
      remove.addEventListener("click", () => removePolicy(p));
      actions.append(document.createTextNode(" "), remove);
    }
    tr.append(actions);
    body.appendChild(tr);
  }
  fillPolicySelect(document.querySelector("#env-policy"));
  fillPolicySelect(hostPolicySelect);
  fillPolicySelect(document.querySelector("#group-policy"));
}

function fillPolicy(p, mode) {
  editingPolicy = mode;
  const title = p.builtin && mode === "create" ? "覆盖内置 " + p.name : "编辑 " + p.name;
  document.querySelector("#policy-form-title").textContent = title;
  policyForm.elements.namedItem("name").value = p.name;
  policyForm.elements.namedItem("name").readOnly = true;
  policyForm.elements.namedItem("mode").value = p.mode || "";
  fillRules(policyForm, p);
  showError(policyError, "");
  reveal(policyForm);
}

function resetPolicyForm() {
  editingPolicy = "";
  HTMLFormElement.prototype.reset.call(policyForm);
  policyForm.elements.namedItem("name").readOnly = false;
  document.querySelector("#policy-form-title").textContent = "添加命名策略";
  showError(policyError, "");
}

async function removePolicy(p) {
  const msg = p.overridden ? "恢复内置策略 " + p.name + "？" : "删除策略 " + p.name + "？";
  if (!window.confirm(msg)) return;
  showError(policyError, "");
  try {
    await postJSON("/api/policies/remove", { name: p.name });
    if (policyForm.elements.namedItem("name").value === p.name) resetPolicyForm();
    await loadCatalog();
  } catch (err) {
    showError(policyError, err.message);
  }
}

function modeSelect(selected) {
  const select = document.createElement("select");
  select.dataset.max = "1";
  for (const mode of ["readonly", "standard", "admin"]) {
    select.appendChild(option(mode, mode, selected));
  }
  return select;
}

function renderEnvs() {
  const body = document.querySelector("#env-rows");
  body.replaceChildren();
  const envs = (catalog.envs || []).slice().sort(byName);
  for (const e of envs) {
    const tr = document.createElement("tr");
    if (e.builtin) {
      tr.append(
        cell(e.name),
        cell(e.label || ""),
        cell(e.color || ""),
        cell(e.maxMode),
        cell(e.defaultPolicy || ""),
        cell("内置，不可改")
      );
      body.appendChild(tr);
      continue;
    }
    tr.append(cell(e.name));
    const labelCell = document.createElement("td");
    const label = document.createElement("input");
    label.value = e.label || "";
    label.dataset.label = "1";
    labelCell.append(label);
    const colorCell = document.createElement("td");
    const color = document.createElement("input");
    color.value = e.color || "";
    color.dataset.color = "1";
    colorCell.append(color);
    const modeCell = document.createElement("td");
    modeCell.append(modeSelect(e.maxMode));
    const polCell = document.createElement("td");
    const pol = document.createElement("select");
    pol.dataset.pol = "1";
    pol.replaceChildren(...policyChoices(e.defaultPolicy || ""));
    polCell.append(pol);
    const actions = document.createElement("td");
    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "保存";
    save.addEventListener("click", () => saveEnv(e.name, tr));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "删除";
    remove.addEventListener("click", () => removeEnv(e.name));
    actions.append(save, document.createTextNode(" "), remove);
    tr.append(labelCell, colorCell, modeCell, polCell, actions);
    body.appendChild(tr);
  }
  fillPolicySelect(document.querySelector("#env-policy"));
}

async function saveEnv(name, row) {
  showError(envError, "");
  try {
    await postJSON("/api/envs/update", {
      name,
      label: row.querySelector("[data-label]").value,
      color: row.querySelector("[data-color]").value,
      maxMode: row.querySelector("[data-max]").value,
      defaultPolicy: row.querySelector("[data-pol]").value
    });
    await loadCatalog();
  } catch (err) {
    showError(envError, err.message);
  }
}

async function removeEnv(name) {
  if (!window.confirm("删除环境 " + name + "？仍被分组使用时会失败。")) return;
  showError(envError, "");
  try {
    await postJSON("/api/envs/remove", { name });
    await loadCatalog();
  } catch (err) {
    showError(envError, err.message);
  }
}

function groupCaption(g) {
  if (!g) return "";
  return g.label ? g.name + " / " + g.label : g.name;
}

function groupByName(name) {
  return (catalog.groups || []).find((g) => g.name === name);
}

function renderHosts() {
  const groups = (catalog.groups || []).slice().sort(byName);
  const hosts = (catalog.hosts || []).slice().sort(byName);
  const prevGroup = groupSelect.value;
  groupSelect.replaceChildren();
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.name;
    opt.textContent = groupCaption(g) + " (" + g.env + ")";
    groupSelect.appendChild(opt);
  }
  if (prevGroup) groupSelect.value = prevGroup;
  fillPolicySelect(hostPolicySelect);
  hostsBody.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement("tr");
    tr.append(
      cell(h.alias + (h.default ? " *" : "")),
      cell(groupCaption(groupByName(h.group)) || h.group),
      cell(h.env),
      cell(h.host),
      cell(h.port),
      cell(h.user),
      cell(h.auth),
      cell((h.tags || []).join(","))
    );
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = "编辑";
    edit.addEventListener("click", () => fillForm(h));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "删除";
    remove.addEventListener("click", () => removeHost(h.alias));
    actions.append(edit, document.createTextNode(" "), remove);
    tr.append(actions);
    hostsBody.appendChild(tr);
  }
}

function fillForm(h) {
  editing = true;
  formTitle.textContent = "编辑 " + h.alias;
  form.alias.value = h.alias;
  form.alias.readOnly = true;
  form.group.value = h.group;
  form.host.value = h.host;
  form.port.value = h.port || "";
  form.user.value = h.user;
  form.password.value = "";
  form.identity.value = "";
  fillPolicySelect(hostPolicySelect, h.policy || "");
  form.tags.value = (h.tags || []).join(",");
  fillRules(form, h);
  form.setDefault.checked = !!h.default;
  showError(formError, "");
  reveal(form);
}

function resetForm() {
  editing = false;
  HTMLFormElement.prototype.reset.call(form);
  form.alias.readOnly = false;
  formTitle.textContent = "添加主机";
  showError(formError, "");
}

async function removeHost(alias) {
  if (!window.confirm("删除主机 " + alias + "？")) return;
  showError(catalogError, "");
  try {
    await postJSON("/api/hosts/remove", { alias });
    if (form.alias.value === alias) resetForm();
    await loadCatalog();
  } catch (err) {
    showError(catalogError, err.message);
  }
}

groupForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(groupError, "");
  const name = groupForm.elements.namedItem("name").value.trim();
  const envName = groupForm.elements.namedItem("env").value;
  if (editingGroup && groupEnvWas === "prod" && envName !== "prod") {
    if (!window.confirm("把分组 " + name + " 的环境从 prod 改成 " + envName + "？这会改变该组主机的权限天花板。")) {
      return;
    }
  }
  const body = Object.assign({
    name,
    label: groupForm.elements.namedItem("label").value.trim(),
    env: envName,
    policy: groupForm.elements.namedItem("policy").value,
    protectedPaths: lines(groupForm.elements.namedItem("protectedPaths").value)
  }, ruleBody(groupForm));
  try {
    await postJSON(editingGroup ? "/api/groups/update" : "/api/groups", body);
    resetGroupForm();
    closeDialog(groupForm);
    await loadCatalog();
  } catch (err) {
    showError(groupError, err.message);
  }
});

document.querySelector("#group-clear").addEventListener("click", () => { resetGroupForm(); closeDialog(groupForm); });

policyForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(policyError, "");
  const body = Object.assign({
    name: policyForm.elements.namedItem("name").value.trim(),
    mode: policyForm.elements.namedItem("mode").value
  }, ruleBody(policyForm));
  try {
    await postJSON(editingPolicy === "update" ? "/api/policies/update" : "/api/policies", body);
    resetPolicyForm();
    closeDialog(policyForm);
    await loadCatalog();
  } catch (err) {
    showError(policyError, err.message);
  }
});

document.querySelector("#policy-clear").addEventListener("click", () => { resetPolicyForm(); closeDialog(policyForm); });

envForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(envError, "");
  try {
    await postJSON("/api/envs", {
      name: envForm.elements.namedItem("name").value.trim(),
      label: envForm.elements.namedItem("label").value.trim(),
      color: envForm.elements.namedItem("color").value.trim(),
      maxMode: envForm.elements.namedItem("maxMode").value,
      defaultPolicy: envForm.elements.namedItem("defaultPolicy").value
    });
    HTMLFormElement.prototype.reset.call(envForm);
    closeDialog(envForm);
    await loadCatalog();
  } catch (err) {
    showError(envError, err.message);
  }
});

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(formError, "");
  const body = Object.assign({
    alias: form.alias.value.trim(),
    group: form.group.value,
    host: form.host.value.trim(),
    user: form.user.value.trim(),
    policy: form.policy.value,
    tags: commaList(form.tags.value),
    setDefault: form.setDefault.checked
  }, ruleBody(form));
  if (form.port.value !== "") body.port = Number(form.port.value);
  if (form.password.value !== "") body.password = form.password.value;
  if (form.identity.value.trim() !== "") body.identity = form.identity.value.trim();
  try {
    await postJSON(editing ? "/api/hosts/update" : "/api/hosts", body);
    resetForm();
    closeDialog(form);
    await loadCatalog();
  } catch (err) {
    showError(formError, err.message);
  }
});

document.querySelector("#clear-form").addEventListener("click", () => { resetForm(); closeDialog(form); });

function subject(rec) {
  if (rec.command) return rec.command;
  if (rec.src || rec.dst) return (rec.src || "") + " → " + (rec.dst || "");
  return "";
}

function auditQuery() {
  const fd = new FormData(document.querySelector("#audit-filter"));
  const params = new URLSearchParams();
  for (const [k, v] of fd.entries()) {
    if (String(v).trim() !== "") params.set(k, String(v).trim());
  }
  params.set("page", String(auditPage));
  params.set("pageSize", String(auditPageSize));
  return params;
}

async function loadAudit() {
  showError(auditError, "");
  const data = await readJSON(await apiFetch("/api/audit?" + auditQuery().toString()));
  auditBody.replaceChildren();
  for (const rec of data.records || []) {
    const tr = document.createElement("tr");
    tr.append(
      cell(rec.time),
      cell(rec.status),
      cell(rec.op),
      cell(rec.host),
      cell(rec.env || ""),
      cell(rec.exit_code == null ? "" : rec.exit_code),
      cell(rec.high_risk ? "yes" : ""),
      cell(subject(rec)),
      cell(rec.reason || "")
    );
    auditBody.appendChild(tr);
  }
  const stats = data.stats || {};
  const size = data.pageSize || auditPageSize;
  const pages = Math.max(1, Math.ceil((data.total || 0) / size));
  setText("#summary-audit", "日志 " + (stats.files || 0) + " 个文件，" + (stats.entries || 0) + " 条，" + (stats.bytes || 0) + " 字节 · 筛选 " + (data.total || 0) + " 条");
  setBadge("audit", stats.entries || 0);
  renderPager(document.querySelector("#audit-pager"), {
    page: data.page || auditPage,
    pages: pages,
    total: data.total || 0,
    size: size,
    onPage: (p) => {
      auditPage = p;
      loadAudit().catch((err) => showError(auditError, err.message));
    },
    onSize: (n) => {
      auditPageSize = n;
      auditPage = 1;
      loadAudit().catch((err) => showError(auditError, err.message));
    }
  });
}

document.querySelector("#audit-filter").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  auditPage = 1;
  try {
    await loadAudit();
  } catch (err) {
    showError(auditError, err.message);
  }
});
document.querySelector("#audit-cleanup").addEventListener("click", async () => {
  showError(auditError, "");
  try {
    const data = await postJSON("/api/audit/cleanup", {});
    await loadAudit();
    showError(auditError, "");
    setText("#summary-audit", (document.querySelector("#summary-audit").textContent || "") + " · 已删除 " + data.removed + " 条");
  } catch (err) {
    showError(auditError, err.message);
  }
});

async function loadKnown() {
  showError(knownError, "");
  const data = await readJSON(await apiFetch("/api/known-hosts"));
  knownBody.replaceChildren();
  for (const entry of data.knownHosts || []) {
    const tr = document.createElement("tr");
    tr.append(cell(entry.marker), cell(entry.keyType), cell(entry.fingerprint));
    const actions = document.createElement("td");
    const rm = document.createElement("button");
    rm.type = "button";
    rm.className = "secondary";
    rm.textContent = "删除";
    rm.addEventListener("click", async () => {
      if (!window.confirm("删除已知主机密钥 " + entry.marker + "？下次连接会重新记录第一把钥匙。")) return;
      try {
        await postJSON("/api/known-hosts/remove", { marker: entry.marker });
        await loadKnown();
      } catch (err) {
        showError(knownError, err.message);
      }
    });
    actions.append(rm);
    tr.append(actions);
    knownBody.appendChild(tr);
  }
  const n = (data.knownHosts || []).length;
  setText("#summary-known", n + " 条");
  setBadge("known", n);
  applyFilters();
}

function setText(sel, text) {
  const el = document.querySelector(sel);
  if (el) el.textContent = text;
}

function setBadge(name, n) {
  setText("#badge-" + name, String(n));
}

function refreshChrome() {
  const hosts = catalog.hosts || [];
  const groups = catalog.groups || [];
  const envs = catalog.envs || [];
  const policies = catalog.policies || [];
  const tagged = hosts.filter((h) => h.tags && h.tags.length).length;
  setBadge("hosts", hosts.length);
  setBadge("groups", groups.length);
  setBadge("tags", tagged);
  setBadge("envs", envs.length);
  setBadge("policy", policies.length);
  const def = hosts.find((h) => h.default);
  setText("#summary-hosts", hosts.length + " 台主机" + (def ? " · 默认 " + def.alias : ""));
  setText("#summary-groups", groups.length + " 个分组");
  setText("#summary-tags", tagged + " 台主机带了标签");
  const builtin = envs.filter((e) => e.builtin).length;
  setText("#summary-envs", envs.length + " 个环境 · 内置 " + builtin);
  setText("#summary-policy", policies.length + " 条命名策略");
}

function applyFilters() {
  document.querySelectorAll("[data-filter]").forEach((input) => {
    const body = document.querySelector(input.dataset.filter);
    if (!body) return;
    const q = input.value.trim().toLowerCase();
    for (const tr of body.rows) {
      tr.dataset.hit = q === "" || tr.textContent.toLowerCase().includes(q) ? "1" : "0";
    }
  });
  pageTables();
}

function ensurePage(key) {
  const cur = pageState[key];
  if (!cur || typeof cur !== "object") pageState[key] = { page: 1, size: DEFAULT_PAGE_SIZE };
  const st = pageState[key];
  if (!PAGE_SIZES.includes(st.size)) st.size = DEFAULT_PAGE_SIZE;
  if (!Number.isFinite(st.page) || st.page < 1) st.page = 1;
  return st;
}

function renderPager(bar, state) {
  if (!bar) return;
  bar.replaceChildren();
  const total = document.createElement("span");
  total.className = "pager-meta";
  total.textContent = "共 " + state.total + " 条";
  const sizeLabel = document.createElement("label");
  sizeLabel.className = "pager-size";
  const sizeText = document.createElement("span");
  sizeText.textContent = "每页";
  const select = document.createElement("select");
  select.setAttribute("aria-label", "每页条数");
  for (const n of PAGE_SIZES) {
    const opt = document.createElement("option");
    opt.value = String(n);
    opt.textContent = String(n);
    if (n === state.size) opt.selected = true;
    select.appendChild(opt);
  }
  select.addEventListener("change", () => state.onSize(Number(select.value)));
  sizeLabel.append(sizeText, select);
  const prev = document.createElement("button");
  prev.type = "button";
  prev.className = "secondary";
  prev.textContent = "上一页";
  prev.disabled = state.page <= 1;
  prev.addEventListener("click", () => state.onPage(state.page - 1));
  const label = document.createElement("span");
  label.className = "pager-meta";
  label.textContent = state.page + " / " + state.pages;
  const next = document.createElement("button");
  next.type = "button";
  next.className = "secondary";
  next.textContent = "下一页";
  next.disabled = state.page >= state.pages;
  next.addEventListener("click", () => state.onPage(state.page + 1));
  bar.append(total, sizeLabel, prev, label, next);
}

function pageTables() {
  document.querySelectorAll("[data-pager]").forEach((bar) => {
    const key = bar.dataset.pager;
    const body = document.querySelector(key);
    if (!body) return;
    const st = ensurePage(key);
    const rows = [...body.rows].filter((tr) => tr.dataset.hit !== "0");
    const pages = Math.max(1, Math.ceil(rows.length / st.size) || 1);
    if (st.page > pages) st.page = pages;
    for (const tr of body.rows) tr.hidden = true;
    rows.forEach((tr, i) => {
      tr.hidden = i < (st.page - 1) * st.size || i >= st.page * st.size;
    });
    renderPager(bar, {
      page: st.page,
      pages: pages,
      total: rows.length,
      size: st.size,
      onPage: (p) => { st.page = p; pageTables(); },
      onSize: (n) => { st.size = n; st.page = 1; pageTables(); }
    });
  });
}

function fillSelect(select, values, current) {
  const keep = current != null ? current : select.value;
  select.replaceChildren(option("", "全部", ""));
  for (const v of values) select.appendChild(option(v, v, keep));
  if (keep) select.value = keep;
}

function fillChoices() {
  const hosts = (catalog.hosts || []).map((h) => h.alias).sort();
  const groups = (catalog.groups || []).map((g) => g.name).sort();
  const envs = (catalog.envs || []).map((e) => e.name).sort();
  fillSelect(document.querySelector("#audit-host"), hosts);
  fillSelect(document.querySelector("#audit-group"), groups);
  fillSelect(document.querySelector("#audit-env"), envs);
  document.querySelectorAll("#op-host, .op-host, select[name=from], select[name=to]").forEach((select) => {
    const keep = select.value;
    select.replaceChildren();
    for (const alias of hosts) select.appendChild(option(alias, alias, keep));
  });
}

function reveal(el) {
  const dialog = el && el.closest ? el.closest("dialog") : null;
  if (dialog && !dialog.open) dialog.showModal();
}

function closeDialog(el) {
  const dialog = el && el.closest ? el.closest("dialog") : null;
  if (dialog && dialog.open) dialog.close();
}

function bindDialog(id, reset) {
  const dialog = document.querySelector(id);
  if (!dialog) return;
  dialog.addEventListener("close", reset);
  dialog.addEventListener("click", (ev) => {
    if (ev.target === dialog) dialog.close();
  });
}

const viewAlias = {
  "": "hosts",
  hosts: "hosts",
  "hosts-panel": "hosts",
  groups: "groups",
  tags: "tags",
  envs: "envs",
  policy: "policy",
  known: "known",
  "known-panel": "known",
  audit: "audit",
  "audit-panel": "audit",
  sessions: "sessions",
  operate: "operate",
  relay: "relay",
  bundle: "bundle"
};

function showView(name) {
  const view = viewAlias[name] || "hosts";
  document.querySelectorAll(".view").forEach((el) => {
    el.hidden = el.dataset.view !== view;
  });
  document.querySelectorAll("button[data-view]").forEach((btn) => {
    const on = btn.dataset.view === view;
    btn.classList.toggle("active", on);
    if (on) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  });
  const current = document.querySelector('.view[data-view="' + view + '"]');
  setText("#page-title", current ? current.dataset.title : "ssh-cli");
  if (location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
}

document.querySelectorAll("button[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});
document.querySelectorAll("[data-filter]").forEach((input) => {
  input.addEventListener("input", () => {
    const st = pageState[input.dataset.filter];
    if (st) st.page = 1;
    applyFilters();
  });
});
document.querySelector("#host-new").addEventListener("click", () => {
  resetForm();
  reveal(form);
});
document.querySelector("#group-new").addEventListener("click", () => {
  resetGroupForm();
  reveal(groupForm);
});
document.querySelector("#policy-new").addEventListener("click", () => {
  resetPolicyForm();
  reveal(policyForm);
});
document.querySelector("#env-new").addEventListener("click", () => {
  HTMLFormElement.prototype.reset.call(envForm);
  reveal(envForm);
});
bindDialog("#host-dialog", resetForm);
bindDialog("#group-dialog", resetGroupForm);
bindDialog("#policy-dialog", resetPolicyForm);
bindDialog("#env-dialog", () => HTMLFormElement.prototype.reset.call(envForm));
window.addEventListener("hashchange", () => showView(location.hash.replace("#", "")));
showView(location.hash.replace("#", ""));

const operateError = document.querySelector("#operate-error");
const relayError = document.querySelector("#relay-error");
const bundleError = document.querySelector("#bundle-error");
const sessionError = document.querySelector("#session-error");

async function loadSessions() {
  showError(sessionError, "");
  const data = await readJSON(await apiFetch("/api/sessions"));
  const body = document.querySelector("#session-rows");
  body.replaceChildren();
  for (const item of data.sessions || []) {
    const tr = document.createElement("tr");
    tr.append(cell(item.alias), cell(item.opened), cell(item.used), cell(item.busy));
    const actions = document.createElement("td");
    const close = document.createElement("button");
    close.type = "button";
    close.className = "danger";
    close.textContent = "关闭";
    close.addEventListener("click", async () => {
      try {
        await postJSON("/api/sessions/close", { alias: item.alias });
        await loadSessions();
      } catch (err) {
        showError(sessionError, err.message);
      }
    });
    actions.append(close);
    tr.append(actions);
    body.appendChild(tr);
  }
  setText("#summary-sessions", (data.sessions || []).length + " 个会话在这个进程里");
  pageTables();
}

document.querySelector("#session-refresh").addEventListener("click", () => {
  loadSessions().catch((err) => showError(sessionError, err.message));
});

document.querySelector("#exec-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(operateError, "");
  const fd = new FormData(ev.target);
  try {
    const data = await postJSON("/api/exec", {
      alias: fd.get("alias"),
      command: fd.get("command"),
      timeout: fd.get("timeout") || "",
      confirm: fd.get("confirm") || "",
      allowOutflow: fd.get("allowOutflow") === "on"
    });
    const out = document.querySelector("#operate-out");
    out.hidden = false;
    if (data.stdoutSuppressed) {
      out.textContent = "exit " + data.exitCode + "\n" + (data.notice || "noDataOutflow: command output discarded");
    } else {
      out.textContent = "exit " + data.exitCode + "\n" + (data.stdout || "") + (data.stderr || "");
    }
    ev.target.reset();
    await loadAudit();
  } catch (err) {
    showError(operateError, err.message);
  }
});

document.querySelector("#upload-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(operateError, "");
  await ensureSession();
  const fd = new FormData(ev.target);
  try {
    const res = await apiFetch("/api/upload", {
      method: "POST",
      body: fd
    });
    const data = await res.json();
    if (res.status === 409 && data.needsConfirm) {
      const typed = window.prompt(data.error + "\n请输入：" + data.confirm);
      if (typed == null) throw new Error(data.error);
      fd.set("confirm", typed);
      const retry = await apiFetch("/api/upload", {
        method: "POST",
        body: fd
      });
      const again = await retry.json();
      if (!retry.ok || again.ok === false) throw new Error(again.error || retry.statusText);
    } else if (!res.ok || data.ok === false) {
      throw new Error(data.error || res.statusText);
    }
    ev.target.reset();
    await loadAudit();
  } catch (err) {
    showError(operateError, err.message);
  }
});

document.querySelector("#download-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(operateError, "");
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
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "download";
    a.click();
    URL.revokeObjectURL(url);
    ev.target.reset();
    await loadAudit();
  } catch (err) {
    showError(operateError, err.message);
  }
});

document.querySelector("#relay-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(relayError, "");
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
    showError(relayError, "");
    setText("#summary-sessions", "");
    const out = document.querySelector("#operate-out");
    out.hidden = false;
    out.textContent = "relay " + data.algo + " " + data.sum + " " + data.bytes + " bytes";
    await loadAudit();
  } catch (err) {
    showError(relayError, err.message);
  }
});

document.querySelector("#bundle-export").addEventListener("click", async () => {
  showError(bundleError, "");
  try {
    const data = await readJSON(await apiFetch("/api/config/export"));
    document.querySelector("#bundle-yaml").value = data.yaml || "";
  } catch (err) {
    showError(bundleError, err.message);
  }
});

document.querySelector("#bundle-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(bundleError, "");
  try {
    await postJSON("/api/config/import", { yaml: document.querySelector("#bundle-yaml").value });
    document.querySelector("#bundle-yaml").value = "";
    await loadCatalog();
  } catch (err) {
    showError(bundleError, err.message);
  }
});

document.querySelector("#env-clear").addEventListener("click", () => {
  HTMLFormElement.prototype.reset.call(envForm);
  closeDialog(envForm);
});

loadCatalog().catch((err) => showError(catalogError, err.message));
loadKnown().catch((err) => showError(knownError, err.message));
loadAudit().catch((err) => showError(auditError, err.message));
loadSessions().catch((err) => showError(sessionError, err.message));

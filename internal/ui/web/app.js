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

let catalog = { envs: [], groups: [], hosts: [], policies: [] };
let editing = false;
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

async function postJSON(url, body) {
  return readJSON(await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }));
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text == null || text === "" ? "" : String(text);
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
  catalog = await readJSON(await fetch("/api/catalog"));
  renderGroups();
  renderTags();
  renderPolicies();
  renderEnvs();
  renderHosts();
}

function renderGroups() {
  const body = document.querySelector("#group-rows");
  body.replaceChildren();
  const groups = (catalog.groups || []).slice().sort(byName);
  for (const g of groups) {
    const tr = document.createElement("tr");
    tr.append(
      cell(g.name),
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
  fillEnvSelect(document.querySelector("#group-env"), g.env);
  fillPolicySelect(document.querySelector("#group-policy"), g.policy || "");
  fillRules(groupForm, g);
  groupForm.elements.namedItem("protectedPaths").value = (g.protectedPaths || []).join("\n");
  showError(groupError, "");
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
    tr.append(cell(g.name), cell(g.env));
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

function renderHosts() {
  const groups = (catalog.groups || []).slice().sort(byName);
  const hosts = (catalog.hosts || []).slice().sort(byName);
  const prevGroup = groupSelect.value;
  groupSelect.replaceChildren();
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.name;
    opt.textContent = g.name + " (" + g.env + ")";
    groupSelect.appendChild(opt);
  }
  if (prevGroup) groupSelect.value = prevGroup;
  fillPolicySelect(hostPolicySelect);
  hostsBody.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement("tr");
    tr.append(
      cell(h.alias + (h.default ? " *" : "")),
      cell(h.group),
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
    env: envName,
    policy: groupForm.elements.namedItem("policy").value,
    protectedPaths: lines(groupForm.elements.namedItem("protectedPaths").value)
  }, ruleBody(groupForm));
  try {
    await postJSON(editingGroup ? "/api/groups/update" : "/api/groups", body);
    resetGroupForm();
    await loadCatalog();
  } catch (err) {
    showError(groupError, err.message);
  }
});

document.querySelector("#group-clear").addEventListener("click", resetGroupForm);

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
    await loadCatalog();
  } catch (err) {
    showError(policyError, err.message);
  }
});

document.querySelector("#policy-clear").addEventListener("click", resetPolicyForm);

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
    await loadCatalog();
  } catch (err) {
    showError(formError, err.message);
  }
});

document.querySelector("#clear-form").addEventListener("click", resetForm);

function subject(rec) {
  if (rec.command) return rec.command;
  if (rec.src || rec.dst) return (rec.src || "") + " → " + (rec.dst || "");
  return "";
}

async function loadAudit(query) {
  showError(auditError, "");
  const data = await readJSON(await fetch("/api/audit" + (query || "")));
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
}

document.querySelector("#audit-filter").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const params = new URLSearchParams();
  for (const [k, v] of fd.entries()) {
    if (String(v).trim() !== "") params.set(k, String(v).trim());
  }
  const q = params.toString();
  try {
    await loadAudit(q ? "?" + q : "");
  } catch (err) {
    showError(auditError, err.message);
  }
});

loadCatalog().catch((err) => showError(catalogError, err.message));
loadAudit("").catch((err) => showError(auditError, err.message));

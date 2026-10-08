const hostsBody = document.querySelector("#hosts");
const auditBody = document.querySelector("#audit");
const groupSelect = document.querySelector("#group");
const form = document.querySelector("#host-form");
const formTitle = document.querySelector("#form-title");
const formError = document.querySelector("#form-error");
const catalogError = document.querySelector("#catalog-error");
const auditError = document.querySelector("#audit-error");
const envsBody = document.querySelector("#envs");
const groupsBody = document.querySelector("#groups");
const policiesBody = document.querySelector("#policies");
const knownBody = document.querySelector("#known");
const envForm = document.querySelector("#env-form");
const groupForm = document.querySelector("#group-form");
const policyForm = document.querySelector("#policy-form");
const groupEnvSelect = document.querySelector("#group-env");
let editing = false;
let editingEnv = false;
let editingGroup = false;
let editingPolicy = false;
let policyBuiltin = false;

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

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text == null || text === "" ? "" : String(text);
  return td;
}

function lines(value) {
  return String(value || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

function post(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

async function loadCatalog() {
  showError(catalogError, "");
  const data = await readJSON(await fetch("/api/catalog"));
  const envs = (data.envs || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  const groups = (data.groups || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  const hosts = (data.hosts || []).slice().sort((a, b) => a.alias.localeCompare(b.alias));
  const policies = (data.policies || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  renderEnvs(envs);
  renderGroups(groups);
  renderPolicies(policies);
  groupSelect.replaceChildren();
  groupEnvSelect.replaceChildren();
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.name;
    opt.textContent = g.name + " (" + g.env + ")";
    groupSelect.appendChild(opt);
  }
  for (const e of envs) {
    const opt = document.createElement("option");
    opt.value = e.name;
    opt.textContent = e.name;
    groupEnvSelect.appendChild(opt);
  }
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

function renderEnvs(envs) {
  envsBody.replaceChildren();
  for (const e of envs) {
    const tr = document.createElement("tr");
    tr.append(cell(e.name), cell(e.label), cell(e.color), cell(e.maxMode), cell(e.defaultPolicy), cell(e.noDataOutflow ? "yes" : ""));
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = "编辑";
    edit.addEventListener("click", () => fillEnv(e));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "删除";
    remove.addEventListener("click", () => removeNamed("/api/envs/remove", e.name, "env-error"));
    actions.append(edit, document.createTextNode(" "), remove);
    tr.append(actions);
    envsBody.appendChild(tr);
  }
}

function renderGroups(groups) {
  groupsBody.replaceChildren();
  for (const g of groups) {
    const tr = document.createElement("tr");
    tr.append(cell(g.name), cell(g.env), cell(g.policy), cell(g.hosts), cell((g.protectedPaths || []).join(",")));
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = "编辑";
    edit.addEventListener("click", () => fillGroup(g));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "删除";
    remove.addEventListener("click", () => removeNamed("/api/groups/remove", g.name, "group-error"));
    actions.append(edit, document.createTextNode(" "), remove);
    tr.append(actions);
    groupsBody.appendChild(tr);
  }
}

function renderPolicies(policies) {
  policiesBody.replaceChildren();
  for (const p of policies) {
    const tr = document.createElement("tr");
    tr.append(cell(p.name), cell(p.source), cell(p.mode), cell((p.deny || []).join(", ")), cell((p.confirm || []).join(", ")));
    const actions = document.createElement("td");
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "secondary";
    edit.textContent = "编辑";
    edit.addEventListener("click", () => fillPolicy(p));
    if (p.source !== "builtin") {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger";
      remove.textContent = "删除";
      remove.addEventListener("click", () => removeNamed("/api/policies/remove", p.name, "policy-error"));
      actions.append(edit, document.createTextNode(" "), remove);
    } else {
      actions.append(edit);
    }
    tr.append(actions);
    policiesBody.appendChild(tr);
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
  form.identity.value = h.identity || "";
  form.policy.value = h.policy || "";
  form.tags.value = (h.tags || []).join(",");
  form.setDefault.checked = !!h.default;
}

function resetForm() {
  editing = false;
  HTMLFormElement.prototype.reset.call(form);
  form.alias.readOnly = false;
  formTitle.textContent = "添加主机";
  showError(formError, "");
}

async function removeHost(alias) {
  if (!window.confirm("删除主机 " + alias + "？")) {
    return;
  }
  showError(catalogError, "");
  try {
    await readJSON(await post("/api/hosts/remove", { alias }));
    if (form.alias.value === alias) {
      resetForm();
    }
    await loadCatalog();
  } catch (err) {
    showError(catalogError, err.message);
  }
}

async function removeNamed(url, name, errorId) {
  if (!window.confirm("删除 " + name + "？")) {
    return;
  }
  const el = document.querySelector("#" + errorId);
  showError(el, "");
  try {
    await readJSON(await post(url, { name }));
    await loadCatalog();
  } catch (err) {
    showError(el, err.message);
  }
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError(formError, "");
  const body = {
    alias: form.alias.value.trim(),
    group: form.group.value,
    host: form.host.value.trim(),
    user: form.user.value.trim(),
    tags: lines(form.tags.value),
    setDefault: form.setDefault.checked
  };
  if (editing || form.policy.value.trim() !== "") {
    body.policy = form.policy.value.trim();
  }
  if (form.port.value !== "") {
    body.port = Number(form.port.value);
  }
  if (form.password.value !== "") {
    body.password = form.password.value;
  }
  if (form.identity.value.trim() !== "") {
    body.identity = form.identity.value.trim();
  }
  const url = editing ? "/api/hosts/update" : "/api/hosts";
  try {
    await readJSON(await post(url, body));
    form.password.value = "";
    resetForm();
    await loadCatalog();
  } catch (err) {
    showError(formError, err.message);
  }
});

document.querySelector("#clear-form").addEventListener("click", resetForm);

function fillEnv(e) {
  editingEnv = true;
  document.querySelector("#env-title").textContent = "编辑 " + e.name;
  envForm.name.value = e.name;
  envForm.name.readOnly = true;
  envForm.label.value = e.label || "";
  envForm.color.value = e.color || "";
  envForm.maxMode.value = e.maxMode;
  envForm.defaultPolicy.value = e.defaultPolicy || "";
  envForm.noDataOutflow.checked = !!e.noDataOutflow;
}

function resetEnv() {
  editingEnv = false;
  HTMLFormElement.prototype.reset.call(envForm);
  envForm.name.readOnly = false;
  document.querySelector("#env-title").textContent = "添加环境";
  showError(document.querySelector("#env-error"), "");
}

envForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const el = document.querySelector("#env-error");
  showError(el, "");
  const body = {
    name: envForm.name.value.trim(),
    label: envForm.label.value.trim(),
    color: envForm.color.value.trim(),
    maxMode: envForm.maxMode.value,
    defaultPolicy: envForm.defaultPolicy.value.trim(),
    noDataOutflow: envForm.noDataOutflow.checked
  };
  try {
    await readJSON(await post(editingEnv ? "/api/envs/update" : "/api/envs", body));
    resetEnv();
    await loadCatalog();
  } catch (err) {
    showError(el, err.message);
  }
});
document.querySelector("#env-clear").addEventListener("click", resetEnv);

function fillGroup(g) {
  editingGroup = true;
  document.querySelector("#group-title").textContent = "编辑 " + g.name;
  groupForm.name.value = g.name;
  groupForm.name.readOnly = true;
  groupForm.env.value = g.env;
  groupForm.policy.value = g.policy || "";
  groupForm.protectedPaths.value = (g.protectedPaths || []).join(",");
}

function resetGroup() {
  editingGroup = false;
  HTMLFormElement.prototype.reset.call(groupForm);
  groupForm.name.readOnly = false;
  document.querySelector("#group-title").textContent = "添加分组";
  showError(document.querySelector("#group-error"), "");
}

groupForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const el = document.querySelector("#group-error");
  showError(el, "");
  const body = {
    name: groupForm.name.value.trim(),
    env: groupForm.env.value,
    policy: groupForm.policy.value.trim(),
    protectedPaths: lines(groupForm.protectedPaths.value)
  };
  try {
    if (editingGroup) {
      const current = body.env;
      await readJSON(await post("/api/groups/update", body));
      const data = await readJSON(await fetch("/api/catalog"));
      const existing = (data.groups || []).find((g) => g.name === body.name);
      if (existing && existing.env !== current) {
        const moved = await readJSON(await post("/api/groups/set-env", { name: body.name, env: current }));
        resetGroup();
        await loadCatalog();
        if (moved.warning) {
          showError(el, moved.warning);
        }
        return;
      }
    } else {
      await readJSON(await post("/api/groups", body));
    }
    resetGroup();
    await loadCatalog();
  } catch (err) {
    showError(el, err.message);
  }
});
document.querySelector("#group-clear").addEventListener("click", resetGroup);

function fillPolicy(p) {
  editingPolicy = true;
  policyBuiltin = p.source === "builtin" || p.source === "override";
  document.querySelector("#policy-title").textContent = "编辑 " + p.name;
  policyForm.name.value = p.name;
  policyForm.name.readOnly = true;
  policyForm.mode.value = p.mode || "";
  policyForm.allow.value = (p.allow || []).join("\n");
  policyForm.allowEmpty.checked = !!p.allowEmpty;
  policyForm.deny.value = (p.deny || []).join("\n");
  policyForm.confirm.value = (p.confirm || []).join("\n");
  policyForm.protectedPaths.value = (p.protectedPaths || []).join(",");
  policyForm.upload.value = p.upload == null ? "" : String(p.upload);
  policyForm.download.value = p.download == null ? "" : String(p.download);
  policyForm.forward.value = p.forward == null ? "" : String(p.forward);
  policyForm.relay.value = p.relay || "";
  policyForm.service.value = (p.service || []).join(",");
}

function resetPolicy() {
  editingPolicy = false;
  policyBuiltin = false;
  HTMLFormElement.prototype.reset.call(policyForm);
  policyForm.name.readOnly = false;
  document.querySelector("#policy-title").textContent = "添加策略";
  showError(document.querySelector("#policy-error"), "");
}

policyForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const el = document.querySelector("#policy-error");
  showError(el, "");
  const body = {
    name: policyForm.name.value.trim(),
    mode: policyForm.mode.value,
    deny: lines(policyForm.deny.value),
    confirm: lines(policyForm.confirm.value),
    protectedPaths: lines(policyForm.protectedPaths.value)
  };
  if (policyForm.allowEmpty.checked) {
    body.allowEmpty = true;
  } else if (policyForm.allow.value.trim() !== "") {
    body.allow = lines(policyForm.allow.value);
  }
  if (policyForm.upload.value !== "") {
    body.upload = policyForm.upload.value === "true";
  }
  if (policyForm.download.value !== "") {
    body.download = policyForm.download.value === "true";
  }
  if (policyForm.forward.value !== "") {
    body.forward = policyForm.forward.value === "true";
  }
  if (policyForm.relay.value !== "") {
    body.relay = policyForm.relay.value;
  }
  if (policyForm.service.value.trim() !== "") {
    body.service = lines(policyForm.service.value);
  }
  const url = editingPolicy ? "/api/policies/update" : "/api/policies";
  try {
    await readJSON(await post(url, body));
    resetPolicy();
    await loadCatalog();
  } catch (err) {
    showError(el, err.message);
  }
});
document.querySelector("#policy-clear").addEventListener("click", resetPolicy);

async function loadKnown() {
  const el = document.querySelector("#known-error");
  showError(el, "");
  const data = await readJSON(await fetch("/api/known-hosts"));
  knownBody.replaceChildren();
  for (const entry of data.knownHosts || []) {
    const tr = document.createElement("tr");
    tr.append(cell(entry.marker), cell(entry.keyType), cell(entry.fingerprint), cell(entry.comment));
    const actions = document.createElement("td");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "删除";
    remove.addEventListener("click", async () => {
      if (!window.confirm("删除已知主机密钥 " + entry.marker + "？下次连接会重新记录第一把钥匙。")) {
        return;
      }
      try {
        await readJSON(await post("/api/known-hosts/remove", { marker: entry.marker }));
        await loadKnown();
      } catch (err) {
        showError(el, err.message);
      }
    });
    actions.append(remove);
    tr.append(actions);
    knownBody.appendChild(tr);
  }
}

function subject(rec) {
  if (rec.command) {
    return rec.command;
  }
  if (rec.src || rec.dst) {
    return (rec.src || "") + " → " + (rec.dst || "");
  }
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
    if (String(v).trim() !== "") {
      params.set(k, String(v).trim());
    }
  }
  const q = params.toString();
  try {
    await loadAudit(q ? "?" + q : "");
  } catch (err) {
    showError(auditError, err.message);
  }
});

loadCatalog().catch((err) => showError(catalogError, err.message));
loadKnown().catch((err) => showError(document.querySelector("#known-error"), err.message));
loadAudit("").catch((err) => showError(auditError, err.message));

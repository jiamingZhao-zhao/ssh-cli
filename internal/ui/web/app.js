const hostsBody = document.querySelector("#hosts");
const auditBody = document.querySelector("#audit");
const groupSelect = document.querySelector("#group");
const form = document.querySelector("#host-form");
const formTitle = document.querySelector("#form-title");
const formError = document.querySelector("#form-error");
const catalogError = document.querySelector("#catalog-error");
const auditError = document.querySelector("#audit-error");
let editing = false;

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

async function loadCatalog() {
  showError(catalogError, "");
  const data = await readJSON(await fetch("/api/catalog"));
  const groups = (data.groups || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  const hosts = (data.hosts || []).slice().sort((a, b) => a.alias.localeCompare(b.alias));
  groupSelect.replaceChildren();
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.name;
    opt.textContent = g.name + " (" + g.env + ")";
    groupSelect.appendChild(opt);
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
  form.policy.value = "";
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
    await readJSON(await fetch("/api/hosts/remove", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alias })
    }));
    if (form.alias.value === alias) {
      resetForm();
    }
    await loadCatalog();
  } catch (err) {
    showError(catalogError, err.message);
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
    tags: form.tags.value.split(",").map((s) => s.trim()).filter(Boolean),
    setDefault: form.setDefault.checked
  };
  if (form.policy.value.trim() !== "") {
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
    await readJSON(await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }));
    resetForm();
    await loadCatalog();
  } catch (err) {
    showError(formError, err.message);
  }
});

document.querySelector("#clear-form").addEventListener("click", resetForm);

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
loadAudit("").catch((err) => showError(auditError, err.message));

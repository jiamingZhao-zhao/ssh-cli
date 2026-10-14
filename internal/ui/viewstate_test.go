package ui

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPageStatusHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required to execute app.js status helpers")
	}
	script := `
const fs = require("fs");
const vm = require("vm");
const src = fs.readFileSync(process.argv[1], "utf8");
const cut = src.split("document.addEventListener")[0];
const sandbox = { TextEncoder };
vm.createContext(sandbox);
vm.runInContext(cut, sandbox, { filename: "app.js" });
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const first = sandbox.hmacView({}, { status: "ok" });
assert(first.status === "ok", "dashboard first load status " + JSON.stringify(first));
assert(first.className.indexOf("success") >= 0, "dashboard first load class " + first.className);
assert(first.text.indexOf("有效") >= 0, "dashboard first load text " + first.text);
assert(first.text.indexOf("还没有签名") < 0, "empty ops.hmac shadowed dash.hmac");

const valid = sandbox.hmacView({ status: "ok" }, { status: "mismatch" });
assert(valid.status === "ok" && valid.className.indexOf("success") >= 0 && valid.text.indexOf("有效") >= 0, "valid " + JSON.stringify(valid));

const missing = sandbox.hmacView({ status: "missing" }, { status: "ok" });
assert(missing.status === "missing" && missing.className.indexOf("danger") >= 0 && missing.text.indexOf("不在") >= 0, "missing " + JSON.stringify(missing));

const mismatch = sandbox.hmacView({ status: "mismatch", error: "digest" }, {});
assert(mismatch.status === "mismatch" && mismatch.className.indexOf("danger") >= 0, "mismatch class " + JSON.stringify(mismatch));
assert(mismatch.text.indexOf("不一致") >= 0 && mismatch.text.indexOf("digest") >= 0, "mismatch text " + mismatch.text);

const row = { alias: "box", ok: true, exitCode: 1, status: "error", stderr: "no" };
assert(sandbox.batchRowFailed(row), "non-zero exit still looks successful");
const summary = sandbox.batchSummary([
  row,
  { alias: "okbox", ok: true, exitCode: 0, status: "ok", stdout: "hi" }
]);
assert(summary.failed === 1 && summary.total === 2, "fail count " + JSON.stringify(summary));
assert(summary.text.indexOf("失败 1 / 2") >= 0, "summary " + summary.text);
assert(summary.text.indexOf("box 失败 exit 1") >= 0, "exit code " + summary.text);
assert(summary.text.indexOf("okbox ok exit 0") >= 0, "success row " + summary.text);
const denied = sandbox.batchSummary([{ alias: "no", ok: false, status: "denied", error: "blocked" }]);
assert(denied.failed === 1 && denied.text.indexOf("失败") >= 0, "denied " + denied.text);
`
	cmd := exec.Command(node, "-e", script, filepath.Join("web", "app.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

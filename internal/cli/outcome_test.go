package cli

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/sshtest"
)

func TestJSONExecutionOutcomes(t *testing.T) {
	ttyCheck = func() bool { return false }
	t.Cleanup(func() { ttyCheck = defaultTTY })
	srv, err := sshtest.Start("tester", "outcome-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	run := func(input string, args ...string) (int, string) {
		t.Helper()
		var out, errb strings.Builder
		code := Execute(append([]string{"--config", dir}, args...), strings.NewReader(input), &out, &errb)
		return code, out.String()
	}
	if code, _ := run("", "group", "add", "lab", "--env", "dev"); code != 0 {
		t.Fatal(code)
	}
	if code, _ := run("outcome-secret\n", "host", "add", "box", "--group", "lab", "--host", host, "--port", port, "--user", "tester", "--password-stdin"); code != 0 {
		t.Fatal(code)
	}
	for _, parallel := range []string{"1", "2"} {
		code, raw := run("", "--json", "exec", "-H", "box", "--parallel", parallel, "--", "sh -c 'exit 251'")
		var body struct {
			Results []struct {
				ExitCode  int    `json:"exitCode"`
				Status    string `json:"status"`
				Outcome   string `json:"outcome"`
				RetrySafe *bool  `json:"retrySafe"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatal(err, raw)
		}
		if code != 251 || len(body.Results) != 1 {
			t.Fatalf("exit %d: %s", code, raw)
		}
		row := body.Results[0]
		if row.Status != "error" || row.Outcome != "completed" || row.ExitCode != 251 || row.RetrySafe == nil || *row.RetrySafe {
			t.Fatalf("remote exit: %s", raw)
		}
	}
	srv.Close()
	_, raw := run("", "--json", "exec", "-H", "box", "--timeout", "400ms", "--", "echo once")
	var body struct {
		Results []execResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil || len(body.Results) != 1 {
		t.Fatalf("lost result: %s (%v)", raw, err)
	}
	if body.Results[0].Outcome != "unknown" || body.Results[0].Status != "connect" || body.Results[0].RetrySafe {
		t.Fatalf("transport error: %s", raw)
	}
}

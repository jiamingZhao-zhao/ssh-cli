package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestTerminalOutputWindow(t *testing.T) {
	f := newOutputWindow()
	if err := f.acquire(terminalOutputWindow); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1, terminalOutputWindow + 1} {
		if f.acknowledge(n) == nil {
			t.Fatalf("accepted invalid acknowledgement %d", n)
		}
	}
	wait := make(chan error, 1)
	go func() { wait <- f.acquire(1) }()
	select {
	case <-wait:
		t.Fatal("output exceeded its credit window")
	case <-time.After(30 * time.Millisecond):
	}
	if err := f.acknowledge(1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wait:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("credit did not resume output")
	}
	go func() { wait <- f.acquire(1) }()
	close(f.stop)
	select {
	case err := <-wait:
		if err == nil {
			t.Fatal("closed flow resumed")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock writer")
	}
	for _, raw := range []string{`{"type":"output_ack","bytes":6}`, `{"type":"output_ack","bytes":"bad"}`, `{"type":"output_ack"}`} {
		n, ok := parseOutputAck([]byte(raw))
		if !ok || (raw == `{"type":"output_ack","bytes":6}` && n != 6) {
			t.Fatalf("ack parsing %s", raw)
		}
	}
}

func TestTerminalOutputBackpressure(t *testing.T) {
	f := startTermFixture(t, true)
	_ = f.ws.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	op, payload, err := f.ws.ReadMessage()
	var ready map[string]string
	if err != nil || op != wsText || json.Unmarshal(payload, &ready) != nil || ready["category"] != "output_ack" {
		t.Fatalf("flow negotiation: %s %v", payload, err)
	}
	if err := f.ws.Write(wsBinary, []byte("yes x | head -c 1048576; printf '\\nFLOW-DONE\\n'\n")); err != nil {
		t.Fatal(err)
	}
	type frame struct {
		payload []byte
		err     error
	}
	frames := make(chan frame, 64)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			op, payload, err := f.ws.ReadMessage()
			if op == wsBinary || err != nil {
				select {
				case frames <- frame{payload, err}:
				case <-done:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	var all bytes.Buffer
	deadline := time.After(8 * time.Second)
	for all.Len() < terminalOutputWindow-(32<<10) {
		select {
		case frame := <-frames:
			if frame.err != nil {
				t.Fatal(frame.err)
			}
			all.Write(frame.payload)
		case <-deadline:
			t.Fatalf("producer did not fill window: %d", all.Len())
		}
	}
	// Give a fast producer time to send more. Without credit control this
	// reaches the end marker; with it, output stays within 256 KiB.
	pause := time.NewTimer(150 * time.Millisecond)
pauseLoop:
	for {
		select {
		case frame := <-frames:
			if frame.err != nil {
				t.Fatal(frame.err)
			}
			all.Write(frame.payload)
			if all.Len() > terminalOutputWindow {
				t.Fatalf("unbounded output: %d", all.Len())
			}
		case <-pause.C:
			break pauseLoop
		}
	}
	if err := f.ws.Write(wsBinary, []byte("printf 'INPUT-OK\\n'\n")); err != nil {
		t.Fatal(err)
	}
	ack := func(n int) {
		t.Helper()
		if err := f.ws.Write(wsText, []byte(fmt.Sprintf(`{"type":"output_ack","bytes":%d}`, n))); err != nil {
			t.Fatal(err)
		}
	}
	ack(all.Len())
	for !bytes.Contains(all.Bytes(), []byte("INPUT-OK")) {
		select {
		case frame := <-frames:
			if frame.err != nil {
				t.Fatal(frame.err)
			}
			all.Write(frame.payload)
			ack(len(frame.payload))
		case <-deadline:
			t.Fatalf("output did not resume: %d bytes", all.Len())
		}
	}
	want := append(bytes.Repeat([]byte("x\n"), 1048576/2), []byte("\nFLOW-DONE\nINPUT-OK\n")...)
	if !bytes.Equal(all.Bytes(), want) {
		t.Fatalf("output lost or reordered: got %d want %d bytes", all.Len(), len(want))
	}
	// Closing SSH while the consumer withholds credit must close the socket,
	// not leave a bridge waiting forever on output acknowledgements.
	if err := f.ws.Write(wsBinary, []byte("yes x | head -c 1048576\n")); err != nil {
		t.Fatal(err)
	}
	paused := 0
	for paused < terminalOutputWindow-(32<<10) {
		select {
		case frame := <-frames:
			if frame.err != nil {
				t.Fatal(frame.err)
			}
			paused += len(frame.payload)
		case <-deadline:
			t.Fatal("second output did not fill window")
		}
	}
	res := f.post(t, "/api/sessions/close", `{"alias":"box"}`, false)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("close SSH: %d %s", res.StatusCode, raw)
	}
	closed := time.After(3 * time.Second)
	for {
		select {
		case frame := <-frames:
			if frame.err != nil {
				return
			}
		case <-closed:
			t.Fatal("closed SSH left a stalled output bridge")
		}
	}
}

func TestTerminalOutputExitDrains(t *testing.T) {
	f := startTermFixture(t, true)
	_ = f.ws.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	op, ready, err := f.ws.ReadMessage()
	if err != nil || op != wsText || !bytes.Contains(ready, []byte("output_ack")) {
		t.Fatalf("ready %s %v", ready, err)
	}
	if err := f.ws.Write(wsBinary, []byte("yes x | head -c 1048576; printf '\\nEXIT-DONE\\n'; exit\n")); err != nil {
		t.Fatal(err)
	}
	var all bytes.Buffer
	for !bytes.Contains(all.Bytes(), []byte("EXIT-DONE")) {
		op, payload, err := f.ws.ReadMessage()
		if op == wsBinary {
			all.Write(payload)
			ackErr := f.ws.Write(wsText, []byte(fmt.Sprintf(`{"type":"output_ack","bytes":%d}`, len(payload))))
			if ackErr != nil && !bytes.Contains(all.Bytes(), []byte("EXIT-DONE")) {
				t.Fatal(ackErr)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	want := append(bytes.Repeat([]byte("x\n"), 1048576/2), []byte("\nEXIT-DONE\n")...)
	if !bytes.Equal(all.Bytes(), want) {
		t.Fatalf("normal exit lost output: got %d want %d bytes", all.Len(), len(want))
	}
}

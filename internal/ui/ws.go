package ui

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	wsText   = 0x1
	wsBinary = 0x2
	wsClose  = 0x8
	wsPing   = 0x9
	wsPong   = 0xA
	wsMax    = 1 << 20
	wsGUID   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var errUpgrade = errors.New("websocket upgrade failed")

// wsConn is a small RFC 6455 peer. Server connections require masked client
// frames. The test client sets writeMask.
type wsConn struct {
	c         net.Conn
	r         *bufio.Reader
	w         *bufio.Writer
	mu        sync.Mutex
	writeMask bool
	readMask  bool
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !headerHasToken(r.Header, "Connection", "upgrade") || !headerHasToken(r.Header, "Upgrade", "websocket") {
		return nil, errUpgrade
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errUpgrade
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, errUpgrade
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errUpgrade
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := wsAccept(key)
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &wsConn{c: conn, r: rw.Reader, w: rw.Writer, readMask: true}, nil
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, part := range strings.Split(h.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.c == nil {
		return io.ErrClosedPipe
	}
	return c.c.SetReadDeadline(t)
}

func (c *wsConn) ReadMessage() (byte, []byte, error) {
	var acc []byte
	var op byte
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case wsPing:
			if err := c.Write(wsPong, payload); err != nil {
				return 0, nil, err
			}
			continue
		case wsPong:
			continue
		case wsClose:
			_ = c.Write(wsClose, nil)
			return 0, nil, io.EOF
		case 0x0:
			acc = append(acc, payload...)
		case wsText, wsBinary:
			op = opcode
			acc = append(acc[:0], payload...)
		default:
			return 0, nil, fmt.Errorf("websocket opcode %d", opcode)
		}
		if len(acc) > wsMax {
			return 0, nil, fmt.Errorf("websocket message too large")
		}
		if fin {
			if op == 0 {
				return 0, nil, fmt.Errorf("websocket empty fragment")
			}
			return op, append([]byte(nil), acc...), nil
		}
	}
}

func (c *wsConn) readFrame() (bool, byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.r, hdr); err != nil {
		return false, 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	op := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	if c.readMask && !masked {
		return false, 0, nil, fmt.Errorf("websocket client frame is not masked")
	}
	if !c.readMask && masked {
		return false, 0, nil, fmt.Errorf("websocket server frame is masked")
	}
	n := int(hdr[1] & 0x7f)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.r, ext); err != nil {
			return false, 0, nil, err
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.r, ext); err != nil {
			return false, 0, nil, err
		}
		if ext[0]|ext[1]|ext[2]|ext[3] != 0 {
			return false, 0, nil, fmt.Errorf("websocket frame too large")
		}
		n = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}
	if n < 0 || n > wsMax {
		return false, 0, nil, fmt.Errorf("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.r, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, op, payload, nil
}

func (c *wsConn) Write(op byte, p []byte) error {
	if c == nil {
		return io.ErrClosedPipe
	}
	if len(p) > wsMax {
		return fmt.Errorf("websocket message too large")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	hdr := []byte{0x80 | op}
	n := len(p)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 65535:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	var mask [4]byte
	if c.writeMask {
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		hdr[1] |= 0x80
		hdr = append(hdr, mask[:]...)
		p = append([]byte(nil), p...)
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	if _, err := c.w.Write(hdr); err != nil {
		return err
	}
	if _, err := c.w.Write(p); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *wsConn) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	_ = c.Write(wsClose, nil)
	return c.c.Close()
}

// dialWebSocket is the test client. rawURL is http(s) or ws(s).
func dialWebSocket(rawURL string, header http.Header) (*wsConn, error) {
	u, err := parseWSURL(rawURL)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])
	var b strings.Builder
	b.WriteString("GET " + u.RequestURI() + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, vals := range header {
		for _, v := range vals {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake %s", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &wsConn{c: conn, r: br, w: bufio.NewWriter(conn), writeMask: true}, nil
}

func parseWSURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Replace(raw, "ws://", "http://", 1)
	raw = strings.Replace(raw, "wss://", "https://", 1)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid websocket url")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

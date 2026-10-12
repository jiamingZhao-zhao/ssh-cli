package transfer

import (
	"fmt"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	// sshChannelWindow is the default SSH channel window used by
	// golang.org/x/crypto/ssh and OpenSSH (64 * 32KiB).
	sshChannelWindow = 64 * 32 * 1024
	// sftpDataOverhead is the bytes around one SSH_FXP_DATA payload that still
	// consume window: packet length, type, request id, and data length.
	sftpDataOverhead = 4 + 1 + 4 + 4
	sftpMaxPacket    = 32 * 1024
)

// safeConcurrentRequests keeps in-flight DATA packets under the channel
// window with room left for window-adjust. The sftp default of 64 fills a
// 2MiB window (64 * (32KiB + framing) exceeds 2MiB) and can stall or reset a
// connection once RTT lets the pipeline fill. Small files never take that
// path, which is why a few-kilobyte download succeeds while a ~100MB file
// reports "connection lost" and drops other channels on the same client.
func safeConcurrentRequests() int {
	n := sshChannelWindow / (sftpMaxPacket + sftpDataOverhead)
	if n > 2 {
		n -= 2
	}
	if n < 1 {
		n = 1
	}
	return n
}

// Client opens an SFTP session whose per-file pipeline fits the SSH window.
// Upload, download, list, and relay share this so CLI and UI behave the same.
func Client(raw *ssh.Client) (*sftp.Client, error) {
	if raw == nil {
		return nil, fmt.Errorf("ssh client is nil")
	}
	return sftp.NewClient(raw,
		sftp.MaxPacket(sftpMaxPacket),
		sftp.MaxConcurrentRequestsPerFile(safeConcurrentRequests()),
	)
}

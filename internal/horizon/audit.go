package horizon

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

const AuditVersion = "horizon.nyxr.io/audit/v1"

// AuditEntry is one line of the append-only audit trail. Each entry hashes
// its predecessor, so an edit, reorder or deletion breaks the chain. The chain
// detects tampering by anyone who cannot recompute it; it is not a signature.
type AuditEntry struct {
	Version        string    `json:"version"`
	Seq            uint64    `json:"seq"`
	Time           time.Time `json:"time"`
	Actor          string    `json:"actor"`
	Action         string    `json:"action"` // run.create, run.finish, run.cancel, resolve, kill-switch, denied
	RunID          string    `json:"runId,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	ExperimentHash string    `json:"experimentHash,omitempty"`
	Target         string    `json:"target,omitempty"`
	Ports          []uint16  `json:"ports,omitempty"`
	Outcome        string    `json:"outcome"`
	Detail         string    `json:"detail,omitempty"`
	Prev           string    `json:"prev"`
	Hash           string    `json:"hash"`
}

const maxAuditLine = 64 << 10

func auditHash(e AuditEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Audit appends hash-chained entries to a private file and syncs each one.
type Audit struct {
	mu     sync.Mutex
	file   *os.File
	seq    uint64
	prev   string
	now    func() time.Time
	failed error // a failed write may leave a partial line: refuse all later writes
}

// ErrAuditUnavailable is what callers show clients; details stay server-side.
var ErrAuditUnavailable = errors.New("audit trail unavailable")

// OpenAudit opens or creates an audit file, verifying any existing chain
// before appending. A broken chain or a group/world-writable file is refused.
func OpenAudit(path string) (*Audit, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		err = fmt.Errorf("audit file %s is group or world writable", path)
	}
	var seq uint64
	var prev string
	if err == nil {
		if _, err = f.Seek(0, io.SeekStart); err == nil {
			seq, prev, err = verifyAudit(f)
		}
	}
	if err == nil {
		// One writer per file: a second process would fork the chain.
		err = lockAudit(f)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Audit{file: f, seq: seq, prev: prev, now: time.Now}, nil
}

// VerifyAudit checks every entry and the chain, returning the entry count.
func VerifyAudit(r io.Reader) (uint64, error) {
	n, _, err := verifyAudit(r)
	return n, err
}

func verifyAudit(r io.Reader) (uint64, string, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxAuditLine)
	var seq uint64
	prev := ""
	for s.Scan() {
		var e AuditEntry
		d := json.NewDecoder(bytes.NewReader(s.Bytes()))
		d.DisallowUnknownFields()
		if err := d.Decode(&e); err != nil {
			return seq, prev, fmt.Errorf("audit entry %d: %w", seq+1, err)
		}
		if e.Version != AuditVersion || e.Seq != seq+1 || e.Prev != prev || e.Hash != auditHash(e) {
			return seq, prev, fmt.Errorf("audit chain broken at entry %d", seq+1)
		}
		seq, prev = e.Seq, e.Hash
	}
	if err := s.Err(); err != nil {
		return seq, prev, fmt.Errorf("audit entry %d: %w", seq+1, err)
	}
	return seq, prev, nil
}

// Record appends one entry. Callers that start traffic must fail closed when
// it returns an error.
func (a *Audit) Record(e AuditEntry) error {
	if a == nil {
		return errors.New("no audit trail is configured")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return errors.New("audit trail is closed")
	}
	if a.failed != nil {
		return fmt.Errorf("audit trail failed earlier: %w", a.failed)
	}
	e.Version, e.Seq, e.Time, e.Prev = AuditVersion, a.seq+1, a.now().UTC(), a.prev
	e.Hash = auditHash(e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) >= maxAuditLine {
		return errors.New("audit entry too large")
	}
	if _, err := a.file.Write(append(b, '\n')); err != nil {
		a.failed = err
		return err
	}
	if err := a.file.Sync(); err != nil {
		a.failed = err
		return err
	}
	a.seq, a.prev = e.Seq, e.Hash
	return nil
}

func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}

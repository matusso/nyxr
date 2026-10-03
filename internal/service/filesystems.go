package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// This file identifies network file systems and the storage services that
// front them: NFS and the ONC RPC portmapper, plus a passive matcher for the
// Ceph messenger banner. Object storage (MinIO, Ceph RADOS Gateway and other
// S3-compatible endpoints) speaks HTTP and is identified by the HTTP probe.
// Every exchange here is an unauthenticated, read-only RPC NULL or dump.

// Well-known ONC RPC program numbers, for naming a portmapper dump.
var rpcPrograms = map[uint32]string{
	100000: "rpcbind", 100003: "nfs", 100005: "mountd", 100021: "nlockmgr",
	100024: "status", 100227: "nfs_acl", 100011: "rquotad", 100001: "rstatd",
	100002: "rusersd", 100007: "ypbind", 150001: "pcnfsd",
}

// rpcCall builds an ONC RPC v2 call with null authentication.
func rpcCall(xid, prog, vers, proc uint32, args []byte) []byte {
	b := make([]byte, 0, 40+len(args))
	put := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	put(xid)
	put(0) // msg_type: CALL
	put(2) // rpcvers
	put(prog)
	put(vers)
	put(proc)
	put(0)
	put(0) // cred: AUTH_NONE, length 0
	put(0)
	put(0) // verf: AUTH_NONE, length 0
	return append(b, args...)
}

// rpcExchange sends one record-marked RPC call and reads the reassembled reply.
func rpcExchange(c net.Conn, msg []byte) ([]byte, error) {
	frame := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(frame[:4], 0x80000000|uint32(len(msg))) // last fragment
	copy(frame[4:], msg)
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}
	var out []byte
	for {
		var h [4]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return out, err
		}
		mark := binary.BigEndian.Uint32(h[:])
		n := int(mark & 0x7fffffff)
		if n < 0 || len(out)+n > 0x20000 {
			return out, fmt.Errorf("invalid RPC fragment length %d", n)
		}
		frag := make([]byte, n)
		if _, err := io.ReadFull(c, frag); err != nil {
			return out, err
		}
		out = append(out, frag...)
		if mark&0x80000000 != 0 { // last fragment
			return out, nil
		}
	}
}

// rpcAcceptedBody validates an RPC reply for xid and returns the accept status
// and the bytes after it. ok is false when the message is not an RPC reply.
func rpcAcceptedBody(xid uint32, resp []byte) (acceptStat uint32, body []byte, ok bool) {
	if len(resp) < 12 || binary.BigEndian.Uint32(resp[0:4]) != xid || binary.BigEndian.Uint32(resp[4:8]) != 1 {
		return 0, nil, false // not a REPLY to our xid
	}
	if binary.BigEndian.Uint32(resp[8:12]) != 0 {
		return 0, nil, true // MSG_DENIED: still a valid RPC responder
	}
	p := 12
	if len(resp) < p+8 {
		return 0, nil, false
	}
	vlen := int(binary.BigEndian.Uint32(resp[p+4 : p+8]))
	p += 8 + vlen
	if vlen < 0 || len(resp) < p+4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(resp[p : p+4]), resp[p+4:], true
}

// probeNFS identifies NFS on 2049 with an RPC NULL, and on the portmapper
// (111) dumps the registered programs, which reveals the whole NFS stack.
func (e *Engine) probeNFS(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeNFS, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeNFS
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeNFS)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	var xidb [4]byte
	_, _ = rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])

	if t.Port == 111 {
		ok := e.rpcbindDump(rc, xid, o)
		e.finish(&ev, rc, nil)
		matched = ok
		return ok
	}
	// NFS: a NULL call that is accepted (or version-mismatched) proves NFS.
	resp, err := rpcExchange(rc, rpcCall(xid, 100003, 3, 0, nil))
	e.finish(&ev, rc, err)
	if err != nil {
		return false
	}
	stat, body, ok := rpcAcceptedBody(xid, resp)
	if !ok {
		return false
	}
	o.Service, o.Confidence, o.Probe = "nfs", 100, ProbeNFS
	switch stat {
	case 0: // SUCCESS
		o.Reason = "RPC NULL accepted by the NFS program"
		addAttr(o, "nfs.versions", "3")
	case 2: // PROG_MISMATCH: body carries the supported [low, high] versions
		o.Reason = "NFS program present (version mismatch on the NULL probe)"
		if len(body) >= 8 {
			lo := binary.BigEndian.Uint32(body[0:4])
			hi := binary.BigEndian.Uint32(body[4:8])
			addAttr(o, "nfs.versions", versionRange(lo, hi))
		}
	default: // PROG_UNAVAIL and friends: the responder is RPC but not NFS here
		o.Service, o.Probe = "rpc", ProbeNFS
		o.Reason = "ONC RPC responder (NFS program unavailable)"
	}
	matched = true
	return true
}

func (e *Engine) rpcbindDump(rc net.Conn, xid uint32, o *observe.Observation) bool {
	resp, err := rpcExchange(rc, rpcCall(xid, 100000, 2, 4, nil)) // PMAPPROC_DUMP
	if err != nil {
		return false
	}
	_, body, ok := rpcAcceptedBody(xid, resp)
	if !ok {
		return false
	}
	o.Service, o.Confidence, o.Probe = "rpcbind", 100, ProbeNFS
	o.Reason = "ONC RPC portmapper dump"
	progs := map[uint32]bool{}
	for i := 0; i < 256 && len(body) >= 4; i++ {
		if binary.BigEndian.Uint32(body[0:4]) == 0 { // value_follows: end of list
			break
		}
		if len(body) < 20 {
			break
		}
		progs[binary.BigEndian.Uint32(body[4:8])] = true
		body = body[20:] // follows(4) + prog, vers, prot, port (4 each)
	}
	var names []string
	for p := range progs {
		if name := rpcPrograms[p]; name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > 0 {
		addAttr(o, "rpc.programs", strings.Join(names, ", "))
	}
	if progs[100003] {
		o.Service, o.Product = "nfs", "NFS"
		o.Reason = "NFS registered with the ONC RPC portmapper"
	}
	return true
}

func versionRange(lo, hi uint32) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	var vs []string
	for v := lo; v <= hi && v-lo < 16; v++ {
		vs = append(vs, fmt.Sprint(v))
	}
	return strings.Join(vs, ",")
}

// matchCephBanner recognizes the Ceph messenger banner, which a monitor or OSD
// sends on connect. Both the v1 ("ceph v027\n") and v2 ("ceph v2\n...") banners
// begin with "ceph v".
func matchCephBanner(o *observe.Observation, banner []byte) bool {
	if !bytes.HasPrefix(banner, []byte("ceph v")) {
		return false
	}
	line, _, _ := bytes.Cut(banner, []byte("\n"))
	o.Service, o.Confidence, o.Reason = "ceph", 100, "Ceph messenger banner"
	o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
	o.Attributes = map[string]string{"ceph.banner": printable(line, 64)}
	return true
}

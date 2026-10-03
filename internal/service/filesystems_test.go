package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

// readRPCCall reads one record-marked RPC call and returns its xid.
func readRPCCall(t *testing.T, c net.Conn) uint32 {
	t.Helper()
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0
	}
	n := int(binary.BigEndian.Uint32(h[:]) & 0x7fffffff)
	call := make([]byte, n)
	if _, err := io.ReadFull(c, call); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(call[0:4])
}

func writeRPCReply(c net.Conn, body []byte) {
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], 0x80000000|uint32(len(body)))
	copy(frame[4:], body)
	_, _ = c.Write(frame)
}

func rpcAcceptReply(xid, acceptStat uint32, extra []byte) []byte {
	b := make([]byte, 0, 24)
	put := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	put(xid)
	put(1) // REPLY
	put(0) // MSG_ACCEPTED
	put(0)
	put(0) // verf AUTH_NONE
	put(acceptStat)
	return append(b, extra...)
}

func TestNFSNullIdentifiesNFS(t *testing.T) {
	e := identityEngine(t, ProbeNFS, func(c net.Conn) {
		xid := readRPCCall(t, c)
		writeRPCReply(c, rpcAcceptReply(xid, 0, nil)) // SUCCESS
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 2049})
	if o.Service != "nfs" || o.Attributes["nfs.versions"] != "3" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("nfs null: %+v", o)
	}
	if o.Evidence[0].Matched != ProbeNFS || len(o.Evidence[0].Request) == 0 {
		t.Fatalf("evidence: %+v", o.Evidence)
	}
}

func TestRpcbindDumpEnumeratesPrograms(t *testing.T) {
	entry := func(prog uint32) []byte {
		b := binary.BigEndian.AppendUint32(nil, 1) // value_follows
		b = binary.BigEndian.AppendUint32(b, prog)
		b = binary.BigEndian.AppendUint32(b, 3)    // vers
		b = binary.BigEndian.AppendUint32(b, 6)    // prot TCP
		b = binary.BigEndian.AppendUint32(b, 2049) // port
		return b
	}
	list := append(append(entry(100003), entry(100005)...), binary.BigEndian.AppendUint32(nil, 0)...)
	e := identityEngine(t, ProbeNFS, func(c net.Conn) {
		xid := readRPCCall(t, c)
		writeRPCReply(c, rpcAcceptReply(xid, 0, list))
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 111})
	if o.Service != "nfs" || o.Attributes["rpc.programs"] != "mountd, nfs" {
		t.Fatalf("rpcbind dump: %+v", o)
	}
}

func TestCephBanner(t *testing.T) {
	e := identityEngine(t, ProbeBanner, func(c net.Conn) {
		_, _ = c.Write([]byte("ceph v027\n\x00\x00\x00"))
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 6789})
	if o.Service != "ceph" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("ceph: %+v", o)
	}
	if o.Attributes["ceph.banner"] != "ceph v027" {
		t.Errorf("ceph.banner = %q", o.Attributes["ceph.banner"])
	}
}

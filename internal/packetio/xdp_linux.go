//go:build linux

package packetio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	xdpRingSize  = 1024
	xdpFrameSize = 4096
	xdpRXFrames  = xdpRingSize
	xdpTXFrames  = xdpRingSize
	// A jumbo Ethernet frame needs the portable backend. This backend uses
	// one descriptor per frame, so it never silently truncates a transmit.
	xdpMaxFrame = xdpFrameSize
)

type xdpRing struct {
	mem      []byte
	producer *uint32
	consumer *uint32
	flags    *uint32
	desc     unsafe.Pointer
	size     uint32
}

func (r *xdpRing) available() uint32 {
	return atomic.LoadUint32(r.producer) - atomic.LoadUint32(r.consumer)
}

func (r *xdpRing) free() uint32 { return r.size - r.available() }

func (r *xdpRing) address(i uint32) *uint64 {
	return (*uint64)(unsafe.Add(r.desc, uintptr(i%r.size)*8))
}

func (r *xdpRing) packet(i uint32) *unix.XDPDesc {
	return (*unix.XDPDesc)(unsafe.Add(r.desc, uintptr(i%r.size)*unsafe.Sizeof(unix.XDPDesc{})))
}

func mmapXDPRing(fd int, offset int64, layout unix.XDPRingOffset, size, entrySize uint32) (xdpRing, error) {
	length := int(layout.Desc) + int(size*entrySize)
	mem, err := unix.Mmap(fd, offset, length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return xdpRing{}, err
	}
	if int(layout.Producer)+4 > len(mem) || int(layout.Consumer)+4 > len(mem) || int(layout.Flags)+4 > len(mem) {
		_ = unix.Munmap(mem)
		return xdpRing{}, errors.New("invalid AF_XDP ring offsets")
	}
	return xdpRing{mem: mem, producer: (*uint32)(unsafe.Pointer(&mem[layout.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&mem[layout.Consumer])),
		flags:    (*uint32)(unsafe.Pointer(&mem[layout.Flags])),
		desc:     unsafe.Pointer(&mem[layout.Desc]), size: size}, nil
}

type xdpSocket struct {
	fd             int
	queue          uint32
	umem           []byte
	rx, tx         xdpRing
	fill           xdpRing
	complete       xdpRing
	freeTX         [xdpTXFrames]uint64
	freeN          int
	received, sent atomic.Uint64
}

func setXDPSockopt(fd, opt int, value unsafe.Pointer, size uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), unix.SOL_XDP, uintptr(opt), uintptr(value), size, 0)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}

func xdpOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var v unix.XDPMmapOffsets
	n := uint32(unsafe.Sizeof(v))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return v, errno
	}
	if n < uint32(unsafe.Sizeof(v)) {
		return v, errors.New("short AF_XDP mmap offsets")
	}
	return v, nil
}

func openXDPSocket(ifindex int, queue uint32) (s *xdpSocket, err error) {
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	s = &xdpSocket{fd: fd, queue: queue}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.umem, err = unix.Mmap(-1, 0, (xdpRXFrames+xdpTXFrames)*xdpFrameSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, err
	}
	reg := unix.XDPUmemReg{Addr: uint64(uintptr(unsafe.Pointer(&s.umem[0]))), Len: uint64(len(s.umem)), Size: xdpFrameSize}
	if err = setXDPSockopt(fd, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err != nil {
		return nil, err
	}
	n := uint32(xdpRingSize)
	for _, opt := range []int{unix.XDP_UMEM_FILL_RING, unix.XDP_UMEM_COMPLETION_RING, unix.XDP_RX_RING, unix.XDP_TX_RING} {
		if err = setXDPSockopt(fd, opt, unsafe.Pointer(&n), unsafe.Sizeof(n)); err != nil {
			return nil, err
		}
	}
	var offsets unix.XDPMmapOffsets
	if offsets, err = xdpOffsets(fd); err != nil {
		return nil, err
	}
	if s.fill, err = mmapXDPRing(fd, unix.XDP_UMEM_PGOFF_FILL_RING, offsets.Fr, xdpRingSize, 8); err != nil {
		return nil, err
	}
	if s.complete, err = mmapXDPRing(fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, offsets.Cr, xdpRingSize, 8); err != nil {
		return nil, err
	}
	if s.rx, err = mmapXDPRing(fd, unix.XDP_PGOFF_RX_RING, offsets.Rx, xdpRingSize, uint32(unsafe.Sizeof(unix.XDPDesc{}))); err != nil {
		return nil, err
	}
	if s.tx, err = mmapXDPRing(fd, unix.XDP_PGOFF_TX_RING, offsets.Tx, xdpRingSize, uint32(unsafe.Sizeof(unix.XDPDesc{}))); err != nil {
		return nil, err
	}
	for i := uint32(0); i < xdpRXFrames; i++ {
		*s.fill.address(i) = uint64(i) * xdpFrameSize
	}
	atomic.StoreUint32(s.fill.producer, xdpRXFrames)
	for i := 0; i < xdpTXFrames; i++ {
		s.freeTX[i] = uint64(xdpRXFrames+i) * xdpFrameSize
	}
	s.freeN = xdpTXFrames
	if err = unix.Bind(fd, &unix.SockaddrXDP{Ifindex: uint32(ifindex), QueueID: queue, Flags: unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *xdpSocket) close() error {
	for _, r := range []xdpRing{s.rx, s.tx, s.fill, s.complete} {
		if r.mem != nil {
			_ = unix.Munmap(r.mem)
		}
	}
	if s.umem != nil {
		_ = unix.Munmap(s.umem)
	}
	return unix.Close(s.fd)
}

func (s *xdpSocket) receive(buffers [][]byte) (int, error) {
	available := min(int(s.rx.available()), len(buffers))
	cons := atomic.LoadUint32(s.rx.consumer)
	fillProd := atomic.LoadUint32(s.fill.producer)
	n := 0
	for n < available && s.fill.free() > uint32(n) {
		d := *s.rx.packet(cons + uint32(n))
		if d.Options != 0 || d.Addr >= uint64(len(s.umem)) ||
			uint64(d.Len) > uint64(len(s.umem))-d.Addr ||
			(d.Addr%xdpFrameSize)+uint64(d.Len) > xdpFrameSize {
			return 0, errors.New("invalid AF_XDP RX descriptor")
		}
		if int(d.Len) > len(buffers[n]) {
			return 0, errors.New("AF_XDP receive buffer is too small")
		}
		copy(buffers[n], s.umem[int(d.Addr):int(d.Addr)+int(d.Len)])
		buffers[n] = buffers[n][:min(len(buffers[n]), int(d.Len))]
		*s.fill.address(fillProd + uint32(n)) = d.Addr &^ (xdpFrameSize - 1)
		n++
	}
	if n != 0 {
		atomic.StoreUint32(s.rx.consumer, cons+uint32(n))
		atomic.StoreUint32(s.fill.producer, fillProd+uint32(n))
		s.received.Add(uint64(n))
	}
	return n, nil
}

func (s *xdpSocket) reclaim() {
	cons := atomic.LoadUint32(s.complete.consumer)
	n := s.complete.available()
	for i := uint32(0); i < n; i++ {
		addr := *s.complete.address(cons + i)
		if addr >= uint64(xdpRXFrames*xdpFrameSize) && addr < uint64(len(s.umem)) && addr%xdpFrameSize == 0 && s.freeN < len(s.freeTX) {
			s.freeTX[s.freeN] = addr
			s.freeN++
		}
	}
	atomic.StoreUint32(s.complete.consumer, cons+n)
}

func (s *xdpSocket) transmit(frames [][]byte) int {
	s.reclaim()
	n := min(len(frames), int(s.tx.free()), s.freeN)
	prod := atomic.LoadUint32(s.tx.producer)
	for i := 0; i < n; i++ {
		s.freeN--
		addr := s.freeTX[s.freeN]
		copy(s.umem[int(addr):int(addr)+len(frames[i])], frames[i])
		*s.tx.packet(prod + uint32(i)) = unix.XDPDesc{Addr: addr, Len: uint32(len(frames[i]))}
	}
	if n != 0 {
		atomic.StoreUint32(s.tx.producer, prod+uint32(n))
		s.sent.Add(uint64(n))
		_ = unix.Sendto(s.fd, nil, unix.MSG_DONTWAIT, nil)
	}
	return n
}

type xdpLive struct {
	sockets         []*xdpSocket
	mapFD, configFD int
	queueIDs        []uint32
	lock            *os.File
	pollFDs         []unix.PollFd
	next            int
	closed          atomic.Bool
}

// OpenXDP opens AF_XDP copy-mode sockets for every RX queue. The pinned maps
// must belong to the Nyxr XDP program in tools/xdp; the program redirects only
// replies for the configured IPv4 SYN source, and passes all other traffic.
// The caller must call SetSYNFilter before sending probes.
func OpenXDP(device, pinDir string, source net.IP) (PacketIO, error) {
	if source.To4() == nil {
		return nil, errors.New("AF_XDP SYN source must be IPv4")
	}
	resolvedDir, err := filepath.EvalSymlinks(pinDir)
	if err != nil {
		return nil, fmt.Errorf("AF_XDP pin directory: %w", err)
	}
	pinDir, err = filepath.Abs(resolvedDir)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	queues, err := xdpQueues(device)
	if err != nil {
		return nil, err
	}
	for _, q := range queues {
		if q >= 128 {
			return nil, fmt.Errorf("AF_XDP RX queue %d exceeds the Nyxr map capacity (128)", q)
		}
	}
	// A pinned map set belongs to one active scan. Keep this lock until Close.
	h := fnv.New64a()
	_, _ = h.Write([]byte(pinDir))
	lock, err := os.OpenFile(filepath.Join(os.TempDir(), fmt.Sprintf("nyxr-xdp-%x.lock", h.Sum64())), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("AF_XDP maps are in use: %w", err)
	}
	mfd, err := bpfObjectGet(filepath.Join(pinDir, "xsks"))
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("open pinned XSK map: %w", err)
	}
	cfd, err := bpfObjectGet(filepath.Join(pinDir, "filter"))
	if err != nil {
		_ = unix.Close(mfd)
		_ = lock.Close()
		return nil, fmt.Errorf("open pinned filter map: %w", err)
	}
	l := &xdpLive{mapFD: mfd, configFD: cfd, lock: lock}
	ok := false
	defer func() {
		if !ok {
			_ = l.Close()
		}
	}()
	// Disable a stale filter before new sockets become visible to the program.
	var key uint32
	var filter [8]byte
	copy(filter[:4], source.To4())
	if err = bpfMapUpdate(cfd, unsafe.Pointer(&key), unsafe.Pointer(&filter[0])); err != nil {
		return nil, err
	}
	for _, q := range queues {
		var s *xdpSocket
		s, err = openXDPSocket(iface.Index, q)
		if err != nil {
			return nil, fmt.Errorf("AF_XDP queue %d: %w", q, err)
		}
		l.sockets = append(l.sockets, s)
		l.pollFDs = append(l.pollFDs, unix.PollFd{Fd: int32(s.fd), Events: unix.POLLIN})
		socketFD := uint32(s.fd)
		if err = bpfMapUpdate(mfd, unsafe.Pointer(&q), unsafe.Pointer(&socketFD)); err != nil {
			return nil, fmt.Errorf("register AF_XDP queue %d: %w", q, err)
		}
		l.queueIDs = append(l.queueIDs, q)
	}
	ok = true
	return l, nil
}

func xdpQueues(device string) ([]uint32, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", device, "queues"))
	if err != nil {
		return nil, err
	}
	var queues []uint32
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "rx-") {
			continue
		}
		n, e := strconv.ParseUint(strings.TrimPrefix(e.Name(), "rx-"), 10, 32)
		if e == nil {
			queues = append(queues, uint32(n))
		}
	}
	if len(queues) == 0 {
		return nil, errors.New("interface has no RX queues")
	}
	sort.Slice(queues, func(i, j int) bool { return queues[i] < queues[j] })
	return queues, nil
}

// SetSYNFilter enables selective XDP redirect for the source port. Only one
// AF_XDP scan may use the pinned maps on a given interface at a time.
func (l *xdpLive) SetSYNFilter(port uint16) error {
	if port == 0 {
		return errors.New("zero SYN source port")
	}
	var key uint32
	var filter [8]byte
	// Preserve the source IP supplied at OpenXDP.
	if err := bpfMapLookup(l.configFD, unsafe.Pointer(&key), unsafe.Pointer(&filter[0])); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(filter[4:6], port)
	binary.NativeEndian.PutUint16(filter[6:8], 1)
	return bpfMapUpdate(l.configFD, unsafe.Pointer(&key), unsafe.Pointer(&filter[0]))
}

func (l *xdpLive) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	for _, b := range buffers {
		if len(b) == 0 {
			return 0, errors.New("receive buffer is empty")
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := 0
		for i := range l.sockets {
			idx := (l.next + i) % len(l.sockets)
			count, err := l.sockets[idx].receive(buffers[n:])
			n += count
			if err != nil {
				return n, err
			}
			if n == len(buffers) {
				break
			}
		}
		l.next = (l.next + 1) % len(l.sockets)
		if n != 0 {
			return n, nil
		}
		_, err := unix.Poll(l.pollFDs, pollMillis)
		if err != nil && err != unix.EINTR {
			return 0, err
		}
	}
}

func (l *xdpLive) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	for _, frame := range frames {
		if len(frame) < 14 || len(frame) > xdpMaxFrame {
			return 0, fmt.Errorf("AF_XDP Ethernet frame length %d outside 14..%d", len(frame), xdpMaxFrame)
		}
	}
	if len(frames) == 0 {
		return 0, nil
	}
	// TX uses queue zero. RSS determines which queue receives each reply.
	s := l.sockets[0]
	pollFD := [1]unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLOUT}}
	sent := 0
	for sent < len(frames) {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		n := s.transmit(frames[sent:])
		sent += n
		if n == 0 {
			_, err := unix.Poll(pollFD[:], pollMillis)
			if err != nil && err != unix.EINTR {
				return sent, err
			}
			_ = unix.Sendto(s.fd, nil, unix.MSG_DONTWAIT, nil)
		}
	}
	return sent, nil
}

func (l *xdpLive) Stats() Stats {
	var stats Stats
	for _, s := range l.sockets {
		stats.Received += s.received.Load()
		stats.Sent += s.sent.Load()
		var k unix.XDPStatistics
		n := uint32(unsafe.Sizeof(k))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s.fd), unix.SOL_XDP, unix.XDP_STATISTICS, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&n)), 0)
		if errno == 0 {
			stats.Dropped += k.Rx_dropped + k.Rx_ring_full + k.Rx_fill_ring_empty_descs
		}
	}
	return stats
}

func (l *xdpLive) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	var key uint32
	var filter [8]byte
	if l.configFD >= 0 {
		_ = bpfMapUpdate(l.configFD, unsafe.Pointer(&key), unsafe.Pointer(&filter[0]))
	}
	for _, q := range l.queueIDs {
		_ = bpfMapDelete(l.mapFD, unsafe.Pointer(&q))
	}
	for _, s := range l.sockets {
		_ = s.close()
	}
	if l.mapFD >= 0 {
		_ = unix.Close(l.mapFD)
	}
	if l.configFD >= 0 {
		_ = unix.Close(l.configFD)
	}
	if l.lock != nil {
		_ = l.lock.Close()
	}
	return nil
}

type bpfMapElem struct {
	mapFD uint32
	_     uint32
	key   uint64
	value uint64
	flags uint64
}
type bpfMapKey struct {
	mapFD uint32
	_     uint32
	key   uint64
}
type bpfPath struct {
	pathname  uint64
	bpfFD     uint32
	fileFlags uint32
}

func bpfCall(command int, attr unsafe.Pointer, size uintptr) (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), uintptr(attr), size)
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func bpfObjectGet(path string) (int, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	a := bpfPath{pathname: uint64(uintptr(unsafe.Pointer(p)))}
	fd, err := bpfCall(unix.BPF_OBJ_GET, unsafe.Pointer(&a), unsafe.Sizeof(a))
	runtime.KeepAlive(p)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func bpfMapUpdate(fd int, key, value unsafe.Pointer) error {
	a := bpfMapElem{mapFD: uint32(fd), key: uint64(uintptr(key)), value: uint64(uintptr(value))}
	_, err := bpfCall(unix.BPF_MAP_UPDATE_ELEM, unsafe.Pointer(&a), unsafe.Sizeof(a))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func bpfMapLookup(fd int, key, value unsafe.Pointer) error {
	a := bpfMapElem{mapFD: uint32(fd), key: uint64(uintptr(key)), value: uint64(uintptr(value))}
	_, err := bpfCall(unix.BPF_MAP_LOOKUP_ELEM, unsafe.Pointer(&a), unsafe.Sizeof(a))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func bpfMapDelete(fd int, key unsafe.Pointer) error {
	a := bpfMapKey{mapFD: uint32(fd), key: uint64(uintptr(key))}
	_, err := bpfCall(unix.BPF_MAP_DELETE_ELEM, unsafe.Pointer(&a), unsafe.Sizeof(a))
	runtime.KeepAlive(key)
	return err
}

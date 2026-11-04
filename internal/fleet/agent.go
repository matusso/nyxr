package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet/fleetpb"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/pipeline"
)

// AgentConfig configures a fleet agent.
type AgentConfig struct {
	// Controller is the controller's gRPC address (host:port).
	Controller string
	// TLS secures the connection. Nil means plaintext, which callers must
	// restrict to loopback controllers.
	TLS *tls.Config
	// IdentityFile keeps the enrolled agent ID and secret (mode 0600).
	IdentityFile string
	// EnrollToken is used once, when IdentityFile does not exist yet.
	EnrollToken string
	Name        string
	// AllowTargets is the operator-authorized vantage. It is required: an
	// agent never scans outside it, whatever the controller asks.
	AllowTargets []string
	// OpenLive is the packetd opener; nil with Privileged uses the local raw
	// backend, nil without Privileged means no raw packet I/O.
	OpenLive   packetio.Opener
	Privileged bool
	// Privilege describes the process: root, raw-capabilities, packetd or
	// unprivileged.
	Privilege string
	// Interface, when set, is used for every raw scan; otherwise raw SYN uses
	// the route to the first target, as on the CLI.
	Interface   string
	XDPPinDir   string
	EvidenceDir string
	MaxLeases   int
	// MaxRate and MaxServiceRate are this agent's total budgets, split across
	// its leases. Zero leaves the controller's share unchanged.
	MaxRate        int
	MaxServiceRate int
	AllowOT        bool
	Version        string
	Log            *log.Logger

	// Test hooks.
	Pipeline     func(*pipeline.Options)
	Capabilities func() *fleetpb.Capabilities
	// BatchRecords and FlushDelay tune result batching (default 256, 200ms).
	BatchRecords int
	FlushDelay   time.Duration
}

type identity struct {
	AgentID    string `json:"agent_id"`
	Secret     string `json:"secret"`
	Controller string `json:"controller"`
}

// Agent runs leased scans for a controller.
type Agent struct {
	cfg   AgentConfig
	scope config.Scope

	mu     sync.Mutex
	stream grpc.BidiStreamingClient[fleetpb.AgentMessage, fleetpb.ControllerMessage]
	sendMu sync.Mutex
	leases map[string]*agentLease
	wg     sync.WaitGroup
	id     identity
	// contact is the last time the controller was heard from; ttl is the
	// lease lifetime it announced. Both use this process's monotonic clock.
	contact time.Time
	ttl     time.Duration
}

// watchdog abandons every lease once the controller has been silent for a
// full lease TTL. By then the controller has expired the leases and may have
// re-leased the units, so continuing would scan the same targets twice and
// exceed the global budget.
func (a *Agent) watchdog(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		// Abandon a little before the controller can expire the lease.
		silent := a.ttl > 0 && !a.contact.IsZero() && time.Since(a.contact) > a.ttl*4/5
		var stale []*agentLease
		if silent {
			for _, l := range a.leases {
				stale = append(stale, l)
			}
		}
		a.mu.Unlock()
		for _, l := range stale {
			a.cfg.Log.Printf("abandoning lease %s: no contact with the controller for %s", l.id, a.ttl)
			l.abandon()
		}
	}
}

func (a *Agent) heard() {
	a.mu.Lock()
	a.contact = time.Now()
	a.mu.Unlock()
}

// NewAgent validates the configuration.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.Controller == "" {
		return nil, errors.New("agent requires a controller address")
	}
	if len(cfg.AllowTargets) == 0 {
		return nil, errors.New("agent requires --allow-targets: the scope this vantage is authorized to scan")
	}
	scope, err := config.ParseScope(cfg.AllowTargets)
	if err != nil || scope.Empty() {
		return nil, fmt.Errorf("invalid agent --allow-targets: %v", err)
	}
	if cfg.IdentityFile == "" {
		return nil, errors.New("agent requires an identity file")
	}
	if cfg.MaxLeases <= 0 {
		cfg.MaxLeases = 1
	}
	if cfg.BatchRecords <= 0 {
		cfg.BatchRecords = 256
	}
	if cfg.FlushDelay <= 0 {
		cfg.FlushDelay = 200 * time.Millisecond
	}
	if cfg.Log == nil {
		cfg.Log = log.New(os.Stderr, "agent: ", log.LstdFlags)
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	return &Agent{cfg: cfg, scope: scope, leases: map[string]*agentLease{}}, nil
}

// bearer sends the agent credential with every RPC.
type bearer struct {
	token  string
	secure bool
}

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{mdAuth: "Bearer " + b.token}, nil
}

func (b bearer) RequireTransportSecurity() bool { return b.secure }

func (a *Agent) dial(perRPC credentials.PerRPCCredentials) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if a.cfg.TLS != nil {
		creds = credentials.NewTLS(a.cfg.TLS)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageBytes), grpc.MaxCallSendMsgSize(MaxMessageBytes))}
	if perRPC != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(perRPC))
	}
	return grpc.NewClient(a.cfg.Controller, opts...)
}

func (a *Agent) loadIdentity(ctx context.Context) error {
	b, err := os.ReadFile(a.cfg.IdentityFile)
	if err == nil {
		if err := json.Unmarshal(b, &a.id); err != nil || a.id.AgentID == "" || a.id.Secret == "" {
			return fmt.Errorf("identity file %s is invalid", a.cfg.IdentityFile)
		}
		if a.id.Controller != "" && a.id.Controller != a.cfg.Controller {
			return fmt.Errorf("identity file %s belongs to controller %s; use another --identity to enroll with %s", a.cfg.IdentityFile, a.id.Controller, a.cfg.Controller)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("identity file %s does not exist; enroll with --enroll-token-file", a.cfg.IdentityFile)
	}
	conn, err := a.dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, mdEnroll, a.cfg.EnrollToken)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := fleetpb.NewFleetClient(conn).Enroll(ctx, &fleetpb.EnrollRequest{Protocol: Protocol, Name: a.cfg.Name, Capabilities: a.capabilities()})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	a.id = identity{AgentID: resp.GetAgentId(), Secret: resp.GetSecret(), Controller: a.cfg.Controller}
	out, _ := json.MarshalIndent(a.id, "", "  ")
	if err := os.MkdirAll(filepath.Dir(a.cfg.IdentityFile), 0o700); err != nil {
		return err
	}
	tmp := a.cfg.IdentityFile + ".tmp"
	_ = os.Remove(tmp) // a stale file would keep its old permissions
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.cfg.IdentityFile); err != nil {
		return err
	}
	a.cfg.Log.Printf("enrolled as %s; credential saved to %s", a.id.AgentID, a.cfg.IdentityFile)
	return nil
}

// capabilities advertises what this vantage can do.
func (a *Agent) capabilities() *fleetpb.Capabilities {
	if a.cfg.Capabilities != nil {
		return a.cfg.Capabilities()
	}
	raw := a.cfg.OpenLive != nil || a.cfg.Privileged
	c := &fleetpb.Capabilities{RawSocket: raw, AfXdp: raw && a.cfg.XDPPinDir != "" && runtime.GOOS == "linux",
		Ot: a.cfg.AllowOT, Capture: raw && a.cfg.EvidenceDir != "", Icmp: a.cfg.Privileged, Privilege: a.cfg.Privilege,
		AllowTargets: a.cfg.AllowTargets, MaxRate: uint32(max(a.cfg.MaxRate, 0)), MaxServiceRate: uint32(max(a.cfg.MaxServiceRate, 0)),
		MaxLeases: uint32(a.cfg.MaxLeases), Os: runtime.GOOS, Arch: runtime.GOARCH, Version: a.cfg.Version}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		pi := &fleetpb.Interface{Name: ifc.Name, Mac: ifc.HardwareAddr.String(), Mtu: uint32(max(ifc.MTU, 0))}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(ipn.String())
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
			if p.Addr().Is6() && p.Addr().IsGlobalUnicast() {
				c.Ipv6 = true
			}
			if p.Addr().IsLinkLocalUnicast() {
				continue
			}
			pi.Prefixes = append(pi.Prefixes, p.String())
		}
		c.Interfaces = append(c.Interfaces, pi)
	}
	return c
}

// Run connects, reconnecting with backoff, until ctx ends. Running leases
// continue across reconnects; their unacknowledged results are resent.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadIdentity(ctx); err != nil {
		return err
	}
	conn, err := a.dial(bearer{token: a.id.AgentID + "." + a.id.Secret, secure: a.cfg.TLS != nil})
	if err != nil {
		return err
	}
	defer conn.Close()
	client := fleetpb.NewFleetClient(conn)
	go a.watchdog(ctx)
	backoff := time.Second
	defer func() {
		a.mu.Lock()
		leases := make([]*agentLease, 0, len(a.leases))
		for _, l := range a.leases {
			leases = append(leases, l)
		}
		a.mu.Unlock()
		// abandon, not just cancel: a scan blocked on a full queue must wake.
		for _, l := range leases {
			l.abandon()
		}
		a.wg.Wait()
	}()
	for {
		start := time.Now()
		err := a.session(ctx, client)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		a.cfg.Log.Printf("controller connection lost: %v; retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (a *Agent) leaseStates() []*fleetpb.LeaseState {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*fleetpb.LeaseState, 0, len(a.leases))
	for id := range a.leases {
		out = append(out, &fleetpb.LeaseState{LeaseId: id})
	}
	return out
}

// send writes one message on the current stream; it fails while disconnected.
func (a *Agent) send(m *fleetpb.AgentMessage) error {
	a.mu.Lock()
	s := a.stream
	a.mu.Unlock()
	if s == nil {
		return errors.New("not connected")
	}
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return s.Send(m)
}

func (a *Agent) session(parent context.Context, client fleetpb.FleetClient) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Hello{Hello: &fleetpb.Hello{Protocol: Protocol,
		Capabilities: a.capabilities(), AgentTimeUnixNano: time.Now().UnixNano(), Leases: a.leaseStates()}}}); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	w := first.GetWelcome()
	if w == nil || !versionOK(w.GetProtocol()) {
		return errors.New("controller did not welcome this agent with a compatible protocol")
	}
	a.cfg.Log.Printf("connected to %s as %s", a.cfg.Controller, w.GetAgentId())
	a.mu.Lock()
	a.stream = stream
	a.contact = time.Now()
	a.ttl = time.Duration(max(w.GetLeaseTtlSeconds(), 1)) * time.Second
	for _, l := range a.leases {
		l.resend() // the previous stream may have lost the in-flight batch
	}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.stream == stream {
			a.stream = nil
		}
		a.mu.Unlock()
	}()
	hb := time.Duration(max(w.GetHeartbeatSeconds(), 1)) * time.Second
	go func() {
		t := time.NewTicker(hb)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := a.send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Heartbeat{Heartbeat: &fleetpb.Heartbeat{
					AgentTimeUnixNano: time.Now().UnixNano(), Leases: a.leaseStates()}}}); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		a.heard()
		switch msg := m.GetMsg().(type) {
		case *fleetpb.ControllerMessage_Lease:
			a.startLease(parent, msg.Lease)
		case *fleetpb.ControllerMessage_Cancel:
			a.mu.Lock()
			l := a.leases[msg.Cancel.GetLeaseId()]
			a.mu.Unlock()
			if l != nil {
				a.cfg.Log.Printf("lease %s canceled: %s", l.id, msg.Cancel.GetReason())
				l.abandon()
			}
		case *fleetpb.ControllerMessage_Ack:
			a.mu.Lock()
			l := a.leases[msg.Ack.GetLeaseId()]
			a.mu.Unlock()
			if l != nil {
				l.ack(msg.Ack.GetSeq(), msg.Ack.GetDone())
			}
		}
	}
}

func (a *Agent) respond(leaseID string, accepted bool, reason string) {
	_ = a.send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_LeaseResponse{LeaseResponse: &fleetpb.LeaseResponse{
		LeaseId: leaseID, Accepted: accepted, Reason: reason}}})
}

// prepare validates a lease against this agent's own policy and resolves it
// through the same Request.Resolve path as the API.
func (a *Agent) prepare(l *fleetpb.Lease) (config.Resolved, error) {
	var req config.Request
	d := json.NewDecoder(bytes.NewReader(l.GetRequestJson()))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return config.Resolved{}, fmt.Errorf("invalid lease request: %w", err)
	}
	if err := validateFleetRequest(req); err != nil {
		return config.Resolved{}, err
	}
	if req.Profile == "ot-safe" && !a.cfg.AllowOT {
		return config.Resolved{}, errors.New("the ot-safe profile is not permitted on this agent (--allow-ot)")
	}
	// The agent's own budget caps whatever the controller asks for.
	clamp := func(v **int, total int) {
		if total <= 0 {
			return
		}
		per := max(total/a.cfg.MaxLeases, 1)
		if *v == nil || **v == 0 || **v > per {
			*v = &per
		}
	}
	clamp(&req.Rate, a.cfg.MaxRate)
	// Concurrent leases share this agent's raw interface.
	if req.InterfaceRate != nil && *req.InterfaceRate > 0 && a.cfg.MaxLeases > 1 {
		per := max(*req.InterfaceRate/a.cfg.MaxLeases, 1)
		req.InterfaceRate = &per
	}
	if req.Service == nil || *req.Service {
		clamp(&req.ServiceRate, a.cfg.MaxServiceRate)
	}
	req.Interface = a.cfg.Interface
	r, err := req.Resolve(config.ResolveOptions{Remote: true})
	if err != nil {
		return r, err
	}
	c := r.Config
	raw := a.cfg.OpenLive != nil || a.cfg.Privileged
	switch {
	case (c.TCPMode == "syn" || c.ARP || c.NDP || r.PCAPNG != "") && !raw:
		return r, errors.New("raw SYN, ARP/NDP and capture need nyxr-packetd (--packetd) or --allow-privileged on this agent")
	case c.ICMP && !a.cfg.Privileged:
		return r, errors.New("ICMP echo needs a privileged agent (--allow-privileged)")
	case r.PCAPNG != "" && a.cfg.EvidenceDir == "":
		return r, errors.New("pcapng capture needs an agent evidence directory (--evidence-dir)")
	}
	if r.PCAPNG != "" {
		r.PCAPNG = filepath.Join(a.cfg.EvidenceDir, l.GetLeaseId()+"-"+r.PCAPNG)
		if _, err := os.Lstat(r.PCAPNG); err == nil {
			return r, fmt.Errorf("capture %s already exists", filepath.Base(r.PCAPNG))
		}
	}
	if c.TCPMode == "syn" && a.cfg.XDPPinDir != "" {
		r.Config.XDPPinDir = a.cfg.XDPPinDir
	}
	var outside netip.Addr
	c.EachTarget(func(t netip.Addr) bool {
		if !a.scope.Covers(t.Unmap().WithZone(""), t.Unmap().WithZone("")) {
			outside = t
			return false
		}
		return true
	})
	if outside.IsValid() {
		return r, fmt.Errorf("target %s is outside this agent's --allow-targets", outside)
	}
	return r, nil
}

func (a *Agent) startLease(ctx context.Context, l *fleetpb.Lease) {
	a.mu.Lock()
	if _, dup := a.leases[l.GetLeaseId()]; dup {
		a.mu.Unlock()
		return
	}
	busy := len(a.leases) >= a.cfg.MaxLeases
	a.mu.Unlock()
	if busy {
		a.respond(l.GetLeaseId(), false, ReasonLeaseLimit)
		return
	}
	r, err := a.prepare(l)
	if err != nil {
		a.cfg.Log.Printf("rejecting lease %s: %v", l.GetLeaseId(), err)
		a.respond(l.GetLeaseId(), false, err.Error())
		return
	}
	lctx, cancel := context.WithCancel(ctx)
	ls := newAgentLease(a, l.GetLeaseId(), cancel)
	a.mu.Lock()
	a.leases[ls.id] = ls
	a.mu.Unlock()
	a.respond(ls.id, true, "")
	a.cfg.Log.Printf("running lease %s: job %s unit %d attempt %d (%d targets)", ls.id, l.GetJobId(), l.GetUnit(), l.GetAttempt(), r.Config.TargetCount())
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		ls.flushLoop(ctx)
	}()
	go func() {
		defer a.wg.Done()
		opts := pipeline.FromResolved(r)
		opts.OpenLive = a.cfg.OpenLive
		opts.Sinks = []pipeline.Sink{ls}
		if a.cfg.Pipeline != nil {
			a.cfg.Pipeline(&opts)
		}
		sc, err := pipeline.Run(lctx, r.Config, opts)
		if sc.ID == "" && lctx.Err() == nil {
			// The scan never began, so no Finish will arrive.
			reason := "scan did not start"
			if err != nil {
				reason = err.Error()
			}
			a.respond(ls.id, false, reason)
			ls.abandon()
		}
	}()
}

func (a *Agent) forget(id string) {
	a.mu.Lock()
	delete(a.leases, id)
	a.mu.Unlock()
}

// agentLease streams one lease's records with at most one unacknowledged
// batch. It implements pipeline.Sink; when its bounded queue is full the
// scan blocks, so a slow or absent controller applies backpressure instead of
// growing memory.
type agentLease struct {
	agent  *Agent
	id     string
	cancel context.CancelFunc

	mu       sync.Mutex
	cond     *sync.Cond
	queue    []*fleetpb.Record
	inflight *fleetpb.ResultBatch
	sentAt   time.Time
	seq      uint64
	closed   bool // acknowledged done or abandoned
	wakeup   chan struct{}
}

// maxQueued bounds records waiting for the controller per lease.
const maxQueued = 4096

func newAgentLease(a *Agent, id string, cancel context.CancelFunc) *agentLease {
	l := &agentLease{agent: a, id: id, cancel: cancel, wakeup: make(chan struct{}, 1)}
	l.cond = sync.NewCond(&l.mu)
	return l
}

func (l *agentLease) resend() {
	l.mu.Lock()
	l.sentAt = time.Time{}
	l.mu.Unlock()
	l.kick()
}

func (l *agentLease) kick() {
	select {
	case l.wakeup <- struct{}{}:
	default:
	}
}

func (l *agentLease) enqueue(kind fleetpb.Record_Kind, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	l.mu.Lock()
	for len(l.queue) >= maxQueued && !l.closed {
		l.cond.Wait()
	}
	if l.closed {
		l.mu.Unlock()
		return errors.New("lease ended")
	}
	l.queue = append(l.queue, &fleetpb.Record{Kind: kind, Json: b})
	l.mu.Unlock()
	l.kick()
	return nil
}

func (l *agentLease) Begin(sc observe.Scan) error { return l.enqueue(fleetpb.Record_BEGIN, sc) }
func (l *agentLease) Observation(o observe.Observation) error {
	return l.enqueue(fleetpb.Record_OBSERVATION, o)
}
func (l *agentLease) PacketEvidence(p observe.PacketEvidence) error {
	return l.enqueue(fleetpb.Record_PACKET_EVIDENCE, p)
}

// Finish is delivered even when the scan context was canceled, unless the
// controller abandoned the lease.
func (l *agentLease) Finish(sc observe.Scan) error { return l.enqueue(fleetpb.Record_FINISH, sc) }

func (l *agentLease) ack(seq uint64, done bool) {
	l.mu.Lock()
	if l.inflight != nil && l.inflight.GetSeq() <= seq {
		l.inflight = nil
	}
	if done {
		l.closed = true
	}
	l.cond.Broadcast()
	l.mu.Unlock()
	if done {
		l.agent.forget(l.id)
		l.cancel()
	}
	l.kick()
}

// abandon stops the scan and drops unsent results; the controller no longer
// accepts them.
func (l *agentLease) abandon() {
	l.mu.Lock()
	l.closed = true
	l.queue, l.inflight = nil, nil
	l.cond.Broadcast()
	l.mu.Unlock()
	l.agent.forget(l.id)
	l.cancel()
	l.kick()
}

// resendAfter resends an unacknowledged batch whose ack may have been lost
// on a live stream; the controller deduplicates by seq.
const resendAfter = 30 * time.Second

// flushLoop runs until the lease is acknowledged done or abandoned, or the
// agent stops. It outlives the scan context so a canceled scan's Finish is
// still delivered.
func (l *agentLease) flushLoop(ctx context.Context) {
	cfg := l.agent.cfg
	t := time.NewTicker(cfg.FlushDelay)
	defer t.Stop()
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		var batch *fleetpb.ResultBatch
		switch {
		case l.inflight != nil && (time.Since(l.sentAt) > resendAfter || l.sentAt.IsZero()):
			batch = l.inflight
		case l.inflight == nil && len(l.queue) > 0:
			n := min(len(l.queue), cfg.BatchRecords)
			size := 0
			for i := 0; i < n; i++ {
				size += len(l.queue[i].GetJson())
				if size > MaxMessageBytes/2 && i > 0 {
					n = i
					break
				}
			}
			l.seq++
			batch = &fleetpb.ResultBatch{LeaseId: l.id, Seq: l.seq, Records: append([]*fleetpb.Record(nil), l.queue[:n]...)}
			l.queue = append(l.queue[:0], l.queue[n:]...)
			l.inflight = batch
			l.cond.Broadcast()
		}
		l.mu.Unlock()
		if batch != nil {
			err := l.agent.send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Result{Result: batch}})
			l.mu.Lock()
			if l.inflight == batch {
				if err != nil {
					l.sentAt = time.Time{} // resend on reconnect
				} else {
					l.sentAt = time.Now()
				}
			}
			l.mu.Unlock()
		}
		select {
		case <-l.wakeup:
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}

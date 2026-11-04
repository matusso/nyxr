package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet/fleetpb"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

// Metadata keys.
const (
	mdEnroll = "x-nyxr-enroll"
	mdAuth   = "authorization"
)

// MaxMessageBytes bounds one gRPC message in either direction.
const MaxMessageBytes = 16 << 20

// ClockSkewWarning is the agent clock offset reported as a health problem.
// Lease expiry never depends on agent clocks; observation timestamps do.
const ClockSkewWarning = 5 * time.Second

// ControllerConfig configures the fleet controller.
type ControllerConfig struct {
	Store *storage.Store
	// EnrollToken authorizes new agents. Empty disables enrollment; agents
	// already enrolled keep working.
	EnrollToken string
	// LeaseTTL is how long a lease survives without a heartbeat (default 30s).
	LeaseTTL time.Duration
	// Heartbeat is the agent heartbeat interval (default LeaseTTL/3).
	Heartbeat time.Duration
	// Tick is the scheduler period (default 1s).
	Tick time.Duration
	Now  func() time.Time
	Log  *log.Logger
}

// Controller implements the Fleet gRPC service and schedules work. It is
// safe for concurrent use.
type Controller struct {
	fleetpb.UnimplementedFleetServer
	cfg ControllerConfig

	mu       sync.Mutex
	conns    map[string]*agentConn
	plans    map[string]*jobPlan
	rejected map[string]map[string]string // unit key -> agent -> reason
	waiting  map[string]string            // unit key -> why no agent can run it

	wake   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type agentConn struct {
	id, name  string
	remote    string
	connected time.Time
	heard     time.Time // last message from the agent
	view      agentView
	offset    time.Duration
	leases    map[string]*leaseState
	out       chan *fleetpb.ControllerMessage
	done      chan struct{}
	closeOnce sync.Once
}

type leaseState struct {
	jobID string
	unit  int
	runs  []addrRun
}

func (a *agentConn) close() { a.closeOnce.Do(func() { close(a.done) }) }

// send queues a message. A peer that cannot keep up for five seconds is
// disconnected rather than stalling the scheduler; its leases expire or are
// resumed on reconnect.
func (a *agentConn) send(m *fleetpb.ControllerMessage) bool {
	select {
	case a.out <- m:
		return true
	case <-a.done:
		return false
	case <-time.After(5 * time.Second):
		a.close()
		return false
	}
}

// NewController starts the scheduler. Leases that were open when a previous
// controller stopped get one TTL of grace so their agents can resume.
func NewController(cfg ControllerConfig) (*Controller, error) {
	if cfg.Store == nil {
		return nil, errors.New("fleet controller requires a store")
	}
	if cfg.EnrollToken != "" && len(cfg.EnrollToken) < 16 {
		return nil, errors.New("fleet enrollment token must be at least 16 characters")
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = cfg.LeaseTTL / 3
	}
	if cfg.Heartbeat >= cfg.LeaseTTL {
		return nil, errors.New("fleet heartbeat must be shorter than the lease TTL")
	}
	if cfg.Tick <= 0 {
		cfg.Tick = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.New(log.Writer(), "fleet: ", log.LstdFlags)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{cfg: cfg, conns: map[string]*agentConn{}, plans: map[string]*jobPlan{}, rejected: map[string]map[string]string{},
		waiting: map[string]string{}, wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
	if err := cfg.Store.ExtendAllFleetLeases(ctx, cfg.Now().Add(cfg.LeaseTTL)); err != nil {
		cancel()
		return nil, err
	}
	c.wg.Add(1)
	go c.loop()
	return c, nil
}

// Close stops scheduling and disconnects agents. Open leases stay stored and
// resume when the controller restarts.
func (c *Controller) Close() {
	c.cancel()
	c.mu.Lock()
	for _, a := range c.conns {
		a.close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// Register adds the Fleet service to a gRPC server.
func (c *Controller) Register(s *grpc.Server) { fleetpb.RegisterFleetServer(s, c) }

func (c *Controller) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Controller) loop() {
	defer c.wg.Done()
	t := time.NewTicker(c.cfg.Tick)
	defer t.Stop()
	for {
		c.expire()
		c.schedule()
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		case <-c.wake:
		}
	}
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func randomID(prefix string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func versionOK(p string) bool {
	major, _, _ := strings.Cut(Protocol, ".")
	got, _, _ := strings.Cut(p, ".")
	return got == major
}

func capsJSON(caps *fleetpb.Capabilities) json.RawMessage {
	b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(caps)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// Enroll implements fleetpb.FleetServer.
func (c *Controller) Enroll(ctx context.Context, req *fleetpb.EnrollRequest) (*fleetpb.EnrollResponse, error) {
	if c.cfg.EnrollToken == "" {
		return nil, status.Error(codes.PermissionDenied, "enrollment is disabled on this controller")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	got := ""
	if v := md.Get(mdEnroll); len(v) == 1 {
		got = v[0]
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.cfg.EnrollToken)) != 1 {
		return nil, status.Error(codes.Unauthenticated, "invalid enrollment token")
	}
	if !versionOK(req.GetProtocol()) {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported fleet protocol %q; controller speaks %s", req.GetProtocol(), Protocol)
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
		return nil, status.Error(codes.InvalidArgument, "agent name must be 1..64 printable characters")
	}
	id, secret := randomID("agent-", 8), randomID("", 32)
	if err := c.cfg.Store.CreateFleetAgent(ctx, id, name, hashSecret(secret), capsJSON(req.GetCapabilities()), c.cfg.Now()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	c.cfg.Log.Printf("enrolled agent %s (%s)", id, name)
	return &fleetpb.EnrollResponse{AgentId: id, Secret: secret}, nil
}

func (c *Controller) authenticate(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(mdAuth)
	if len(v) != 1 {
		return "", status.Error(codes.Unauthenticated, "missing agent credential")
	}
	cred, ok := strings.CutPrefix(v[0], "Bearer ")
	id, secret, ok2 := strings.Cut(cred, ".")
	if !ok || !ok2 || id == "" || secret == "" {
		return "", status.Error(codes.Unauthenticated, "malformed agent credential")
	}
	hash, ok, err := c.cfg.Store.FleetAgentSecret(ctx, id)
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	// Compare even for unknown agents so timing does not reveal enrollment.
	want := hash
	if !ok {
		want = hashSecret("\x00unknown")
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(want)) != 1 || !ok {
		return "", status.Error(codes.Unauthenticated, "unknown, revoked or invalid agent credential")
	}
	return id, nil
}

// Connect implements fleetpb.FleetServer.
func (c *Controller) Connect(stream grpc.BidiStreamingServer[fleetpb.AgentMessage, fleetpb.ControllerMessage]) error {
	ctx := stream.Context()
	id, err := c.authenticate(ctx)
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "first message must be Hello")
	}
	if !versionOK(hello.GetProtocol()) {
		return status.Errorf(codes.FailedPrecondition, "unsupported fleet protocol %q; controller speaks %s", hello.GetProtocol(), Protocol)
	}
	view, err := newAgentView(id, hello.GetCapabilities())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	now := c.cfg.Now()
	offset := time.Unix(0, hello.GetAgentTimeUnixNano()).Sub(now)
	if err := c.cfg.Store.TouchFleetAgent(ctx, id, now, offset, capsJSON(hello.GetCapabilities())); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	a := &agentConn{id: id, connected: now, heard: now, view: view, offset: offset, leases: map[string]*leaseState{},
		out: make(chan *fleetpb.ControllerMessage, 64), done: make(chan struct{})}
	if p, ok := peer.FromContext(ctx); ok {
		a.remote = p.Addr.String()
	}
	if err := stream.Send(&fleetpb.ControllerMessage{Msg: &fleetpb.ControllerMessage_Welcome{Welcome: &fleetpb.Welcome{
		Protocol: Protocol, AgentId: id, HeartbeatSeconds: uint32(max(c.cfg.Heartbeat/time.Second, 1)),
		LeaseTtlSeconds: uint32(max(c.cfg.LeaseTTL/time.Second, 1)), ControllerTimeUnixNano: now.UnixNano()}}}); err != nil {
		return err
	}
	// Adopt the leases the agent still runs and cancel the rest.
	var cancels []*fleetpb.ControllerMessage
	reported := map[string]bool{}
	for _, l := range hello.GetLeases() {
		reported[l.GetLeaseId()] = true
	}
	open, err := c.cfg.Store.ActiveFleetLeases(ctx, id)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	stored := map[string]storage.FleetAttempt{}
	for _, l := range open {
		stored[l.LeaseID] = l
	}
	for leaseID := range reported {
		l, ok := stored[leaseID]
		if !ok {
			cancels = append(cancels, cancelMsg(leaseID, "lease is no longer active"))
			continue
		}
		ls, err := c.leaseState(ctx, l.JobID, l.Index)
		if err != nil {
			cancels = append(cancels, cancelMsg(leaseID, err.Error()))
			continue
		}
		a.leases[leaseID] = ls
	}
	for leaseID := range stored {
		if !reported[leaseID] {
			// The agent restarted and lost this work.
			if _, fin, err := c.cfg.Store.EndFleetLease(ctx, leaseID, storage.FleetExpired, "agent reconnected without the lease", c.cfg.Now()); err == nil && fin {
				c.forgetFinishedJobs()
			}
		}
	}
	a.view.leases = len(a.leases)
	c.mu.Lock()
	if old := c.conns[id]; old != nil {
		// A reconnect after a network drop replaces the stale stream. Two
		// live processes sharing one identity flap here, so say so.
		c.cfg.Log.Printf("agent %s connected from %s while connected from %s; replacing the older connection (one identity per agent process)", id, a.remote, old.remote)
		old.close()
	}
	c.conns[id] = a
	c.mu.Unlock()
	// Revoke writes the store, then closes registered connections; this
	// registers, then reads the store. One of the two sees the other.
	if _, ok, err := c.cfg.Store.FleetAgentSecret(ctx, id); err != nil || !ok {
		a.close()
		c.mu.Lock()
		if c.conns[id] == a {
			delete(c.conns, id)
		}
		c.mu.Unlock()
		return status.Error(codes.Unauthenticated, "agent credential revoked")
	}
	c.cfg.Log.Printf("agent %s connected from %s with %d lease(s); clock offset %s", id, a.remote, len(a.leases), offset.Round(time.Millisecond))
	defer func() {
		a.close()
		c.mu.Lock()
		if c.conns[id] == a {
			delete(c.conns, id)
		}
		c.mu.Unlock()
		c.cfg.Log.Printf("agent %s disconnected", id)
	}()

	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case m := <-a.out:
				if err := stream.Send(m); err != nil {
					sendErr <- err
					a.close()
					return
				}
			case <-a.done:
				sendErr <- nil
				return
			case <-ctx.Done():
				sendErr <- ctx.Err()
				return
			}
		}
	}()
	for _, m := range cancels {
		a.send(m)
	}
	c.poke()

	recv := make(chan *fleetpb.AgentMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recv <- m:
			case <-a.done:
				return
			}
		}
	}()
	for {
		select {
		case <-a.done:
			return status.Error(codes.Unavailable, "connection replaced or closed")
		case <-c.ctx.Done():
			return status.Error(codes.Unavailable, "controller shutting down")
		case err := <-sendErr:
			return err
		case err := <-recvErr:
			return err
		case m := <-recv:
			if err := c.handle(ctx, a, m); err != nil {
				return err
			}
		}
	}
}

func cancelMsg(leaseID, reason string) *fleetpb.ControllerMessage {
	return &fleetpb.ControllerMessage{Msg: &fleetpb.ControllerMessage_Cancel{Cancel: &fleetpb.Cancel{LeaseId: leaseID, Reason: reason}}}
}

func (c *Controller) leaseState(ctx context.Context, jobID string, idx int) (*leaseState, error) {
	u, err := c.cfg.Store.FleetUnit(ctx, jobID, idx)
	if err != nil {
		return nil, err
	}
	runs, err := unitRuns(u.Targets)
	if err != nil {
		return nil, err
	}
	return &leaseState{jobID: jobID, unit: idx, runs: runs}, nil
}

func (c *Controller) handle(ctx context.Context, a *agentConn, m *fleetpb.AgentMessage) error {
	c.mu.Lock()
	a.heard = c.cfg.Now()
	c.mu.Unlock()
	switch msg := m.GetMsg().(type) {
	case *fleetpb.AgentMessage_Heartbeat:
		now := c.cfg.Now()
		offset := time.Unix(0, msg.Heartbeat.GetAgentTimeUnixNano()).Sub(now)
		c.mu.Lock()
		a.offset = offset
		c.mu.Unlock()
		if err := c.cfg.Store.TouchFleetAgent(ctx, a.id, now, offset, nil); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		var ids []string
		for _, l := range msg.Heartbeat.GetLeases() {
			ids = append(ids, l.GetLeaseId())
		}
		gone, err := c.cfg.Store.RenewFleetLeases(ctx, a.id, ids, now.Add(c.cfg.LeaseTTL))
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		for _, id := range gone {
			c.dropLease(a, id)
			a.send(cancelMsg(id, "lease is no longer active"))
		}
		a.send(&fleetpb.ControllerMessage{Msg: &fleetpb.ControllerMessage_Pong{Pong: &fleetpb.Pong{ControllerTimeUnixNano: now.UnixNano()}}})
	case *fleetpb.AgentMessage_LeaseResponse:
		r := msg.LeaseResponse
		if r.GetAccepted() {
			return nil
		}
		c.mu.Lock()
		ls := a.leases[r.GetLeaseId()]
		if ls != nil && r.GetReason() != ReasonLeaseLimit {
			key := unitKey(ls.jobID, ls.unit)
			if c.rejected[key] == nil {
				c.rejected[key] = map[string]string{}
			}
			c.rejected[key][a.id] = r.GetReason()
		}
		c.mu.Unlock()
		if ls == nil {
			return nil
		}
		c.dropLease(a, r.GetLeaseId())
		if _, fin, err := c.cfg.Store.EndFleetLease(ctx, r.GetLeaseId(), storage.FleetRejected, "agent: "+r.GetReason(), c.cfg.Now()); err != nil {
			return status.Error(codes.Internal, err.Error())
		} else if fin {
			c.forgetFinishedJobs()
		}
		c.poke()
	case *fleetpb.AgentMessage_Result:
		return c.applyResult(ctx, a, msg.Result)
	case *fleetpb.AgentMessage_Hello:
		return status.Error(codes.FailedPrecondition, "duplicate Hello")
	default:
		return status.Error(codes.InvalidArgument, "unknown agent message")
	}
	return nil
}

func (c *Controller) dropLease(a *agentConn, leaseID string) {
	c.mu.Lock()
	if _, ok := a.leases[leaseID]; ok {
		delete(a.leases, leaseID)
		a.view.leases = len(a.leases)
	}
	c.mu.Unlock()
}

func unitKey(jobID string, idx int) string { return fmt.Sprintf("%s/%d", jobID, idx) }

// decodeRecords parses the agent's JSON records and checks every target
// against the unit, so a misbehaving agent cannot write observations about
// addresses it was never asked to scan.
func decodeRecords(in []*fleetpb.Record, runs []addrRun) ([]storage.FleetRecord, error) {
	out := make([]storage.FleetRecord, 0, len(in))
	for i, r := range in {
		var rec storage.FleetRecord
		var err error
		switch r.GetKind() {
		case fleetpb.Record_BEGIN, fleetpb.Record_FINISH:
			rec.Kind = storage.FleetBegin
			if r.GetKind() == fleetpb.Record_FINISH {
				rec.Kind = storage.FleetFinish
			}
			err = json.Unmarshal(r.GetJson(), &rec.Scan)
			if err == nil && (rec.Scan.Schema != observe.SchemaVersion || rec.Scan.Kind != observe.KindScan) {
				err = fmt.Errorf("scan record schema %q kind %q", rec.Scan.Schema, rec.Scan.Kind)
			}
		case fleetpb.Record_OBSERVATION:
			rec.Kind = storage.FleetObservation
			err = json.Unmarshal(r.GetJson(), &rec.Observation)
			if err == nil && !runsContain(runs, rec.Observation.Target) {
				err = fmt.Errorf("observation target %s is outside the leased unit", rec.Observation.Target)
			}
			if err == nil && rec.Observation.Schema != "" && rec.Observation.Schema != observe.SchemaVersion {
				err = fmt.Errorf("observation schema %q", rec.Observation.Schema)
			}
		case fleetpb.Record_PACKET_EVIDENCE:
			rec.Kind = storage.FleetPacketEvidence
			err = json.Unmarshal(r.GetJson(), &rec.Packets)
			if err == nil && !runsContain(runs, rec.Packets.Target) {
				err = fmt.Errorf("packet evidence target %s is outside the leased unit", rec.Packets.Target)
			}
		default:
			err = errors.New("unknown record kind")
		}
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func ackMsg(leaseID string, seq uint64, done bool) *fleetpb.ControllerMessage {
	return &fleetpb.ControllerMessage{Msg: &fleetpb.ControllerMessage_Ack{Ack: &fleetpb.Ack{LeaseId: leaseID, Seq: seq, Done: done}}}
}

func (c *Controller) applyResult(ctx context.Context, a *agentConn, b *fleetpb.ResultBatch) error {
	leaseID := b.GetLeaseId()
	c.mu.Lock()
	ls := a.leases[leaseID]
	c.mu.Unlock()
	if ls == nil {
		// A resend of an already finished lease is acknowledged again so the
		// agent can forget it; anything else is stale.
		if at, ok, err := c.cfg.Store.FleetAttempt(ctx, leaseID); err == nil && ok && at.AgentID == a.id && b.GetSeq() <= at.LastSeq {
			a.send(ackMsg(leaseID, at.LastSeq, at.Status != storage.FleetLeased))
			return nil
		}
		a.send(cancelMsg(leaseID, "lease is no longer active"))
		return nil
	}
	recs, err := decodeRecords(b.GetRecords(), ls.runs)
	if err != nil {
		err = fmt.Errorf("%w: %w", storage.ErrInvalidBatch, err)
	} else {
		var applied storage.FleetApplied
		applied, err = c.cfg.Store.ApplyFleetBatch(ctx, leaseID, b.GetSeq(), recs, c.cfg.Now())
		if err == nil {
			// Queue the Ack before waking the scheduler, so the agent frees
			// its lease slot before any new Lease arrives on the stream.
			a.send(ackMsg(leaseID, b.GetSeq(), applied.Done))
			if applied.Done {
				c.dropLease(a, leaseID)
				if applied.JobFinished {
					c.forgetFinishedJobs()
				}
				c.poke()
			}
			return nil
		}
	}
	if !errors.Is(err, storage.ErrLeaseGone) && !errors.Is(err, storage.ErrInvalidBatch) {
		// A storage failure is not the agent's fault: drop the stream without
		// acknowledging, and the agent resends the batch after reconnecting.
		c.cfg.Log.Printf("agent %s lease %s: storing results: %v", a.id, leaseID, err)
		return status.Error(codes.Unavailable, "controller could not store results; resend")
	}
	// Invalid data, a sequence gap or a lease that ended: stop this lease,
	// keep the stream for the agent's other work.
	reason := err.Error()
	if errors.Is(err, storage.ErrLeaseGone) {
		reason = "lease is no longer active"
	} else {
		c.cfg.Log.Printf("agent %s lease %s: rejecting results: %v", a.id, leaseID, err)
		if _, fin, endErr := c.cfg.Store.EndFleetLease(ctx, leaseID, storage.FleetFailed, "invalid results: "+reason, c.cfg.Now()); endErr != nil {
			return status.Error(codes.Internal, endErr.Error())
		} else if fin {
			c.forgetFinishedJobs()
		}
	}
	c.dropLease(a, leaseID)
	a.send(cancelMsg(leaseID, reason))
	c.poke()
	return nil
}

// expire ends leases whose agents stopped renewing them.
func (c *Controller) expire() {
	now := c.cfg.Now()
	ids, err := c.cfg.Store.ExpiredFleetLeases(c.ctx, now)
	if err != nil {
		if c.ctx.Err() == nil {
			c.cfg.Log.Printf("expire leases: %v", err)
		}
		return
	}
	for _, id := range ids {
		ok, fin, err := c.cfg.Store.ExpireFleetLease(c.ctx, id, "no heartbeat before the lease expired", now)
		if err != nil {
			c.cfg.Log.Printf("expire lease %s: %v", id, err)
			continue
		}
		if fin {
			c.forgetFinishedJobs()
		}
		if !ok {
			continue
		}
		c.mu.Lock()
		var holder *agentConn
		for _, a := range c.conns {
			if _, held := a.leases[id]; held {
				holder = a
			}
		}
		c.mu.Unlock()
		if holder != nil {
			c.dropLease(holder, id)
			holder.send(cancelMsg(id, "lease expired"))
		}
		c.cfg.Log.Printf("lease %s expired; unit requeued or failed", id)
	}
}

func (c *Controller) plan(ctx context.Context, jobID string) (*jobPlan, error) {
	c.mu.Lock()
	p := c.plans[jobID]
	c.mu.Unlock()
	if p != nil {
		return p, nil
	}
	j, ok, err := c.cfg.Store.FleetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("job %s not found", jobID)
	}
	p, err = planFromStored(j)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.plans[jobID] = p
	c.mu.Unlock()
	return p, nil
}

func planFromStored(j storage.FleetJob) (*jobPlan, error) {
	var req config.Request
	var opts JobOptions
	if err := json.Unmarshal(j.Request, &req); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(j.Options, &opts); err != nil {
		return nil, err
	}
	return planFromStoredRequest(req, opts)
}

func planFromStoredRequest(req config.Request, opts JobOptions) (*jobPlan, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}
	p := jobPlan{request: req, options: opts}
	r, err := resolveForController(p.request)
	if err != nil {
		return nil, err
	}
	p.needs, p.rate, p.subnetRate = requirementsOf(r), r.Config.Rate, r.Config.SubnetRate
	if r.Service.Enabled {
		p.serviceRate = r.Service.Rate
	}
	// Every lease gets at least 1/s, so a global budget below max_parallel
	// could not be honored.
	if p.rate > 0 && p.rate < opts.MaxParallel || p.serviceRate > 0 && p.serviceRate < opts.MaxParallel {
		return nil, fmt.Errorf("rate and service_rate must be at least max_parallel (%d) so every lease gets a share", opts.MaxParallel)
	}
	return &p, nil
}

func (c *Controller) forgetFinishedJobs() {
	c.mu.Lock()
	ids := make([]string, 0, len(c.plans))
	for id := range c.plans {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	var done []string
	for _, id := range ids {
		j, ok, err := c.cfg.Store.FleetJob(c.ctx, id)
		if err == nil && (!ok || j.Status != storage.FleetRunning) {
			done = append(done, id)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range done {
		delete(c.plans, id)
		for k := range c.rejected {
			if strings.HasPrefix(k, id+"/") {
				delete(c.rejected, k)
			}
		}
		for k := range c.waiting {
			if strings.HasPrefix(k, id+"/") {
				delete(c.waiting, k)
			}
		}
	}
}

// schedule leases pending units to eligible connected agents. One goroutine
// runs it; the store's conditional update keeps a unit leased at most once.
func (c *Controller) schedule() {
	c.mu.Lock()
	if len(c.conns) == 0 {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	now := c.cfg.Now()
	units, err := c.cfg.Store.PendingFleetUnits(c.ctx, now, 512)
	if err != nil {
		if c.ctx.Err() == nil {
			c.cfg.Log.Printf("pending units: %v", err)
		}
		return
	}
	// Count every open lease, including those of disconnected agents that
	// have not expired yet: they may still be scanning.
	open, err := c.cfg.Store.ActiveFleetLeases(c.ctx, "")
	if err != nil {
		c.cfg.Log.Printf("active leases: %v", err)
		return
	}
	active := map[string]int{}
	for _, l := range open {
		active[l.JobID]++
	}
	for _, u := range units {
		p, err := c.plan(c.ctx, u.JobID)
		if err != nil {
			c.cfg.Log.Printf("job %s: %v", u.JobID, err)
			continue
		}
		if active[u.JobID] >= p.options.MaxParallel {
			continue
		}
		runs, err := unitRuns(u.Targets)
		if err != nil {
			c.cfg.Log.Printf("job %s unit %d: %v", u.JobID, u.Index, err)
			continue
		}
		key := unitKey(u.JobID, u.Index)
		c.mu.Lock()
		var candidates []*agentConn
		reasons := map[string]bool{}
		for _, a := range c.conns {
			if now.Sub(a.heard) > c.cfg.LeaseTTL {
				// Half-open or stalled: no heartbeat for a whole TTL.
				a.close()
				reasons["agent silent"] = true
				continue
			}
			if _, no := c.rejected[key][a.id]; no {
				reasons["rejected by agent"] = true
				continue
			}
			if ok, why := a.view.eligible(p.needs, runs); !ok {
				reasons[why] = true
				continue
			}
			candidates = append(candidates, a)
		}
		if len(candidates) == 0 {
			var why []string
			for r := range reasons {
				why = append(why, r)
			}
			sort.Strings(why)
			c.waiting[key] = strings.Join(why, "; ")
			c.mu.Unlock()
			continue
		}
		delete(c.waiting, key)
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].view.leases != candidates[j].view.leases {
				return candidates[i].view.leases < candidates[j].view.leases
			}
			return candidates[i].id < candidates[j].id
		})
		a := candidates[0]
		offset := a.offset
		c.mu.Unlock()
		leaseID := randomID("lease-", 12)
		attempt, ok, err := c.cfg.Store.LeaseFleetUnit(c.ctx, u.JobID, u.Index, leaseID, a.id, now, now.Add(c.cfg.LeaseTTL), offset)
		if err != nil || !ok {
			if err != nil {
				c.cfg.Log.Printf("lease job %s unit %d: %v", u.JobID, u.Index, err)
			}
			continue
		}
		body, err := json.Marshal(leaseRequest(*p, u.Targets, u.SubnetShare, a.view.caps))
		if err != nil {
			continue
		}
		c.mu.Lock()
		a.leases[leaseID] = &leaseState{jobID: u.JobID, unit: u.Index, runs: runs}
		a.view.leases = len(a.leases)
		c.mu.Unlock()
		active[u.JobID]++
		sent := a.send(&fleetpb.ControllerMessage{Msg: &fleetpb.ControllerMessage_Lease{Lease: &fleetpb.Lease{
			LeaseId: leaseID, JobId: u.JobID, Unit: uint32(u.Index), Attempt: uint32(attempt), RequestJson: body,
			TtlSeconds: uint32(max(c.cfg.LeaseTTL/time.Second, 1))}}})
		if !sent {
			// The lease expires and is retried like any lost lease.
			c.dropLease(a, leaseID)
		}
	}
}

// Submit validates, partitions and stores a distributed scan.
func (c *Controller) Submit(ctx context.Context, req config.Request, opts JobOptions) (storage.FleetJob, error) {
	if err := opts.normalize(); err != nil {
		return storage.FleetJob{}, err
	}
	if _, err := planFromStoredRequest(req, opts); err != nil {
		return storage.FleetJob{}, err
	}
	r, err := resolveForController(req)
	if err != nil {
		return storage.FleetJob{}, err
	}
	units, err := Partition(r.Config, opts.UnitSize)
	if err != nil {
		return storage.FleetJob{}, err
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return storage.FleetJob{}, err
	}
	optJSON, err := json.Marshal(opts)
	if err != nil {
		return storage.FleetJob{}, err
	}
	now := c.cfg.Now()
	job := storage.FleetJob{ID: "fleet-" + observe.NewScanID(now), Created: now, Request: reqJSON, Options: optJSON,
		MaxAttempts: opts.MaxAttempts, Targets: r.Config.TargetCount()}
	stored := make([]storage.FleetUnit, len(units))
	for i, u := range units {
		stored[i] = storage.FleetUnit{Targets: u.Targets, TargetCount: u.Count, SubnetShare: u.SubnetShare}
	}
	if err := c.cfg.Store.CreateFleetJob(ctx, job, stored); err != nil {
		return storage.FleetJob{}, err
	}
	c.poke()
	j, _, err := c.cfg.Store.FleetJob(ctx, job.ID)
	return j, err
}

// Cancel stops a running job and its leases. ok is false when the job is not
// running.
func (c *Controller) Cancel(ctx context.Context, jobID string) (bool, error) {
	leases, ok, err := c.cfg.Store.CancelFleetJob(ctx, jobID, c.cfg.Now())
	if err != nil || !ok {
		return ok, err
	}
	for _, l := range leases {
		if _, _, err := c.cfg.Store.EndFleetLease(ctx, l.LeaseID, storage.FleetCanceled, "job canceled", c.cfg.Now()); err != nil {
			return true, err
		}
		c.mu.Lock()
		a := c.conns[l.AgentID]
		c.mu.Unlock()
		if a != nil {
			c.dropLease(a, l.LeaseID)
			a.send(cancelMsg(l.LeaseID, "job canceled"))
		}
	}
	c.forgetFinishedJobs()
	return true, nil
}

// AgentStatus is an enrolled agent with its live connection.
type AgentStatus struct {
	storage.FleetAgent
	Connected      bool      `json:"connected"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
	Remote         string    `json:"remote,omitempty"`
	ActiveLeases   int       `json:"active_leases"`
	// Health is online, offline, revoked or clock-skew.
	Health string `json:"health"`
}

// Agents lists enrolled agents with live state.
func (c *Controller) Agents(ctx context.Context) ([]AgentStatus, error) {
	stored, err := c.cfg.Store.FleetAgents(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AgentStatus, 0, len(stored))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range stored {
		s := AgentStatus{FleetAgent: a, Health: "offline"}
		if conn := c.conns[a.ID]; conn != nil {
			s.Connected, s.ConnectedSince, s.Remote, s.ActiveLeases = true, conn.connected, conn.remote, len(conn.leases)
			s.ClockOffset = conn.offset
			s.Health = "online"
			if s.ClockOffset > ClockSkewWarning || -s.ClockOffset > ClockSkewWarning {
				s.Health = "clock-skew"
			}
		}
		if a.Revoked {
			s.Health = "revoked"
		}
		out = append(out, s)
	}
	return out, nil
}

// Revoke disables an agent credential and disconnects it. Its open leases
// expire and are retried elsewhere.
func (c *Controller) Revoke(ctx context.Context, agentID string) (bool, error) {
	ok, err := c.cfg.Store.RevokeFleetAgent(ctx, agentID, c.cfg.Now())
	if err != nil || !ok {
		return ok, err
	}
	c.mu.Lock()
	if a := c.conns[agentID]; a != nil {
		a.close()
	}
	c.mu.Unlock()
	return true, nil
}

// JobDetail is a job with its units, attempts and scheduling notes.
type JobDetail struct {
	storage.FleetJob
	UnitList []UnitDetail           `json:"unit_list"`
	Attempts []storage.FleetAttempt `json:"attempts"`
}

// UnitDetail adds the scheduler's reason a pending unit is not leased.
type UnitDetail struct {
	storage.FleetUnit
	Waiting string `json:"waiting,omitempty"`
}

// Job returns a job's full state; ok is false when it does not exist.
func (c *Controller) Job(ctx context.Context, jobID string) (JobDetail, bool, error) {
	j, ok, err := c.cfg.Store.FleetJob(ctx, jobID)
	if err != nil || !ok {
		return JobDetail{}, ok, err
	}
	units, err := c.cfg.Store.FleetUnits(ctx, jobID)
	if err != nil {
		return JobDetail{}, false, err
	}
	attempts, err := c.cfg.Store.FleetAttempts(ctx, jobID)
	if err != nil {
		return JobDetail{}, false, err
	}
	d := JobDetail{FleetJob: j, Attempts: attempts, UnitList: make([]UnitDetail, len(units))}
	c.mu.Lock()
	for i, u := range units {
		d.UnitList[i] = UnitDetail{FleetUnit: u}
		if u.Status == storage.FleetPending {
			d.UnitList[i].Waiting = c.waiting[unitKey(jobID, u.Index)]
			if d.UnitList[i].Waiting == "" && len(c.conns) == 0 {
				d.UnitList[i].Waiting = "no agent connected"
			}
		}
	}
	c.mu.Unlock()
	return d, true, nil
}

// Jobs lists recent jobs.
func (c *Controller) Jobs(ctx context.Context, limit int) ([]storage.FleetJob, error) {
	return c.cfg.Store.FleetJobs(ctx, limit)
}

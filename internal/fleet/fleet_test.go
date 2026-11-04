package fleet

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet/fleetpb"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/storage"
)

const testToken = "enroll-token-0123456789"

type harness struct {
	t     *testing.T
	store *storage.Store
	ctrl  *Controller
	srv   *grpc.Server
	ttl   time.Duration
	addr  string
	dir   string
}

func (h *harness) serve(addr string) {
	h.t.Helper()
	ctrl, err := NewController(ControllerConfig{Store: h.store, EnrollToken: testToken, LeaseTTL: h.ttl, Heartbeat: h.ttl / 4,
		Tick: 50 * time.Millisecond, Log: log.New(io.Discard, "", 0)})
	if err != nil {
		h.t.Fatal(err)
	}
	var l net.Listener
	for i := 0; ; i++ {
		if l, err = net.Listen("tcp", addr); err == nil || i == 50 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		h.t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(MaxMessageBytes), grpc.MaxSendMsgSize(MaxMessageBytes))
	ctrl.Register(srv)
	go func() { _ = srv.Serve(l) }()
	h.ctrl, h.srv, h.addr = ctrl, srv, l.Addr().String()
}

// restart replaces the controller process state while keeping its database.
func (h *harness) restart() {
	h.srv.Stop()
	h.ctrl.Close()
	h.serve(h.addr)
}

func newHarness(t *testing.T, ttl time.Duration) *harness {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(context.Background(), filepath.Join(dir, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: store, ttl: ttl, dir: dir}
	h.serve("127.0.0.1:0")
	t.Cleanup(func() { h.srv.Stop(); h.ctrl.Close(); store.Close() })
	return h
}

// fakeDiscover reports port 80 open on every target. block, when set, stops
// after that many targets and waits for cancellation, simulating an agent
// that dies mid-unit.
func fakeDiscover(block int, emitted *atomic.Int64) func(*pipeline.Options) {
	return func(o *pipeline.Options) {
		o.Discover = func(ctx context.Context, cfg config.Config, emit func(scan.Observation) error) error {
			n := 0
			var err error
			cfg.EachTarget(func(a netip.Addr) bool {
				if block > 0 && n >= block {
					return false
				}
				n++
				err = emit(scan.Observation{Timestamp: time.Now(), Target: a, Transport: "tcp", Port: 80, State: "open", Confidence: 90,
					Reason: "syn-ack", Probe: "tcp-connect"})
				if emitted != nil {
					emitted.Add(1)
				}
				return err == nil
			})
			if block > 0 {
				<-ctx.Done()
				return ctx.Err()
			}
			return err
		}
	}
}

func (h *harness) agent(name string, hook func(*pipeline.Options), caps func(*fleetpb.Capabilities)) (stop func()) {
	h.t.Helper()
	probe := &fleetpb.Capabilities{}
	if caps != nil {
		caps(probe)
	}
	cfg := AgentConfig{Privileged: probe.RawSocket, Controller: h.addr, IdentityFile: filepath.Join(h.dir, name+".json"), EnrollToken: testToken, Name: name,
		AllowTargets: []string{"10.0.0.0/16"}, MaxLeases: 1, Version: "test", Log: log.New(io.Discard, "", 0), Pipeline: hook,
		FlushDelay: 20 * time.Millisecond, BatchRecords: 64}
	cfg.Capabilities = func() *fleetpb.Capabilities {
		c := &fleetpb.Capabilities{AllowTargets: cfg.AllowTargets, MaxLeases: 1, Privilege: "unprivileged", Os: "test", Version: "test"}
		if caps != nil {
			caps(c)
		}
		return c
	}
	a, err := NewAgent(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	h.t.Cleanup(stop)
	return stop
}

func (h *harness) waitConnected(n int) {
	h.t.Helper()
	h.eventually(func() bool {
		agents, err := h.ctrl.Agents(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		c := 0
		for _, a := range agents {
			if a.Connected {
				c++
			}
		}
		return c == n
	}, "agents connected")
}

func (h *harness) eventually(ok func() bool, what string) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *harness) waitJob(id string) JobDetail {
	h.t.Helper()
	var d JobDetail
	h.eventually(func() bool {
		var err error
		d, _, err = h.ctrl.Job(context.Background(), id)
		if err != nil {
			h.t.Fatal(err)
		}
		return d.Status != storage.FleetRunning
	}, "job "+id)
	return d
}

func connectRequest(targets ...string) config.Request {
	off := false
	return config.Request{Targets: targets, Ports: "80", Protocols: "tcp", Service: &off}
}

func countObservations(t *testing.T, s *storage.Store) int {
	t.Helper()
	obs, err := s.Observations(context.Background(), storage.Filter{Limit: 100000})
	if err != nil {
		t.Fatal(err)
	}
	return len(obs)
}

// Two agents share a job; every target is stored exactly once.
func TestTwoAgentsCompleteJob(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	h.agent("eu-1", fakeDiscover(0, nil), nil)
	h.agent("us-1", fakeDiscover(0, nil), nil)
	h.waitConnected(2)
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.0.0/22"), JobOptions{UnitSize: 256, MaxParallel: 2})
	if err != nil {
		t.Fatal(err)
	}
	if job.Units != 4 || job.Targets != 1024 {
		t.Fatalf("units %d targets %d", job.Units, job.Targets)
	}
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || d.Observations != 1024 || d.UnitStatus[storage.FleetCompleted] != 4 {
		t.Fatalf("job %+v", d.FleetJob)
	}
	agents := map[string]bool{}
	for _, u := range d.UnitList {
		agents[u.AgentID] = true
		if u.Attempts != 1 || u.ScanID == "" {
			t.Fatalf("unit %+v attempts %+v", u, d.Attempts)
		}
		sc, ok, err := h.store.Scan(context.Background(), u.ScanID)
		if err != nil || !ok || sc.Status != "completed" || sc.Observations != 256 {
			t.Fatalf("scan %+v %v %v", sc, ok, err)
		}
	}
	if len(agents) != 2 {
		t.Fatalf("units ran on %d agents, want both", len(agents))
	}
	if n := countObservations(t, h.store); n != 1024 {
		t.Fatalf("stored %d observations, want 1024", n)
	}
}

// An agent dies mid-unit: its lease expires, the unit is retried on the other
// agent, and job totals count only the completed attempt.
func TestAgentLossRequeuesWithoutDoubleCounting(t *testing.T) {
	h := newHarness(t, 2*time.Second)
	var emitted atomic.Int64
	stopA := h.agent("dies", fakeDiscover(100, &emitted), nil)
	h.waitConnected(1)
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.1.0/24"), JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Wait until the partial results are stored, then kill the agent.
	h.eventually(func() bool { return countObservations(t, h.store) == 100 }, "partial results")
	stopA()
	h.agent("survives", fakeDiscover(0, nil), nil)
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || d.Observations != 256 {
		t.Fatalf("job %+v", d.FleetJob)
	}
	if len(d.Attempts) != 2 || d.Attempts[0].Status != storage.FleetExpired || d.Attempts[1].Status != storage.FleetCompleted {
		t.Fatalf("attempts %+v", d.Attempts)
	}
	partial, _, err := h.store.Scan(context.Background(), d.Attempts[0].ScanID)
	if err != nil || partial.Status != "failed" {
		t.Fatalf("partial scan %+v %v", partial, err)
	}
	// The failed attempt's evidence is kept (100) but not counted in the job.
	if n := countObservations(t, h.store); n != 356 {
		t.Fatalf("stored %d observations, want 100 partial + 256 accepted", n)
	}
}

// Units are only leased to agents with the required capability and vantage.
func TestCapabilityAndVantageScheduling(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	h.agent("connect-only", fakeDiscover(0, nil), nil)
	h.waitConnected(1)
	req := connectRequest("10.0.2.0/24")
	req.TCPMode = "syn"
	job, err := h.ctrl.Submit(context.Background(), req, JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h.eventually(func() bool {
		d, _, _ := h.ctrl.Job(context.Background(), job.ID)
		return len(d.UnitList) == 1 && d.UnitList[0].Waiting == "raw packet I/O unavailable"
	}, "waiting reason")
	outside, err := h.ctrl.Submit(context.Background(), connectRequest("192.0.2.0/28"), JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h.eventually(func() bool {
		d, _, _ := h.ctrl.Job(context.Background(), outside.ID)
		return len(d.UnitList) == 1 && d.UnitList[0].Waiting == "targets outside the agent's authorized vantage"
	}, "vantage reason")
	h.agent("raw", fakeDiscover(0, nil), func(c *fleetpb.Capabilities) { c.RawSocket = true })
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || d.Observations != 256 {
		t.Fatalf("syn job %+v", d.FleetJob)
	}
	if ok, err := h.ctrl.Cancel(context.Background(), outside.ID); err != nil || !ok {
		t.Fatalf("cancel %v %v", ok, err)
	}
	if d := h.waitJob(outside.ID); d.Status != storage.FleetCanceled || d.UnitStatus[storage.FleetCanceled] != 1 {
		t.Fatalf("canceled job %+v", d.FleetJob)
	}
}

// rawAgent speaks the protocol by hand to exercise duplicates and hostile input.
type rawAgent struct {
	t      *testing.T
	stream grpc.BidiStreamingClient[fleetpb.AgentMessage, fleetpb.ControllerMessage]
}

func dialRaw(t *testing.T, h *harness, clock time.Time) *rawAgent {
	t.Helper()
	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := fleetpb.NewFleetClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), mdEnroll, testToken)
	caps := &fleetpb.Capabilities{AllowTargets: []string{"10.0.0.0/16"}, MaxLeases: 1}
	en, err := client.Enroll(ctx, &fleetpb.EnrollRequest{Protocol: Protocol, Name: "raw", Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(context.Background(), mdAuth, "Bearer "+en.AgentId+"."+en.Secret))
	t.Cleanup(cancel)
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Hello{Hello: &fleetpb.Hello{Protocol: Protocol, Capabilities: caps,
		AgentTimeUnixNano: clock.UnixNano()}}}); err != nil {
		t.Fatal(err)
	}
	r := &rawAgent{t: t, stream: stream}
	if r.recv().GetWelcome() == nil {
		t.Fatal("no welcome")
	}
	return r
}

func (r *rawAgent) recv() *fleetpb.ControllerMessage {
	r.t.Helper()
	m, err := r.stream.Recv()
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

func (r *rawAgent) result(lease string, seq uint64, recs ...*fleetpb.Record) {
	r.t.Helper()
	if err := r.stream.Send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Result{Result: &fleetpb.ResultBatch{LeaseId: lease, Seq: seq, Records: recs}}}); err != nil {
		r.t.Fatal(err)
	}
}

func record(t *testing.T, kind fleetpb.Record_Kind, v any) *fleetpb.Record {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return &fleetpb.Record{Kind: kind, Json: b}
}

func TestDuplicateDeliveryAndForeignTargets(t *testing.T) {
	h := newHarness(t, 5*time.Second)
	r := dialRaw(t, h, time.Now().Add(time.Hour))
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.3.1", "10.0.3.2"), JobOptions{MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	lease := r.recv().GetLease()
	if lease == nil || lease.JobId != job.ID {
		t.Fatalf("lease %+v", lease)
	}
	var req config.Request
	if err := json.Unmarshal(lease.RequestJson, &req); err != nil || len(req.Targets) != 1 || req.Targets[0] != "10.0.3.1-10.0.3.2" {
		t.Fatalf("lease request %+v %v", req, err)
	}
	now := time.Now()
	sc := observe.Scan{Schema: observe.SchemaVersion, Kind: observe.KindScan, ID: observe.NewScanID(now), Profile: "default", Started: now, Status: "running", Targets: 2}
	obs := observe.Observation{Schema: observe.SchemaVersion, Kind: observe.KindPort, ScanID: sc.ID, Timestamp: now,
		Target: netip.MustParseAddr("10.0.3.1"), Transport: "tcp", Port: 80, State: "open"}
	batch := []*fleetpb.Record{record(t, fleetpb.Record_BEGIN, sc), record(t, fleetpb.Record_OBSERVATION, obs)}
	r.result(lease.LeaseId, 1, batch...)
	if a := r.recv().GetAck(); a == nil || a.Seq != 1 || a.Done {
		t.Fatalf("ack %+v", a)
	}
	r.result(lease.LeaseId, 1, batch...) // resent after a lost ack
	if a := r.recv().GetAck(); a == nil || a.Seq != 1 {
		t.Fatalf("duplicate ack %+v", a)
	}
	if n := countObservations(t, h.store); n != 1 {
		t.Fatalf("duplicate stored: %d observations", n)
	}
	// An observation about an address outside the unit ends the lease.
	foreign := obs
	foreign.Target = netip.MustParseAddr("10.0.9.9")
	r.result(lease.LeaseId, 2, record(t, fleetpb.Record_OBSERVATION, foreign))
	if c := r.recv().GetCancel(); c == nil || c.LeaseId != lease.LeaseId {
		t.Fatalf("expected cancel, got %+v", c)
	}
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetFailed || countObservations(t, h.store) != 1 {
		t.Fatalf("job %+v", d.FleetJob)
	}
	agents, _ := h.ctrl.Agents(context.Background())
	if len(agents) != 1 || agents[0].Health != "clock-skew" {
		t.Fatalf("agents %+v", agents)
	}
}

func TestAuthentication(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := fleetpb.NewFleetClient(conn)
	bad := metadata.AppendToOutgoingContext(context.Background(), mdEnroll, "wrong-token-0123456789")
	if _, err := client.Enroll(bad, &fleetpb.EnrollRequest{Protocol: Protocol, Name: "x"}); err == nil {
		t.Fatal("enrolled with a wrong token")
	}
	good := metadata.AppendToOutgoingContext(context.Background(), mdEnroll, testToken)
	en, err := client.Enroll(good, &fleetpb.EnrollRequest{Protocol: Protocol, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	try := func(cred string) error {
		ctx := metadata.AppendToOutgoingContext(context.Background(), mdAuth, cred)
		s, err := client.Connect(ctx)
		if err != nil {
			return err
		}
		_ = s.Send(&fleetpb.AgentMessage{Msg: &fleetpb.AgentMessage_Hello{Hello: &fleetpb.Hello{Protocol: Protocol,
			Capabilities: &fleetpb.Capabilities{AllowTargets: []string{"10.0.0.0/8"}}}}})
		_, err = s.Recv()
		return err
	}
	if err := try("Bearer " + en.AgentId + ".wrong"); err == nil {
		t.Fatal("connected with a wrong secret")
	}
	if ok, err := h.ctrl.Revoke(context.Background(), en.AgentId); err != nil || !ok {
		t.Fatalf("revoke %v %v", ok, err)
	}
	if err := try("Bearer " + en.AgentId + "." + en.Secret); err == nil {
		t.Fatal("revoked agent connected")
	}
}

func agentCaps(t *testing.T, leases, rate uint32) *fleetpb.Capabilities {
	t.Helper()
	return &fleetpb.Capabilities{AllowTargets: []string{"10.0.0.0/8"}, MaxLeases: leases, MaxRate: rate}
}

// A controller restart while a lease runs: the agent reconnects, reports the
// lease, resends its unacknowledged batch, and the unit completes in its
// first attempt with every observation stored once.
func TestControllerRestartResumesLease(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	slow := func(o *pipeline.Options) {
		o.Discover = func(ctx context.Context, cfg config.Config, emit func(scan.Observation) error) error {
			var err error
			cfg.EachTarget(func(a netip.Addr) bool {
				time.Sleep(10 * time.Millisecond)
				err = emit(scan.Observation{Timestamp: time.Now(), Target: a, Transport: "tcp", Port: 80, State: "open", Probe: "tcp-connect"})
				return err == nil && ctx.Err() == nil
			})
			return err
		}
	}
	h.agent("steady", slow, nil)
	h.waitConnected(1)
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.4.0/25"), JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h.eventually(func() bool { return countObservations(t, h.store) > 20 }, "first results")
	h.restart()
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || d.Observations != 128 || len(d.Attempts) != 1 || d.Attempts[0].Status != storage.FleetCompleted {
		t.Fatalf("job %+v attempts %+v", d.FleetJob, d.Attempts)
	}
	if n := countObservations(t, h.store); n != 128 {
		t.Fatalf("stored %d observations, want 128", n)
	}
}

// An agent cut off from its controller for a whole lease TTL abandons the
// lease, because the controller has expired it and may run it elsewhere.
func TestAgentAbandonsLeasesWhenControllerSilent(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	a, err := NewAgent(AgentConfig{Controller: h.addr, IdentityFile: filepath.Join(h.dir, "lonely.json"), EnrollToken: testToken, Name: "lonely",
		AllowTargets: []string{"10.0.0.0/16"}, Log: log.New(io.Discard, "", 0), Pipeline: fakeDiscover(10, nil),
		Capabilities: func() *fleetpb.Capabilities {
			return &fleetpb.Capabilities{AllowTargets: []string{"10.0.0.0/16"}, MaxLeases: 1}
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	h.waitConnected(1)
	if _, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.6.0/24"), JobOptions{}); err != nil {
		t.Fatal(err)
	}
	leases := func() int { return len(a.leaseStates()) }
	h.eventually(func() bool { return leases() == 1 }, "lease running")
	h.srv.Stop() // the controller disappears without a goodbye
	h.ctrl.Close()
	start := time.Now()
	h.eventually(func() bool { return leases() == 0 }, "lease abandoned")
	if waited := time.Since(start); waited < 2*time.Second {
		t.Fatalf("abandoned after %s, before the lease TTL", waited)
	}
}

// A lease that streams nothing for longer than the TTL is healthy as long as
// heartbeats flow: the agent must not abandon it.
func TestQuietLeaseSurvivesBeyondTTL(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	quiet := func(o *pipeline.Options) {
		o.Discover = func(ctx context.Context, cfg config.Config, emit func(scan.Observation) error) error {
			select {
			case <-time.After(5 * time.Second): // longer than the TTL, no results
			case <-ctx.Done():
				return ctx.Err()
			}
			var err error
			cfg.EachTarget(func(a netip.Addr) bool {
				err = emit(scan.Observation{Timestamp: time.Now(), Target: a, Transport: "tcp", Port: 80, State: "open", Probe: "tcp-connect"})
				return err == nil
			})
			return err
		}
	}
	h.agent("quiet", quiet, nil)
	h.waitConnected(1)
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.7.1", "10.0.7.2"), JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || len(d.Attempts) != 1 || d.Observations != 2 {
		t.Fatalf("job %+v attempts %+v", d.FleetJob, d.Attempts)
	}
}

// One agent with one slot runs several units back to back; finishing a unit
// must never make the agent reject the next one.
func TestSingleSlotAgentRunsUnitsBackToBack(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	h.agent("solo", fakeDiscover(0, nil), nil)
	h.waitConnected(1)
	job, err := h.ctrl.Submit(context.Background(), connectRequest("10.0.8.0/22"), JobOptions{MaxParallel: 4})
	if err != nil {
		t.Fatal(err)
	}
	d := h.waitJob(job.ID)
	if d.Status != storage.FleetCompleted || len(d.Attempts) != 4 {
		t.Fatalf("job %+v attempts %+v", d.FleetJob, d.Attempts)
	}
	for _, a := range d.Attempts {
		if a.Status != storage.FleetCompleted {
			t.Fatalf("attempt %+v", a)
		}
	}
}

func TestRateBelowParallelismRefused(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	req := connectRequest("10.0.0.0/24")
	two := 2
	req.Rate = &two
	if _, err := h.ctrl.Submit(context.Background(), req, JobOptions{MaxParallel: 4}); err == nil {
		t.Fatal("accepted a global rate the leases cannot honor")
	}
}

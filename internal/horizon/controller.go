package horizon

import (
	"context"
	"errors"
	"sync"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetio"
)

var ErrStopped = errors.New("HORIZON executor kill switch is engaged")
var ErrBusy = errors.New("a HORIZON experiment is already running")

// Controller holds independent operator policy and a fixed transport factory.
// It admits one experiment at a time, bounds aggregate concurrency/rate/memory,
// and permanently cancels all work when Stop is called. Re-enable by constructing
// a new controller under operator control, never through an experiment request.
type Controller struct {
	mu           sync.Mutex
	policy       model.Policy
	link         Link
	open         func() (packetio.PacketIO, error)
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	done         chan struct{}
	activeCancel context.CancelFunc
}

func NewController(policy model.Policy, link Link, open func() (packetio.PacketIO, error)) *Controller {
	policy.AllowTargets = append([]string(nil), policy.AllowTargets...)
	policy.AllowPorts = append([]uint16(nil), policy.AllowPorts...)
	policy.Permissions = append([]string(nil), policy.Permissions...)
	link.SourceMAC = append([]byte(nil), link.SourceMAC...)
	link.NextHopMAC = append([]byte(nil), link.NextHopMAC...)
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{policy: policy, link: link, open: open, ctx: ctx, cancel: cancel}
}
func (c *Controller) Plan(e model.Experiment) (model.Plan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return model.Plan{}, ErrStopped
	}
	return dsl.Compile(e, c.policy)
}
func (c *Controller) Run(ctx context.Context, e model.Experiment) (model.Report, error) {
	// Compile before opening a backend. Run admits again at the actual boundary.
	if _, err := c.Plan(e); err != nil {
		return model.Report{}, err
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return model.Report{}, ErrStopped
	}
	if c.running {
		c.mu.Unlock()
		return model.Report{}, ErrBusy
	}
	if c.open == nil {
		c.mu.Unlock()
		return model.Report{}, errors.New("HORIZON transport is disabled")
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.activeCancel = cancel
	c.running = true
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.running = false; c.activeCancel = nil; close(done); c.mu.Unlock() }()

	defer cancel()
	if c.ctx.Err() != nil {
		return model.Report{}, ErrStopped
	}
	transport, err := c.open()
	if err != nil {
		return model.Report{}, err
	}
	defer transport.Close()
	return Run(runCtx, e, c.policy, c.link, transport)
}

// Stop is idempotent and rejects future plans/runs. In-flight receive, wait,
// rate gate and sends all receive cancellation through their context.
func (c *Controller) Stop() {
	c.mu.Lock()
	c.cancel()
	if c.activeCancel != nil {
		c.activeCancel()
	}
	c.mu.Unlock()
}
func (c *Controller) Close() {
	c.mu.Lock()
	c.cancel()
	if c.activeCancel != nil {
		c.activeCancel()
	}
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

package fleet

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet/fleetpb"
)

// Protocol is the fleet wire protocol version. Agents and controllers reject
// a different major version.
const Protocol = "nyxr-fleet/v1"

// ReasonLeaseLimit is the rejection an agent sends when it has no free slot;
// it says nothing about the unit, so the controller does not blacklist it.
const ReasonLeaseLimit = "agent is at its lease limit"

// Requirements are what a job needs from an agent. They are derived from the
// resolved request, never trusted from the client.
type Requirements struct {
	Raw     bool `json:"raw,omitempty"`          // TCP SYN, ARP or NDP
	ICMP    bool `json:"icmp,omitempty"`         // ICMP echo
	Capture bool `json:"capture,omitempty"`      // pcapng
	OT      bool `json:"ot,omitempty"`           // ot-safe profile
	Local   bool `json:"local_subnet,omitempty"` // ARP/NDP: targets on an attached subnet
}

func requirementsOf(r config.Resolved) Requirements {
	c := r.Config
	return Requirements{Raw: c.TCPMode == "syn" || c.ARP || c.NDP, ICMP: c.ICMP, Capture: r.PCAPNG != "",
		OT: c.Profile == "ot-safe", Local: c.ARP || c.NDP}
}

// JobOptions control partitioning and the global budget.
type JobOptions struct {
	// UnitSize is the most addresses per unit (default 256).
	UnitSize int `json:"unit_size,omitempty"`
	// MaxParallel bounds concurrently leased units; the request's global
	// rate and service rate are divided by it (default 4).
	MaxParallel int `json:"max_parallel,omitempty"`
	// MaxAttempts bounds leases per unit, including the first (default 3).
	MaxAttempts int `json:"max_attempts,omitempty"`
}

func (o *JobOptions) normalize() error {
	if o.UnitSize == 0 {
		o.UnitSize = 256
	}
	if o.MaxParallel == 0 {
		o.MaxParallel = 4
	}
	if o.MaxAttempts == 0 {
		o.MaxAttempts = 3
	}
	if o.UnitSize < 1 || o.UnitSize > 1<<20 || o.MaxParallel < 1 || o.MaxParallel > 4096 || o.MaxAttempts < 1 || o.MaxAttempts > 20 {
		return errors.New("unit_size 1..1048576, max_parallel 1..4096 and max_attempts 1..20 are required")
	}
	return nil
}

// jobPlan is the controller's validated view of a stored job.
type jobPlan struct {
	request     config.Request
	options     JobOptions
	needs       Requirements
	rate        int // resolved global packets/s
	serviceRate int // resolved global service connections/s; 0 when disabled
	subnetRate  int
}

// vantagePlaceholder satisfies interface validation on the controller. Raw
// scans use each agent's own interface; units never carry one.
const vantagePlaceholder = "fleet-agent"

// validateFleetRequest rejects fields that only make sense on one machine.
func validateFleetRequest(req config.Request) error {
	switch {
	case req.Interface != "" || req.SourceIP != "" || req.SourceMAC != "" || req.NextHopMAC != "" || req.XDPPinDir != "":
		return errors.New("interface, source and next-hop settings are vantage-specific; configure them on each agent")
	case req.KnownOpen:
		return errors.New("known_open rescans are not distributed yet; list the targets and ports explicitly")
	case req.Profile == "research":
		return errors.New("the research profile is CLI-only")
	}
	return nil
}

// resolveForController validates the request as an agent would. The
// placeholder interface stands in for each agent's own one, and it keeps
// Build from choosing an egress interface of the controller host.
func resolveForController(req config.Request) (config.Resolved, error) {
	if err := validateFleetRequest(req); err != nil {
		return config.Resolved{}, err
	}
	req.Interface = vantagePlaceholder
	return req.Resolve(config.ResolveOptions{Remote: true})
}

// agentView is what scheduling needs to know about a connected agent.
type agentView struct {
	id       string
	caps     *fleetpb.Capabilities
	scope    config.Scope // authorized vantage
	attached config.Scope // directly attached subnets
	leases   int
	limit    int
}

func newAgentView(id string, caps *fleetpb.Capabilities) (agentView, error) {
	v := agentView{id: id, caps: caps, limit: int(caps.GetMaxLeases())}
	if v.limit < 1 {
		v.limit = 1
	}
	if len(caps.GetAllowTargets()) == 0 {
		return v, errors.New("agent advertises no authorized targets")
	}
	scope, err := config.ParseScope(caps.GetAllowTargets())
	if err != nil {
		return v, fmt.Errorf("agent scope: %w", err)
	}
	v.scope = scope
	var prefixes []string
	for _, ifc := range caps.GetInterfaces() {
		prefixes = append(prefixes, ifc.GetPrefixes()...)
	}
	if v.attached, err = config.ParseScope(prefixes); err != nil {
		return v, fmt.Errorf("agent interfaces: %w", err)
	}
	return v, nil
}

// eligible reports whether the agent may run a unit, and why not.
func (v agentView) eligible(needs Requirements, runs []addrRun) (bool, string) {
	c := v.caps
	switch {
	case v.leases >= v.limit:
		return false, "agent is at its lease limit"
	case needs.Raw && !c.GetRawSocket():
		return false, "raw packet I/O unavailable"
	case needs.ICMP && !c.GetIcmp():
		return false, "ICMP unavailable"
	case needs.Capture && !c.GetCapture():
		return false, "packet capture unavailable"
	case needs.OT && !c.GetOt():
		return false, "ot-safe profile not permitted by the agent operator"
	}
	for _, r := range runs {
		if r.first.Is6() && !c.GetIpv6() {
			return false, "IPv6 unavailable"
		}
		if !v.scope.Covers(r.first, r.last) {
			return false, "targets outside the agent's authorized vantage"
		}
		if needs.Local && v.attached.Empty() || needs.Local && !v.attached.Covers(r.first, r.last) {
			return false, "targets not on an attached subnet"
		}
	}
	return true, ""
}

// leaseRequest restricts the job request to one unit and its budget share.
// The global rate is divided by MaxParallel and then capped by the agent's
// own per-lease budget, so the sum of all leases never exceeds either.
func leaseRequest(p jobPlan, u []string, subnetShare int, caps *fleetpb.Capabilities) config.Request {
	req := p.request
	req.Targets = append([]string(nil), u...)
	limit := max(int(caps.GetMaxLeases()), 1)
	share := func(global, agentMax int) *int {
		n := global
		if n > 0 {
			n = max(n/p.options.MaxParallel, 1)
		}
		if agentMax > 0 {
			per := max(agentMax/limit, 1)
			if n == 0 || n > per {
				n = per
			}
		}
		if n == 0 {
			return nil
		}
		return &n
	}
	req.Rate = share(p.rate, int(caps.GetMaxRate()))
	if p.serviceRate > 0 || caps.GetMaxServiceRate() > 0 {
		if p.serviceRate > 0 || req.Service != nil && *req.Service {
			req.ServiceRate = share(p.serviceRate, int(caps.GetMaxServiceRate()))
		}
	}
	if p.subnetRate > 0 && subnetShare > 1 {
		n := max(p.subnetRate/subnetShare, 1)
		req.SubnetRate = &n
	}
	return req
}

// targetsCovered reports whether every resolved target lies in runs.
func targetsCovered(cfg config.Config, runs []addrRun) (netip.Addr, bool) {
	bad, ok := netip.Addr{}, true
	cfg.EachTarget(func(a netip.Addr) bool {
		if !runsContain(runs, a) {
			bad, ok = a, false
			return false
		}
		return true
	})
	return bad, ok
}

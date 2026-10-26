package service

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// protocolMachine is a bounded protocol conversation. Its implementation may
// branch (ALPN, STARTTLS, DSL steps), but returns only a parser-validated match
// and retains every exchange. A fresh adapter is made per target; planner
// state is never shared between workers.
type protocolMachine interface {
	Execute(context.Context, Target, *observe.Observation) bool
}

type probeFunc func(context.Context, Target, *observe.Observation) bool

func (f probeFunc) Execute(ctx context.Context, t Target, o *observe.Observation) bool {
	return f(ctx, t, o)
}

// executeProbe is the common execution boundary for native and declarative
// machines. Scheduling, inference and transcripts stay outside the parsers.
// Parsers read hostile input, so a panic in one is contained here: the
// partial claim is rolled back, its exchanges are kept, and the panic is
// recorded as a probe error instead of terminating the process.
func (e *Engine) executeProbe(ctx context.Context, t Target, name string, redisHint bool, o *observe.Observation) (matched bool) {
	if ctx.Err() != nil {
		return false
	}
	var machine protocolMachine
	switch name {
	case ProbeTLS:
		machine = probeFunc(e.probeTLS)
	case ProbeHTTP:
		machine = probeFunc(func(ctx context.Context, t Target, o *observe.Observation) bool {
			ev, matched := e.probeHTTP(ctx, t, nil, "tcp", o)
			o.Evidence = append(o.Evidence, ev)
			return matched
		})
	case ProbeDNS:
		machine = probeFunc(e.probeDNS)
	case ProbeSOCKS:
		machine = probeFunc(e.probeSOCKS)
	case ProbeModbus:
		machine = probeFunc(e.probeModbus)
	case ProbeEtherNetIP:
		machine = probeFunc(e.probeEtherNetIP)
	case ProbeS7:
		machine = probeFunc(e.probeS7)
	case ProbeOPCUA:
		machine = probeFunc(e.probeOPCUA)
	case ProbeDatabase:
		machine = probeFunc(func(ctx context.Context, t Target, o *observe.Observation) bool {
			return e.probeDatabase(ctx, t, o, redisHint)
		})
	case ProbeSMB:
		machine = probeFunc(e.probeSMB)
	case ProbeRDP:
		machine = probeFunc(e.probeRDP)
	case ProbeMSRPC:
		machine = probeFunc(e.probeMSRPC)
	case ProbeLDAP:
		machine = probeFunc(e.probeLDAP)
	case ProbeKerberos:
		machine = probeFunc(e.probeKerberos)
	case ProbeNFS:
		machine = probeFunc(e.probeNFS)
	case ProbeQUIC:
		machine = probeFunc(e.probeQUIC)
	case ProbeDTLS:
		machine = probeFunc(e.probeDTLS)
	default:
		for _, d := range e.cfg.Definitions {
			if name == "dsl/"+d.Name {
				machine = probeFunc(func(ctx context.Context, t Target, o *observe.Observation) bool {
					return e.probeProtocol(ctx, t, d, o)
				})
				break
			}
		}
	}
	if machine == nil {
		return false
	}
	saved := *o
	saved.Attributes, saved.Fields = maps.Clone(o.Attributes), maps.Clone(o.Fields)
	defer func() {
		if r := recover(); r != nil {
			evidence := o.Evidence
			*o = saved
			o.Evidence = append(evidence, observe.Evidence{Probe: name, Started: time.Now().UTC(), Error: fmt.Sprintf("probe panic: %v", r)})
			matched = false
		}
	}()
	return machine.Execute(ctx, t, o)
}

func (e *Engine) probeBudget(o *observe.Observation) bool {
	limit := e.cfg.MaxProbes
	if limit == 0 {
		limit = 32
	}
	steps := 0
	for _, d := range o.ProbeDecisions {
		if d.Probe != ProbeDatabase { // composite planner, no wire exchange
			steps++
		}
	}
	if steps >= limit {
		o.ProbeStopReason = "probe budget exhausted"
		return false
	}
	return true
}

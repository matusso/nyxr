package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/storage"
)

// optionalBool distinguishes an absent flag from an explicit false.
type optionalBool struct{ value *bool }

func (b *optionalBool) String() string {
	if b == nil || b.value == nil {
		return ""
	}
	return strconv.FormatBool(*b.value)
}

func (b *optionalBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.value = &v
	return nil
}

func (b *optionalBool) IsBoolFlag() bool { return true }

// stageFlags are the scan flags for Phase 3 stages: deep service probes,
// packet evidence and storage.
type stageFlags struct {
	service         optionalBool
	serviceProbes   *string
	serviceFallback *string
	serviceTimeout  *time.Duration
	serviceWorkers  *int
	serviceRate     *int
	pcapng          *string
	pcapngMaxMB     *int
	db              *string
}

func addStageFlags(fs *flag.FlagSet) *stageFlags {
	s := &stageFlags{}
	fs.Var(&s.service, "service", "run deep service probes on open TCP ports")
	s.serviceProbes = fs.String("service-probes", "", "comma list of banner, ssh, tls, http, dns")
	s.serviceFallback = fs.String("service-fallback", "", "probes for unhinted silent ports, or none")
	s.serviceTimeout = fs.Duration("service-timeout", 0, "upper bound for each service probe")
	s.serviceWorkers = fs.Int("service-workers", -1, "concurrent service probe workers")
	s.serviceRate = fs.Int("service-rate", -1, "new service connections per second (0 unlimited)")
	s.pcapng = fs.String("pcapng", "", "write packet evidence to this pcapng file")
	s.pcapngMaxMB = fs.Int("pcapng-max-mb", 1024, "pcapng size budget in MiB")
	s.db = fs.String("db", "", "store results in this SQLite database")
	return s
}

func (s *stageFlags) serviceOptions() (config.ServiceOptions, error) {
	if *s.serviceWorkers < -1 || *s.serviceRate < -1 || *s.serviceTimeout < 0 {
		return config.ServiceOptions{}, errors.New("service workers, rate and timeout must be nonnegative")
	}
	o := config.ServiceOptions{
		Enable: s.service.value, Probes: *s.serviceProbes, Fallback: *s.serviceFallback,
		Timeout: timeoutText(*s.serviceTimeout),
	}
	if *s.serviceWorkers >= 0 {
		o.Workers = s.serviceWorkers
	}
	if *s.serviceRate >= 0 {
		o.Rate = s.serviceRate
	}
	return o, nil
}

// usesPipeline reports whether a Phase 3 stage is active.
func (s *stageFlags) usesPipeline(svc config.Service) bool {
	return svc.Enabled || *s.pcapng != "" || *s.db != ""
}

func emitStagePlan(out io.Writer, plan config.Plan, svc config.Service, stages *stageFlags, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(out).Encode(struct {
			config.Plan
			Service *config.ServicePlan `json:"service,omitempty"`
			PCAPNG  string              `json:"pcapng,omitempty"`
			DB      string              `json:"db,omitempty"`
		}{plan, svc.Plan(), *stages.pcapng, *stages.db})
	}
	if err := emitPlan(out, plan, false); err != nil {
		return err
	}
	if p := svc.Plan(); p != nil {
		fallback := "none"
		if len(p.Fallback) > 0 {
			fallback = strings.Join(p.Fallback, ", ")
		}
		fmt.Fprintf(out, "service     %s (fallback %s)\n", strings.Join(p.Probes, ", "), fallback)
		fmt.Fprintf(out, "svc-timeout %s, %d workers, %s\n", p.Timeout, p.Workers, rateText(p.Rate))
	}
	if *stages.pcapng != "" {
		fmt.Fprintf(out, "pcapng      %s (max %d MiB)\n", *stages.pcapng, *stages.pcapngMaxMB)
	}
	if *stages.db != "" {
		fmt.Fprintf(out, "db          %s\n", *stages.db)
	}
	return nil
}

func runPipeline(out io.Writer, cfg config.Config, svc config.Service, stages *stageFlags, asJSON bool) error {
	ctx := context.Background()
	opts := pipeline.Options{Service: svc}
	if asJSON {
		opts.Sinks = append(opts.Sinks, pipeline.NewJSONSink(out))
	} else {
		opts.Sinks = append(opts.Sinks, pipeline.NewTextSink(out))
	}
	if *stages.pcapng != "" {
		if *stages.pcapngMaxMB < 1 {
			return errors.New("pcapng size budget must be at least 1 MiB")
		}
		opts.Capture = &pipeline.CaptureOptions{Path: *stages.pcapng, Interface: cfg.Interface, MaxBytes: int64(*stages.pcapngMaxMB) << 20}
	}
	if *stages.db != "" {
		store, err := storage.Open(ctx, *stages.db)
		if err != nil {
			return err
		}
		defer store.Close()
		opts.Sinks = append(opts.Sinks, pipeline.NewStoreSink(ctx, store))
	}
	_, err := pipeline.Run(ctx, cfg, opts)
	return err
}

func historyUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr history --db file [flags]

Without a selector, list stored scans (newest first).

Flags:
  --db file            SQLite database written by nyxr scan --db
  --scan id            print the observations and packet evidence of one scan
  --assets             print every address with the latest state of each port
  --unknown            print service observations with an unknown fingerprint
  --address ip         restrict --scan or --unknown to one address
  --limit int          maximum scans or observations (default 50)
  --prune-older-than   delete scans older than this duration (e.g. 720h)
  --keep int           delete all but the newest N scans
  --json               JSON output
`)
}

func runHistory(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { historyUsage(out) }
	dbFlag := fs.String("db", "", "SQLite database")
	scanFlag := fs.String("scan", "", "scan ID")
	assetsFlag := fs.Bool("assets", false, "list assets")
	unknownFlag := fs.Bool("unknown", false, "list unknown fingerprints")
	addressFlag := fs.String("address", "", "restrict to one address")
	limitFlag := fs.Int("limit", 50, "maximum rows")
	olderFlag := fs.Duration("prune-older-than", 0, "delete scans older than this")
	keepFlag := fs.Int("keep", 0, "keep only the newest N scans")
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			historyUsage(out)
		}
		return err
	}
	if *dbFlag == "" || fs.NArg() != 0 {
		return errors.New("history requires --db and no positional arguments")
	}
	var addr netip.Addr
	if *addressFlag != "" {
		var err error
		if addr, err = netip.ParseAddr(*addressFlag); err != nil {
			return fmt.Errorf("address: %w", err)
		}
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, *dbFlag)
	if err != nil {
		return err
	}
	defer store.Close()
	enc := json.NewEncoder(out)

	switch {
	case *olderFlag != 0 || *keepFlag != 0:
		n, err := store.Prune(ctx, storage.Retention{OlderThan: *olderFlag, KeepLast: *keepFlag}, time.Now())
		if err != nil {
			return err
		}
		if *jsonFlag {
			return enc.Encode(map[string]int{"deleted_scans": n})
		}
		_, err = fmt.Fprintf(out, "deleted %d scans\n", n)
		return err
	case *assetsFlag:
		assets, err := store.Assets(ctx)
		if err != nil {
			return err
		}
		if *jsonFlag {
			for _, a := range assets {
				if err := enc.Encode(a); err != nil {
					return err
				}
			}
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ADDRESS\tPORT\tSTATE\tSERVICE\tPRODUCT\tLAST SEEN")
		for _, a := range assets {
			if len(a.Ports) == 0 {
				fmt.Fprintf(w, "%s\t-\t-\t-\t-\t%s\n", a.Address, a.LastSeen.Format(time.RFC3339))
			}
			for _, p := range a.Ports {
				fmt.Fprintf(w, "%s\t%d/%s\t%s\t%s\t%s\t%s\n", a.Address, p.Port, p.Transport, p.State, dash(p.Service),
					dash(strings.TrimSpace(p.Product+" "+p.Version)), p.ObservedAt.Format(time.RFC3339))
			}
		}
		return w.Flush()
	case *scanFlag != "" || *unknownFlag:
		filter := storage.Filter{ScanID: *scanFlag, Address: addr, Unknown: *unknownFlag, Limit: *limitFlag}
		if *unknownFlag {
			filter.Kind = observe.KindService
		}
		observations, err := store.Observations(ctx, filter)
		if err != nil {
			return err
		}
		var sink pipeline.Sink = pipeline.NewTextSink(out)
		if *jsonFlag {
			sink = pipeline.NewJSONSink(out)
		}
		for _, o := range observations {
			if err := sink.Observation(o); err != nil {
				return err
			}
		}
		if *scanFlag == "" {
			return nil
		}
		evidence, err := store.PacketEvidence(ctx, *scanFlag, addr)
		if err != nil {
			return err
		}
		for _, pe := range evidence {
			if err := sink.PacketEvidence(pe); err != nil {
				return err
			}
		}
		return nil
	default:
		scans, err := store.Scans(ctx, *limitFlag)
		if err != nil {
			return err
		}
		if *jsonFlag {
			for _, s := range scans {
				if err := enc.Encode(s); err != nil {
					return err
				}
			}
			return nil
		}
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SCAN\tPROFILE\tSTARTED\tSTATUS\tTARGETS\tOBSERVATIONS\tSERVICES")
		for _, s := range scans {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n", s.ID, s.Profile, s.Started.Format(time.RFC3339), s.Status, s.Targets, s.Observations, s.Services)
		}
		return w.Flush()
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

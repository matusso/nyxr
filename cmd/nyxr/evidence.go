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
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/storage"
	"github.com/matusso/nyxr/internal/ui"
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
	service             optionalBool
	serviceProbes       *string
	serviceFallback     *string
	serviceTimeout      *time.Duration
	serviceWorkers      *int
	serviceRate         *int
	nmapProbes          *string
	protocolDefinitions *string
	nseScripts          *string
	nseTimeout          *time.Duration
	pcapng              *string
	pcapngMaxMB         *int
	db                  dbFlags
	fingerprint         *bool
}

func addStageFlags(fs *flag.FlagSet) *stageFlags {
	s := &stageFlags{}
	fs.Var(&s.service, "service", "run deep service probes on open TCP ports")
	s.serviceProbes = fs.String("service-probes", "", "comma list of banner, ssh, tls, http, dns, socks, modbus, ethernetip, database")
	s.serviceFallback = fs.String("service-fallback", "", "probes for unhinted silent ports, or none")
	s.serviceTimeout = fs.Duration("service-timeout", 0, "upper bound for each service probe")
	s.serviceWorkers = fs.Int("service-workers", -1, "concurrent service probe workers")
	s.serviceRate = fs.Int("service-rate", -1, "new service connections per second (0 unlimited)")
	s.nmapProbes = fs.String("nmap-service-probes", "", "import this nmap-service-probes file for banner matching")
	s.protocolDefinitions = fs.String("protocol-definitions", "", "comma-separated local Nyxr Protocol DSL files")
	s.nseScripts = fs.String("nse-scripts", "", "comma list of installed safe Nmap NSE scripts")
	s.nseTimeout = fs.Duration("nse-timeout", 0, "maximum Nmap NSE execution time per host (default 30s)")
	s.pcapng = fs.String("pcapng", "", "write packet evidence to this pcapng file")
	s.pcapngMaxMB = fs.Int("pcapng-max-mb", -1, "pcapng size budget in MiB (default 1024)")
	s.db = dbFlags{
		path: fs.String("db", "", "store results in this SQLite database (default ~/.nyxr/nyxr.db)"),
		off:  fs.Bool("no-db", false, "do not store results"),
	}
	s.fingerprint = fs.Bool("fingerprint", false, "classify devices from independent observations")
	return s
}

// overlay applies explicitly set stage flags to the request.
func (s *stageFlags) overlay(r *config.Request) error {
	if *s.serviceWorkers < -1 || *s.serviceRate < -1 || *s.serviceTimeout < 0 || *s.nseTimeout < 0 || *s.pcapngMaxMB < -1 {
		return errors.New("service workers, rate, timeout and pcapng size must be nonnegative")
	}
	if s.service.value != nil {
		r.Service = s.service.value
	}
	r.ServiceProbes = first(*s.serviceProbes, r.ServiceProbes)
	r.ServiceFallback = first(*s.serviceFallback, r.ServiceFallback)
	r.ServiceTimeout = first(timeoutText(*s.serviceTimeout), r.ServiceTimeout)
	r.ServiceWorkers = mergeInt(*s.serviceWorkers, r.ServiceWorkers)
	r.ServiceRate = mergeInt(*s.serviceRate, r.ServiceRate)
	r.NmapServiceProbes = first(*s.nmapProbes, r.NmapServiceProbes)
	r.ProtocolDefinitions = first(*s.protocolDefinitions, r.ProtocolDefinitions)
	r.NSEScripts = first(*s.nseScripts, r.NSEScripts)
	r.NSETimeout = first(timeoutText(*s.nseTimeout), r.NSETimeout)
	r.PCAPNG = first(*s.pcapng, r.PCAPNG)
	r.PCAPNGMaxMB = mergeInt(*s.pcapngMaxMB, r.PCAPNGMaxMB)
	r.Fingerprint = r.Fingerprint || *s.fingerprint
	return nil
}

func emitStagePlan(out io.Writer, r config.Resolved, db string, asJSON bool, style *ui.Styler) error {
	plan := r.Plan()
	plan.DB = db
	if asJSON {
		return json.NewEncoder(out).Encode(plan)
	}
	if err := emitPlan(out, plan.Plan, false, style); err != nil {
		return err
	}
	key := func(k string) string { return style.Key(fmt.Sprintf("%-11s", k)) + " " }
	if p := plan.Service; p != nil {
		fallback := "none"
		if len(p.Fallback) > 0 {
			fallback = strings.Join(p.Fallback, ", ")
		}
		fmt.Fprintf(out, "%s%s %s\n", key("service"), strings.Join(p.Probes, ", "), style.Dim("(fallback "+fallback+")"))
		fmt.Fprintf(out, "%s%s\n", key("svc-timeout"), style.Dim(fmt.Sprintf("%s, %d workers, %s", p.Timeout, p.Workers, rateText(p.Rate))))
		if p.NmapProbes != "" {
			fmt.Fprintf(out, "%s%s\n", key("nmap-probes"), p.NmapProbes)
		}
		if len(p.ProtocolDefinitions) > 0 {
			fmt.Fprintf(out, "%s%s\n", key("protocol DSL"), strings.Join(p.ProtocolDefinitions, ", "))
		}
	}
	if p := plan.NSE; p != nil {
		fmt.Fprintf(out, "%s%s %s\n", key("nse"), strings.Join(p.Scripts, ", "), style.Dim("(safe; "+p.Timeout+" per host)"))
	}
	if plan.PCAPNG != "" {
		fmt.Fprintf(out, "%s%s %s\n", key("pcapng"), plan.PCAPNG, style.Dim(fmt.Sprintf("(max %d MiB)", plan.PCAPNGMaxMB)))
	}
	if db != "" {
		fmt.Fprintf(out, "%s%s\n", key("db"), db)
	}
	if plan.Fingerprint {
		fmt.Fprintf(out, "%s%s\n", key("fingerprint"), style.Green("enabled"))
	}
	if plan.KnownOpen {
		fmt.Fprintf(out, "%s%s\n", key("known-open"), style.Dim("only ports the database last saw open"))
	}
	return nil
}

// runPipeline uses pipeline.FromResolved, the mapping the API also uses.
func runPipeline(out io.Writer, r config.Resolved, db string, open packetio.Opener, asJSON, openOnly bool, style *ui.Styler, tally *scanTally) error {
	ctx := context.Background()
	opts := pipeline.FromResolved(r)
	opts.OpenLive = open
	opts.Sinks = append(opts.Sinks, progressSink{tally})
	if f := r.Service.NmapProbesFile; f != "" {
		nm, err := nmapdb.LoadFile(f)
		if err != nil {
			return fmt.Errorf("nmap-service-probes: %w", err)
		}
		opts.Nmap = nm
	}
	var display pipeline.Sink = pipeline.NewTextSink(out).WithStyle(style)
	if asJSON {
		display = pipeline.NewJSONSink(out)
	}
	if openOnly {
		display = pipeline.NewOpenOnlySink(display)
	}
	opts.Sinks = append(opts.Sinks, display)
	if db != "" {
		store, err := openStore(ctx, db)
		if err != nil {
			return err
		}
		defer store.Close()
		opts.Sinks = append(opts.Sinks, pipeline.NewStoreSink(ctx, store))
	}
	_, err := pipeline.Run(ctx, r.Config, opts)
	return err
}

func historyUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr history [--db file] [flags]

Without a selector, list stored scans (newest first).

Flags:
  --db file            SQLite database written by nyxr scan (default ~/.nyxr/nyxr.db)
  --scan id            print the observations and packet evidence of one scan
  --assets             print every address with the latest state of each port
  --open               with --assets, keep only open ports (and hosts that have one)
  --scope list         with --assets, keep addresses in these IPs, CIDRs or ranges
  --unknown            print service observations with an unknown fingerprint
  --address ip         restrict --scan or --unknown to one address
  --limit int          maximum scans or observations (default 50)
  --prune-older-than   delete scans older than this duration (e.g. 720h)
  --keep int           delete all but the newest N scans
  --json               JSON output
`)
}

func runHistory(args []string, out io.Writer, style *ui.Styler) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { historyUsage(out) }
	dbFlag := dbFlags{path: fs.String("db", "", "SQLite database")}
	scanFlag := fs.String("scan", "", "scan ID")
	assetsFlag := fs.Bool("assets", false, "list assets")
	openFlag := fs.Bool("open", false, "only open ports")
	scopeFlag := fs.String("scope", "", "IPs, CIDRs or ranges")
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
	if fs.NArg() != 0 {
		return errors.New("history takes no positional arguments")
	}
	dbPath, err := dbFlag.resolve()
	if err != nil {
		return err
	}
	var addr netip.Addr
	if *addressFlag != "" {
		var err error
		if addr, err = netip.ParseAddr(*addressFlag); err != nil {
			return fmt.Errorf("address: %w", err)
		}
	}
	ctx := context.Background()
	store, err := openStore(ctx, dbPath)
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
		_, err = fmt.Fprintf(out, "deleted %s scans\n", style.Bold(fmt.Sprintf("%d", n)))
		return err
	case *assetsFlag:
		scope, err := config.ParseScope([]string{*scopeFlag})
		if err != nil {
			return err
		}
		assets, err := store.Assets(ctx)
		if err != nil {
			return err
		}
		if *openFlag {
			assets = storage.OpenOnly(assets)
		}
		kept := assets[:0]
		for _, a := range assets {
			if scope.Contains(a.Address) {
				kept = append(kept, a)
			}
		}
		assets = kept
		if *jsonFlag {
			for _, a := range assets {
				if err := enc.Encode(a); err != nil {
					return err
				}
			}
			return nil
		}
		rows := [][]string{header(style, "ADDRESS", "PORT", "STATE", "SERVICE", "PRODUCT", "LAST SEEN")}
		for _, a := range assets {
			seen := style.Dim(a.LastSeen.Format(time.RFC3339))
			if len(a.Ports) == 0 {
				rows = append(rows, []string{style.Bold(a.Address.String()), "-", "-", "-", "-", seen})
			}
			for _, p := range a.Ports {
				rows = append(rows, []string{
					style.Bold(a.Address.String()),
					style.Cyan(fmt.Sprintf("%d/%s", p.Port, p.Transport)),
					style.StateText(p.State),
					dash(p.Service),
					dash(strings.TrimSpace(p.Product + " " + p.Version)),
					style.Dim(p.ObservedAt.Format(time.RFC3339)),
				})
			}
		}
		return style.Table(out, rows)
	case *scanFlag != "" || *unknownFlag:
		filter := storage.Filter{ScanID: *scanFlag, Address: addr, Unknown: *unknownFlag, Limit: *limitFlag}
		if *unknownFlag {
			filter.Kind = observe.KindService
		}
		observations, err := store.Observations(ctx, filter)
		if err != nil {
			return err
		}
		var sink pipeline.Sink = pipeline.NewTextSink(out).WithStyle(style)
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
		rows := [][]string{header(style, "SCAN", "PROFILE", "STARTED", "STATUS", "TARGETS", "OBSERVATIONS", "SERVICES")}
		for _, s := range scans {
			rows = append(rows, []string{
				style.Bold(s.ID),
				s.Profile,
				style.Dim(s.Started.Format(time.RFC3339)),
				statusText(style, s.Status),
				fmt.Sprintf("%d", s.Targets),
				fmt.Sprintf("%d", s.Observations),
				fmt.Sprintf("%d", s.Services),
			})
		}
		return style.Table(out, rows)
	}
}

// header styles a table header row.
func header(style *ui.Styler, cells ...string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = style.Header(c)
	}
	return out
}

// statusText colors a stored scan's status: green completed, red failed,
// yellow running.
func statusText(style *ui.Styler, status string) string {
	switch status {
	case "completed":
		return style.Green(status)
	case "failed":
		return style.Red(status)
	case "running":
		return style.Yellow(status)
	default:
		return status
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// progressSink counts one task per discovery result; service and device
// records are follow-up work on results already counted.
type progressSink struct{ tally *scanTally }

func (s progressSink) Begin(observe.Scan) error                    { return nil }
func (s progressSink) PacketEvidence(observe.PacketEvidence) error { return nil }
func (s progressSink) Finish(observe.Scan) error                   { return nil }

func (s progressSink) Observation(o observe.Observation) error {
	if o.Kind == observe.KindHost || o.Kind == observe.KindPort {
		s.tally.Step(o.State == "open" || o.State == "responsive")
	}
	return nil
}

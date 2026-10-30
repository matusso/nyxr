package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/service"
	"github.com/matusso/nyxr/internal/storage"
	"github.com/matusso/nyxr/internal/ui"
)

func evidenceUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr evidence show [--db file] [--frames] [--json] observation-id

Navigate one stored claim to the retained exchanges and planner decisions that
support it, and to the exact indexed pcapng packets of its flow. Missing,
truncated or dropped capture evidence is reported, never hidden. Observation
IDs (<scan_id>/<n>, or store:<namespace>/<n>) are the observation_id values
printed by "nyxr history --scan id --json".

Flags:
  --db file    SQLite database (default ~/.nyxr/nyxr.db)
  --frames     also print the indexed frames as hex, read from the capture
               after checking it is still the recorded artifact
  --json       print the nyxr/evidence-trace/v1 record
`)
}

func runEvidence(args []string, out io.Writer, style *ui.Styler) error {
	if len(args) == 0 || args[0] != "show" {
		evidenceUsage(out)
		if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
			return nil
		}
		return errors.New("evidence requires the show subcommand")
	}
	fs := flag.NewFlagSet("evidence show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { evidenceUsage(out) }
	db := dbFlags{path: fs.String("db", "", "SQLite database")}
	framesFlag := fs.Bool("frames", false, "print indexed frames")
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("evidence show requires one observation ID")
	}
	path, err := db.resolve()
	if err != nil {
		return err
	}
	ctx := context.Background()
	store, err := openStore(ctx, path)
	if err != nil {
		return err
	}
	defer store.Close()
	trace, ok, err := store.Trace(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("observation not found in this store")
	}
	var frames map[uint64]capture.Record
	var frameErr error
	if *framesFlag {
		frames, frameErr = traceFrames(ctx, store, trace)
	}
	if *jsonFlag {
		if frameErr != nil {
			return frameErr
		}
		if frames == nil {
			return json.NewEncoder(out).Encode(trace)
		}
		type jsonFrame struct {
			ID  uint64 `json:"id"`
			Hex string `json:"hex"`
		}
		var list []jsonFrame
		for _, p := range trace.Capture.Packets {
			if rec, ok := frames[p.ID]; ok {
				list = append(list, jsonFrame{p.ID, hex.EncodeToString(rec.Data)})
			}
		}
		return json.NewEncoder(out).Encode(struct {
			storage.EvidenceTrace
			Frames []jsonFrame `json:"frames"`
		}{trace, list})
	}
	printTrace(out, style, trace, frames)
	if frameErr != nil {
		fmt.Fprintf(out, "%s %s\n", style.Key("frames"), style.Red(frameErr.Error()))
	}
	return nil
}

// traceFrames reads the flow's indexed frames from the stored capture path
// only after the file is verified as the recorded artifact.
func traceFrames(ctx context.Context, store *storage.Store, t storage.EvidenceTrace) (map[uint64]capture.Record, error) {
	if len(t.Capture.Packets) == 0 {
		return nil, errors.New("no indexed packets to read")
	}
	sc, ok, err := store.Scan(ctx, t.Observation.ScanID)
	if err != nil || !ok || sc.Capture == nil {
		return nil, errors.New("capture summary is not retained")
	}
	f, _, err := capture.OpenVerified(sc.Capture.Path, sc.Capture.Bytes, sc.Capture.ArtifactID)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ids []uint64
	for _, p := range t.Capture.Packets[:min(len(t.Capture.Packets), capture.MaxFrameLookup)] {
		ids = append(ids, p.ID)
	}
	return capture.ReadPackets(f, ids)
}

func printTrace(out io.Writer, style *ui.Styler, t storage.EvidenceTrace, frames map[uint64]capture.Record) {
	o := t.Observation
	key := func(k string) string { return style.Key(fmt.Sprintf("%-12s", k)) + " " }
	claim := o.Kind
	if o.Service != "" {
		claim += " " + o.Service
	}
	fmt.Fprintf(out, "%s%s\n", key("observation"), style.Bold(o.ID))
	fmt.Fprintf(out, "%s%s %s/%d %s\n", key("claim"), claim, o.Transport, o.Port, style.Dim(o.Target.String()))
	fmt.Fprintf(out, "%s%s, %d/100 %s, %s\n", key("status"), o.ClaimStatus, o.Confidence, o.ConfidenceMethod, o.Reason)
	if o.Source != nil {
		fmt.Fprintf(out, "%s%s %s\n", key("source"), o.Source.ArtifactID, style.Dim("scan "+o.ScanID))
	}
	if len(o.ProbeUpdates) > 0 {
		fmt.Fprintf(out, "\n%s\n", style.Header("DECISIONS"))
		for i, u := range o.ProbeUpdates {
			leading := ""
			if len(u.After) > 0 {
				leading = fmt.Sprintf(" → %s %.1f%%", u.After[0].Family, 100*u.After[0].Probability)
			}
			fmt.Fprintf(out, "  #%d %s %s%s %s\n", i, u.Probe, u.Outcome, leading, style.Dim(fmt.Sprintf("exchanges [%d, %d)", u.EvidenceStart, u.EvidenceEnd)))
		}
	}
	fmt.Fprintf(out, "\n%s\n", style.Header("EXCHANGES"))
	if len(t.Exchanges) == 0 {
		fmt.Fprintln(out, "  none retained")
	}
	for _, x := range t.Exchanges {
		matched := x.Matched
		if matched == "" {
			matched = "unmatched"
		}
		fmt.Fprintf(out, "  [%d] %s %s %s, completeness %s, request %d B, response %d B", x.Index, x.Probe, x.Layer, matched, x.Completeness, x.RequestBytes, x.ResponseBytes)
		if x.Truncated {
			fmt.Fprint(out, style.Yellow(" truncated"))
		}
		if x.Error != "" {
			fmt.Fprint(out, style.Red(" error: "+x.Error))
		}
		fmt.Fprintln(out)
		if len(x.Decisions) > 0 {
			fmt.Fprintf(out, "      decisions %s\n", joinIDs(x.Decisions))
		}
		if len(x.Packets) > 0 {
			fmt.Fprintf(out, "      packets %s %s\n", joinIDs(x.Packets), style.Dim("(by time window)"))
		}
	}
	c := t.Capture
	fmt.Fprintf(out, "\n%s %s\n", style.Header("PACKETS"), captureStatus(style, c.Status))
	for _, r := range c.Reasons {
		fmt.Fprintf(out, "  %s %s\n", style.Yellow("!"), r)
	}
	if c.Capture != "" {
		fmt.Fprintf(out, "  %s %s\n", c.Capture, style.Dim(c.CaptureArtifactID))
	}
	for _, p := range c.Packets {
		fmt.Fprintf(out, "  #%d %s %s %d B %s\n", p.ID, style.Dim(p.Timestamp.Format(time.RFC3339Nano)), p.Direction, p.Length, p.Summary)
		if rec, ok := frames[p.ID]; ok {
			fmt.Fprintf(out, "      %s\n", hex.EncodeToString(rec.Data))
		}
	}
	if len(t.Runs) > 0 {
		fmt.Fprintf(out, "\n%s\n", style.Header("REPLAYS"))
		for _, run := range t.Runs {
			fmt.Fprintf(out, "  %s %s %s %s %s\n", run.ID, run.Mode, run.Status, run.Protocol, style.Dim(run.Source.Pointer))
		}
	}
}

func captureStatus(style *ui.Styler, status string) string {
	switch status {
	case "available":
		return style.Green(status)
	case "partial":
		return style.Yellow(status)
	default:
		return style.Red(status)
	}
}

func joinIDs[T int | uint64](values []T) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("#%d", v)
	}
	return strings.Join(parts, " ")
}

func runProbeClone(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe clone", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := dbFlags{path: fs.String("db", "", "SQLite database")}
	exchange := fs.Int("exchange", 0, "retained exchange index")
	output := fs.String("o", "", "write the draft to this new file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("probe clone requires one observation ID")
	}
	o, store, err := loadObservation(db, fs.Arg(0))
	if err != nil {
		return err
	}
	store.Close()
	definition, err := service.CloneProtocol(o, *exchange)
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = out.Write(definition)
		return err
	}
	// Never overwrite: an existing file may be an edited definition.
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(definition); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "wrote %s\n", *output)
	return err
}

func runProbeReplay(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := dbFlags{path: fs.String("db", "", "SQLite database")}
	exchange := fs.Int("exchange", 0, "retained exchange index")
	definitionPath := fs.String("definition", "", "edited Protocol DSL file")
	dryRun := fs.Bool("dry-run", false, "validate and print the plan only")
	live := fs.Bool("live", false, "resend to the original target")
	target := fs.String("target", "", "original target address, required with --live")
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *definitionPath == "" {
		return errors.New("probe replay requires --definition file and one observation ID")
	}
	definition, err := readDefinition(*definitionPath)
	if err != nil {
		return err
	}
	o, store, err := loadObservation(db, fs.Arg(0))
	if err != nil {
		return err
	}
	defer store.Close()
	in := service.ReplayInput{Observation: o, Exchange: *exchange, Definition: definition, Mode: observe.ProbeRunOffline}
	if *live {
		in.Mode = observe.ProbeRunLive
		addr, err := netip.ParseAddr(*target)
		if err != nil || addr != o.Target {
			return fmt.Errorf("--live requires --target %s, the original target", o.Target)
		}
		sc, ok, err := store.Scan(context.Background(), o.ScanID)
		if err != nil {
			return err
		}
		if ok && sc.Profile == "ot-safe" {
			return errors.New("the ot-safe profile does not allow resending edited probes")
		}
	} else if *target != "" {
		return errors.New("--target is only used with --live")
	}
	_, plan, err := service.PlanReplay(in)
	if err != nil {
		return err
	}
	if *dryRun {
		if *jsonFlag {
			return json.NewEncoder(out).Encode(plan)
		}
		_, err := fmt.Fprint(out, service.PlanText(plan))
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), plan.Timeout+5*time.Second)
	defer cancel()
	run, err := service.Replay(ctx, in)
	if err != nil {
		return err
	}
	if err := store.AddProbeRun(ctx, &run, o.ScanID, definition); err != nil {
		return err
	}
	if *jsonFlag {
		return json.NewEncoder(out).Encode(run)
	}
	fmt.Fprint(out, service.PlanText(plan))
	fmt.Fprintf(out, "run         %s\nstatus      %s\n", run.ID, run.Status)
	if run.Error != "" {
		fmt.Fprintf(out, "error       %s\n", run.Error)
	}
	if !run.RequestMatchesEvidence {
		fmt.Fprintln(out, "note        the sent request differs from the retained request")
	}
	if run.ScanID != "" {
		fmt.Fprintf(out, "scan        %s (nyxr history --scan %s)\n", run.ScanID, run.ScanID)
	}
	var names []string
	for name := range run.Result.Attributes {
		if !strings.HasPrefix(name, "replay.") && !strings.HasPrefix(name, "protocol.") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(out, "field       %s = %s\n", name, run.Result.Attributes[name])
	}
	return nil
}

func readDefinition(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("protocol definition exceeds 1 MiB")
	}
	return b, nil
}

func loadObservation(db dbFlags, id string) (observe.Observation, *storage.Store, error) {
	path, err := db.resolve()
	if err != nil {
		return observe.Observation{}, nil, err
	}
	store, err := openStore(context.Background(), path)
	if err != nil {
		return observe.Observation{}, nil, err
	}
	o, ok, err := store.ObservationByID(context.Background(), id)
	if err == nil && !ok {
		err = errors.New("observation not found in this store")
	}
	if err != nil {
		store.Close()
		return observe.Observation{}, nil, err
	}
	return o, store, nil
}

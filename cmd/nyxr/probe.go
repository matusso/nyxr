package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/service"
	"github.com/matusso/nyxr/internal/ui"
)

func probeUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr probe import [--json] file
	       nyxr probe validate [--json] file [more files...]
	       nyxr probe fixtures [--json] cases.yaml definition.yaml [more definitions...]
	       nyxr probe clone [--db file] [--exchange n] [-o new.yaml] observation-id
	       nyxr probe replay [--db file] [--exchange n] --definition file [--dry-run]
	                         [--live --target ip] [--json] observation-id

clone drafts an editable Protocol DSL definition from one retained exchange.
replay runs an edited definition against that exchange: by default offline,
feeding the retained response to the parser without sending anything; with
--live, one connection to the original target and port, recorded as a new
scan. --dry-run prints the exact target, transport and traffic bounds only.
Every replay is stored as a new nyxr/probe-run/v1 record; the original
evidence is never modified.

Import an nmap-service-probes file into nyxr's match model and print a summary.
The file is read at runtime and never bundled into nyxr; its data is licensed
by the Nmap Project. Patterns that Go's RE2 engine cannot compile are skipped
and counted rather than failing the import.

Once imported, scan with it using:
  nyxr scan --service --nmap-service-probes file --ports 21,25,80 host

Flags:
  --json    machine-readable summary
`)
}

// probeSummary is the machine-readable form of an import.
type probeSummary struct {
	Source     string   `json:"source"`
	SHA256     string   `json:"sha256"`
	Probes     int      `json:"probes"`
	MatchRules int      `json:"match_rules"`
	SoftMatch  int      `json:"softmatch"`
	Usable     int      `json:"usable"`
	Skipped    int      `json:"skipped"`
	NullRules  int      `json:"null_rules"`
	Exclusions int      `json:"exclusions"`
	License    string   `json:"license"`
	Warnings   []string `json:"warnings,omitempty"`
}

func runProbe(args []string, out io.Writer, style *ui.Styler) error {
	if len(args) == 0 {
		probeUsage(out)
		return errors.New("probe requires a subcommand (import or validate)")
	}
	switch args[0] {
	case "import":
		return runProbeImport(args[1:], out, style)
	case "validate":
		return runProbeValidate(args[1:], out)
	case "fixtures":
		return runProbeFixtures(args[1:], out)
	case "clone":
		return runProbeClone(args[1:], out)
	case "replay":
		return runProbeReplay(args[1:], out)
	case "help", "-h", "--help":
		probeUsage(out)
		return nil
	default:
		return fmt.Errorf("unknown probe subcommand %q (try nyxr probe validate)", args[0])
	}
}

func runProbeFixtures(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe fixtures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "machine-readable results")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("probe fixtures requires a fixture YAML file and protocol YAML files")
	}
	definitions, err := service.LoadProtocolRegistry(fs.Args()[1:])
	if err != nil {
		return err
	}
	results, err := service.RunProtocolFixtures(definitions, fs.Arg(0))
	if err != nil {
		return err
	}
	failed := false
	for _, result := range results {
		failed = failed || !result.Passed
	}
	if *jsonFlag {
		if err := json.NewEncoder(out).Encode(results); err != nil {
			return err
		}
	} else {
		for _, result := range results {
			status := "PASS"
			if !result.Passed {
				status = "FAIL"
			}
			if _, err := fmt.Fprintf(out, "%s %s (%s): %s\n", status, result.Name, result.Kind, result.Detail); err != nil {
				return err
			}
		}
	}
	if failed {
		return errors.New("protocol fixtures failed")
	}
	return nil
}

func runProbeValidate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "machine-readable summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("probe validate requires protocol YAML files")
	}
	definitions, err := service.LoadProtocolRegistry(fs.Args())
	if err != nil {
		return err
	}
	if *jsonFlag {
		var summaries []map[string]any
		for _, d := range definitions {
			summaries = append(summaries, map[string]any{"schema": d.Schema, "protocol": d.Name, "transport": d.Transport, "ports": d.Ports, "timeout": d.Timeout.String()})
		}
		if len(summaries) == 1 {
			return json.NewEncoder(out).Encode(summaries[0])
		}
		return json.NewEncoder(out).Encode(summaries)
	}
	for _, d := range definitions {
		if _, err := fmt.Fprintf(out, "%s/%s: valid on %d ports (%s timeout)\n", d.Name, d.Transport, len(d.Ports), d.Timeout); err != nil {
			return err
		}
	}
	return nil
}

func runProbeImport(args []string, out io.Writer, style *ui.Styler) error {
	fs := flag.NewFlagSet("probe import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { probeUsage(out) }
	jsonFlag := fs.Bool("json", false, "machine-readable summary")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			probeUsage(out)
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("probe import requires exactly one nmap-service-probes file")
	}
	db, err := nmapdb.LoadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sum := probeSummary{
		Source:     db.Source,
		SHA256:     db.SHA256,
		Probes:     len(db.Probes),
		MatchRules: db.TotalMatch,
		SoftMatch:  db.SoftMatch,
		Usable:     db.Usable,
		Skipped:    db.Skipped,
		NullRules:  db.NullRules(),
		Exclusions: len(db.Exclude),
		License:    nmapdb.LicenseNotice,
		Warnings:   db.Warnings,
	}
	if *jsonFlag {
		return json.NewEncoder(out).Encode(sum)
	}
	key := func(k string) string { return style.Key(fmt.Sprintf("%-12s", k)) + " " }
	fmt.Fprintf(out, "%s%s\n", key("source"), sum.Source)
	fmt.Fprintf(out, "%s%s\n", key("sha256"), style.Dim(sum.SHA256))
	fmt.Fprintf(out, "%s%s\n", key("probes"), style.Bold(fmt.Sprintf("%d", sum.Probes)))
	fmt.Fprintf(out, "%s%s %s\n", key("match rules"), style.Bold(fmt.Sprintf("%d", sum.MatchRules)), style.Dim(fmt.Sprintf("(%d softmatch)", sum.SoftMatch)))
	fmt.Fprintf(out, "%s%s\n", key("usable"), style.Bold(fmt.Sprintf("%d", sum.Usable)))
	fmt.Fprintf(out, "%s%s %s\n", key("skipped"), style.Bold(fmt.Sprintf("%d", sum.Skipped)), style.Dim("(patterns RE2 cannot compile)"))
	fmt.Fprintf(out, "%s%s %s\n", key("banner rules"), style.Bold(fmt.Sprintf("%d", sum.NullRules)), style.Dim("(NULL probe, used for --nmap-service-probes)"))
	fmt.Fprintf(out, "%s%d\n", key("exclusions"), sum.Exclusions)
	if n := len(sum.Warnings); n > 0 {
		shown := sum.Warnings
		if n > 10 {
			shown = shown[:10]
		}
		fmt.Fprintf(out, "%s%s\n", key("warnings"), style.Yellow(fmt.Sprintf("%d", n)))
		for _, w := range shown {
			fmt.Fprintf(out, "  %s %s\n", style.Yellow("-"), style.Dim(w))
		}
		if n > len(shown) {
			fmt.Fprintf(out, "  %s\n", style.Dim(fmt.Sprintf("... and %d more", n-len(shown))))
		}
	}
	fmt.Fprintf(out, "\n%s\n", style.Dim(sum.License))
	return nil
}

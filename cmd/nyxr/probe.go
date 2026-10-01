package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/ui"
)

func probeUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr probe import file [--json]

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
		return errors.New("probe requires a subcommand (import)")
	}
	switch args[0] {
	case "import":
		return runProbeImport(args[1:], out, style)
	case "help", "-h", "--help":
		probeUsage(out)
		return nil
	default:
		return fmt.Errorf("unknown probe subcommand %q (try nyxr probe import)", args[0])
	}
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

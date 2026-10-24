package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

// parseStudy replays every report of a role=report,... study specification.
func parseStudy(spec string) (map[string]model.Envelope, error) {
	study := map[string]model.Envelope{}
	for _, part := range strings.Split(spec, ",") {
		role, path, ok := strings.Cut(part, "=")
		if !ok || !slices.Contains(horizon.CrossPortRoles, role) || study[role].SHA256 != "" {
			return nil, fmt.Errorf("invalid study entry %q", part)
		}
		e, err := replayFile(path)
		if err != nil {
			return nil, err
		}
		study[role] = e
	}
	return study, nil
}

func studyReports(study map[string]model.Envelope) map[string]model.Report {
	reports := map[string]model.Report{}
	for role, e := range study {
		reports[role] = e.Report
	}
	return reports
}

// parseChanges reads declared changes as TIME@host:IP or TIME@network[@detail].
func parseChanges(specs []string) ([]model.ChangeEvent, error) {
	var out []model.ChangeEvent
	for _, spec := range specs {
		parts := strings.SplitN(spec, "@", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid change %q", spec)
		}
		at, err := time.Parse(time.RFC3339, parts[0])
		if err != nil {
			return nil, fmt.Errorf("change %q: %w", spec, err)
		}
		scope, err := horizon.CanonicalChangeScope(parts[1])
		if err != nil {
			return nil, err
		}
		c := model.ChangeEvent{At: at, Scope: scope}
		if len(parts) == 3 {
			c.Detail = parts[2]
		}
		out = append(out, c)
	}
	return out, nil
}

func parseNow(value string) (time.Time, error) {
	if value == "" {
		return time.Now().UTC(), nil
	}
	now, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return now, fmt.Errorf("--now: %w", err)
	}
	return now, nil
}

func writeNew(path string, value any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(horizonJSON(file, value), file.Close())
}

func splitList(value string) []string {
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

// horizonAdapt runs a budgeted adaptive cross-port study. With --replay it
// draws each requested role from recorded reports and sends no traffic.
func horizonAdapt(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("horizon adapt", flag.ContinueOnError)
	fs.SetOutput(out)
	paths := map[string]*string{}
	for _, role := range horizon.CrossPortRoles {
		paths[role] = fs.String(role, "", role+" role experiment (YAML/JSON)")
	}
	replay := fs.String("replay", "", "recorded study role=report,...; no traffic")
	retro := fs.Bool("retro-curtail", false, "with --replay: evaluate exact curtailment retrospectively")
	curtail := fs.Bool("curtail", false, "run each role with exact sign-test curtailment (stopRule: curtail)")
	policyName := fs.String("policy", "", "lab, enterprise, fragile or ot-restricted")
	permissions := fs.String("permit", "", "independent permissions: cross-port")
	allowTargets := fs.String("allow-targets", "", "independent approved IP/CIDR scope")
	allowPorts := fs.String("allow-ports", "", "independent approved TCP ports")
	lf := addLinkFlags(fs)
	budgetPackets := fs.Int("budget-packets", 0, "packet budget across roles (0: unlimited)")
	budgetMS := fs.Int64("budget-ms", 0, "worst-case duration budget across roles in ms (0: unlimited)")
	refine := fs.String("refine", "", "also resolve: direction, cooldown")
	require := fs.String("require", "", "roles that must run: null, same-port, ...")
	full := fs.Bool("full-coverage", false, "run every role; profiles never skip a test")
	lambda := fs.Float64("lambda", 0, "bits of expected information one packet must buy")
	profilePath := fs.String("profile", "", "behavior profile to check and use for refinements")
	var changes stringList
	fs.Var(&changes, "change", "declared change TIME@host:IP or TIME@network[@detail] (repeatable)")
	nowFlag := fs.String("now", "", "evaluation time for profile expiry (RFC 3339)")
	evidenceDir := fs.String("evidence-dir", "", "existing directory for each run role's sealed report")
	output := fs.String("output", "", "new private adaptive study file (refuses overwrites)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("horizon adapt takes no positional arguments")
	}
	now, err := parseNow(*nowFlag)
	if err != nil {
		return err
	}
	declared, err := parseChanges(changes)
	if err != nil {
		return err
	}
	in := horizon.AdaptiveInput{Experiments: map[string]model.Experiment{}, Changes: declared, Now: now,
		Budget: model.Budget{Packets: *budgetPackets, DurationMS: *budgetMS},
		Task:   model.AdaptiveTask{Refine: splitList(*refine), Require: splitList(*require), FullCoverage: *full, LambdaBitsPerPacket: *lambda}}
	if *profilePath != "" {
		file, err := os.Open(*profilePath)
		if err != nil {
			return err
		}
		p, err := horizon.LoadProfile(file)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
		in.Profile = &p
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *replay != "" {
		for role, path := range paths {
			if *path != "" {
				return fmt.Errorf("--replay cannot be combined with --%s", role)
			}
		}
		if *curtail || *policyName != "" || *permissions != "" || *allowTargets != "" || *allowPorts != "" || *lf.sim != "" || lf.live() || *evidenceDir != "" {
			return errors.New("--replay sends no traffic; it takes no policy, link, curtail or evidence options")
		}
		study, err := parseStudy(*replay)
		if err != nil {
			return err
		}
		reports := studyReports(study)
		target := ""
		ports := map[uint16]bool{}
		for role, r := range reports {
			in.Experiments[role] = r.Experiment
			if t := r.Experiment.Spec.Scope.Targets[0]; target == "" {
				target = t
			} else if t != target {
				return errors.New("recorded study reports must share one target")
			}
			for _, p := range r.Experiment.Spec.Scope.TCPPorts {
				ports[p] = true
			}
		}
		// Offline consistency scope, as replay uses; never live authorization.
		in.Policy = model.Policy{Profile: "lab", Permissions: []string{"cross-port"}, AllowTargets: []string{target}}
		for p := range ports {
			in.Policy.AllowPorts = append(in.Policy.AllowPorts, p)
		}
		in.Run = func(_ context.Context, role string) (model.Report, error) {
			r, ok := reports[role]
			if !ok {
				return r, fmt.Errorf("no recorded %s report", role)
			}
			if *retro {
				r = horizon.RetroCurtail(r)
			}
			return r, nil
		}
	} else {
		if *retro {
			return errors.New("--retro-curtail requires --replay")
		}
		if *paths[horizon.RoleMain] == "" || strings.TrimSpace(*allowTargets) == "" || strings.TrimSpace(*allowPorts) == "" {
			return errors.New("horizon adapt requires --main, --allow-targets and --allow-ports (or --replay)")
		}
		authorized, err := config.ParsePorts(*allowPorts)
		if err != nil {
			return err
		}
		in.Policy = model.Policy{Profile: *policyName, AllowTargets: strings.Split(*allowTargets, ","), AllowPorts: authorized}
		if *permissions != "" {
			in.Policy.Permissions = strings.Split(*permissions, ",")
		}
		for role, path := range paths {
			if *path == "" {
				continue
			}
			file, err := os.Open(*path)
			if err != nil {
				return err
			}
			e, err := dsl.Parse(file)
			if err = errors.Join(err, file.Close()); err != nil {
				return fmt.Errorf("%s: %w", role, err)
			}
			if *curtail {
				e.Spec.Execution.StopRule = "curtail"
			}
			if _, err := dsl.Compile(e, in.Policy); err != nil {
				return fmt.Errorf("%s: %w", role, err)
			}
			in.Experiments[role] = e
		}
		if *evidenceDir != "" {
			if info, err := os.Stat(*evidenceDir); err != nil || !info.IsDir() {
				return errors.New("--evidence-dir must be an existing directory")
			}
			// Refuse before any traffic rather than lose evidence afterwards.
			for role := range in.Experiments {
				if _, err := os.Lstat(filepath.Join(*evidenceDir, role+".json")); !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("--evidence-dir already holds %s.json", role)
				}
			}
		}
		link, open, err := lf.open(netip.MustParseAddr(in.Experiments[horizon.RoleMain].Spec.Scope.Targets[0]))
		if err != nil {
			return err
		}
		in.Run = func(ctx context.Context, role string) (model.Report, error) {
			transport, err := open()
			if err != nil {
				return model.Report{}, err
			}
			defer transport.Close()
			report, runErr := horizon.Run(ctx, in.Experiments[role], in.Policy, link, transport)
			if *evidenceDir != "" && report.APIVersion != "" {
				envelope, err := horizon.Seal(report)
				if err == nil {
					err = writeNew(filepath.Join(*evidenceDir, role+".json"), envelope)
				}
				runErr = errors.Join(runErr, err)
			}
			return report, runErr
		}
	}
	// Reserve the output before any traffic; never overwrite.
	var destination *os.File
	if *output != "" {
		destination, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer destination.Close()
	}
	study, runErr := horizon.RunAdaptive(ctx, in)
	if len(study.Steps) == 0 && runErr != nil {
		return runErr
	}
	// A failed study keeps its completed steps and says why it stopped.
	if destination != nil {
		if err := errors.Join(horizonJSON(destination, study), destination.Close()); err != nil {
			return errors.Join(runErr, err)
		}
	}
	return errors.Join(runErr, horizonJSON(out, study))
}

// horizonProfile builds or checks behavior profiles from replayed studies.
func horizonProfile(args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "build" && args[0] != "check") {
		return errors.New("horizon profile requires build or check")
	}
	fs := flag.NewFlagSet("horizon profile "+args[0], flag.ContinueOnError)
	fs.SetOutput(out)
	studySpec := fs.String("study", "", "cross-port study as role=report,...")
	class := fs.String("class", "", "build: operator label for the validated target class")
	ttl := fs.Duration("ttl", 24*time.Hour, "build: validity after the latest run (max 720h)")
	profilePath := fs.String("profile", "", "check: profile file")
	nowFlag := fs.String("now", "", "evaluation time (RFC 3339)")
	output := fs.String("output", "", "build: new private profile file (refuses overwrites)")
	var changes stringList
	fs.Var(&changes, "change", "check: declared change TIME@host:IP or TIME@network[@detail] (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *studySpec == "" {
		return errors.New("horizon profile requires --study")
	}
	now, err := parseNow(*nowFlag)
	if err != nil {
		return err
	}
	study, err := parseStudy(*studySpec)
	if err != nil {
		return err
	}
	reports := studyReports(study)
	if args[0] == "build" {
		if *profilePath != "" || len(changes) != 0 {
			return errors.New("profile build takes no --profile or --change")
		}
		p, err := horizon.BuildProfile(reports, *class, now, *ttl)
		if err != nil {
			return err
		}
		if *output != "" {
			if err := writeNew(*output, p); err != nil {
				return err
			}
		}
		return horizonJSON(out, p)
	}
	if *profilePath == "" || *class != "" || *output != "" {
		return errors.New("profile check requires --profile and takes no --class or --output")
	}
	file, err := os.Open(*profilePath)
	if err != nil {
		return err
	}
	p, err := horizon.LoadProfile(file)
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	declared, err := parseChanges(changes)
	if err != nil {
		return err
	}
	check := horizon.CheckProfile(p, reports, declared, now)
	if err := horizonJSON(out, check); err != nil {
		return err
	}
	if !check.Valid {
		return errors.New("profile is invalid: " + strconv.Itoa(len(check.Reasons)) + " reason(s)")
	}
	return nil
}

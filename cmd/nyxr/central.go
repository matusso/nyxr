package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/matusso/nyxr/internal/central"
	"github.com/matusso/nyxr/internal/inventory"
)

func centralUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr central <command> [flags]

Consolidate nyxr databases (lineages) into one controller store on SQLite or
PostgreSQL, keep large evidence artifacts in object storage, and reconcile
asset identities across lineages. Only scoped cloud and Kubernetes IDs join
lineages automatically; SSH keys, SMB GUIDs, MACs and weak clues stay leads.

Commands:
  push [--db file]          ingest a scanner or controller database (from its cursor)
  upload-dir --dir dir      upload referenced captures found below dir (fleet agent hosts)
  put [flags] file          store an artifact (e.g. a HORIZON report) by content hash
  get [flags] artifact-id   write an artifact's verified bytes to stdout or --out
  artifacts [--state s]     list artifacts (pending, available, missing, expired)
  prune                     delete artifact bytes whose retention ended
  lineages                  list ingested databases and their cursors
  entities                  list reconciled entities
  relations                 list clues shared by several entities (never merged)
  conflicts                 list joins reconciliation refused or contradictions it kept
  review --join|--separate --node-a n --node-b n --note text   record a decision
  revert --decision id --note text                             undo a decision
  decisions                 list decisions
  history [--node n]        list the membership audit
  export [--out file]       write a consistent JSONL export
  restore [--in file]       load an export into an empty store (SQLite <-> PostgreSQL)
  migrate                   create or upgrade the central schema and print its version

Connection flags (every command):
  --central dsn             postgres://... or a SQLite path (or NYXR_CENTRAL_DSN)
  --central-dsn-file file   read the DSN from a file, keeping passwords out of argv
  --objects location        file:///dir, a directory, or s3://bucket/prefix?endpoint=..&region=..
                            (or NYXR_CENTRAL_OBJECTS)
  --objects-credentials-file file  S3 credential-process JSON (default AWS_* variables)
  --json                    JSON output

Command flags:
  push: --kind standalone|controller, --label text, --upload-captures (default true),
        --capture-retention dur
  upload-dir: --max-files n (default 10000)
  put: --kind name, --access internal|restricted (default restricted), --retain dur, --scan id
  get: --allow-restricted, --out file
  review, revert: --actor name, --expect ENTITY@REVISION[,...]
`)
}

// openCentral resolves the DSN (file, flag, then environment) and opens the
// store with its object backend.
func openCentral(ctx context.Context, dsn, dsnFile, objects, objectsCreds string) (*central.DB, error) {
	if dsnFile != "" {
		data, err := inventory.ReadSecretFile(dsnFile, "central DSN")
		if err != nil {
			return nil, err
		}
		dsn = strings.TrimSpace(string(data))
	}
	if dsn == "" {
		dsn = os.Getenv("NYXR_CENTRAL_DSN")
	}
	if dsn == "" {
		return nil, errors.New("--central, --central-dsn-file or NYXR_CENTRAL_DSN is required")
	}
	if objects == "" {
		objects = os.Getenv("NYXR_CENTRAL_OBJECTS")
	}
	store, err := central.OpenObjects(objects, objectsCreds)
	if err != nil {
		return nil, err
	}
	return central.Open(ctx, dsn, store)
}

func runCentral(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		centralUsage(out)
		if len(args) == 0 {
			return errors.New("central needs a command")
		}
		return nil
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("central "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { centralUsage(out) }
	dsn := fs.String("central", "", "central DSN")
	dsnFile := fs.String("central-dsn-file", "", "central DSN file")
	objects := fs.String("objects", "", "object storage location")
	objectsCreds := fs.String("objects-credentials-file", "", "S3 credential-process JSON")
	asJSON := fs.Bool("json", false, "JSON output")
	dbFlag := dbFlags{path: fs.String("db", "", "SQLite database")}
	kind := fs.String("kind", "", "lineage or artifact kind")
	label := fs.String("label", "", "lineage label")
	upload := fs.Bool("upload-captures", true, "upload local captures")
	captureRetention := fs.Duration("capture-retention", 0, "capture retention")
	dir := fs.String("dir", "", "directory to upload from")
	maxFiles := fs.Int("max-files", 10000, "files to examine")
	access := fs.String("access", central.AccessRestricted, "artifact access policy")
	retain := fs.Duration("retain", 0, "artifact retention")
	scanID := fs.String("scan", "", "scan ID the artifact belongs to")
	allowRestricted := fs.Bool("allow-restricted", false, "read restricted artifacts")
	outFile := fs.String("out", "", "output file")
	inFile := fs.String("in", "", "input file")
	state := fs.String("state", "", "artifact state")
	join := fs.Bool("join", false, "record a join")
	separate := fs.Bool("separate", false, "record a separation")
	nodeA := fs.String("node-a", "", "first node")
	nodeB := fs.String("node-b", "", "second node")
	note := fs.String("note", "", "decision note")
	actor := fs.String("actor", os.Getenv("USER"), "decision actor")
	expect := fs.String("expect", "", "entity revisions, ID@revision,...")
	decision := fs.Int64("decision", 0, "decision ID")
	nodeFlag := fs.String("node", "", "node")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			centralUsage(out)
			return nil
		}
		return err
	}
	if cmd != "put" && cmd != "get" && fs.NArg() != 0 {
		return fmt.Errorf("central %s takes no positional arguments", cmd)
	}
	expected, err := parseExpect(*expect)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := openCentral(ctx, *dsn, *dsnFile, *objects, *objectsCreds)
	if err != nil {
		return err
	}
	defer store.Close()
	emit := func(v any, text func(w *tabwriter.Writer)) error {
		if *asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		text(w)
		return w.Flush()
	}
	switch cmd {
	case "migrate":
		v, err := store.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		ns, err := store.Namespace(ctx)
		if err != nil {
			return err
		}
		return emit(map[string]any{"dialect": store.Dialect(), "schema_version": v, "namespace": ns}, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "%s central store, schema %d, namespace %s\n", store.Dialect(), v, ns)
		})
	case "push":
		path, err := dbFlag.resolve()
		if err != nil {
			return err
		}
		src, err := openStore(ctx, path)
		if err != nil {
			return err
		}
		defer src.Close()
		res, err := central.Push(ctx, src, store, central.PushOptions{Kind: *kind, Label: *label, UploadCaptures: *upload, CaptureRetention: *captureRetention})
		if err != nil {
			return err
		}
		return emit(res, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "lineage %s: %d new observations, %d duplicates, %d conflicts, %d scans, %d uploaded, %d captures pending\n",
				res.Lineage, res.Ingested.Observations, res.Ingested.Duplicates, res.Ingested.Conflicts, res.Ingested.Scans, res.Uploaded, res.Pending)
		})
	case "upload-dir":
		if *dir == "" {
			return errors.New("--dir is required")
		}
		uploaded, scanned, err := central.UploadDir(ctx, store, *dir, *maxFiles)
		if err != nil {
			return err
		}
		return emit(map[string]int{"uploaded": uploaded, "scanned": scanned}, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "uploaded %d of %d files\n", uploaded, scanned)
		})
	case "put":
		if fs.NArg() != 1 {
			return errors.New("central put takes one file")
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		ref := central.ArtifactRef{Kind: *kind, Access: *access, ScanID: *scanID}
		if ref.Kind == "" {
			ref.Kind = "file"
		}
		if *retain > 0 {
			ref.RetainUntil = time.Now().UTC().Add(*retain)
		}
		a, err := store.PutArtifact(ctx, ref, f)
		if err != nil {
			return err
		}
		return emit(a, func(w *tabwriter.Writer) { fmt.Fprintf(w, "%s\t%s\t%d bytes\t%s\n", a.ID, a.Kind, a.Size, a.Access) })
	case "get":
		if fs.NArg() != 1 {
			return errors.New("central get takes one artifact ID")
		}
		rc, _, err := store.OpenArtifact(ctx, fs.Arg(0), central.Grant{Restricted: *allowRestricted})
		if err != nil {
			return err
		}
		defer rc.Close()
		return copyOut(rc, *outFile, out)
	case "artifacts":
		list, err := store.Artifacts(ctx, *state, 0)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ARTIFACT\tKIND\tSTATE\tACCESS\tSIZE\tRETAIN UNTIL\tSCAN\tAGENT")
			for _, a := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", a.ID, a.Kind, a.State, a.Access, a.Size, fmtTime(a.RetainUntil), a.ScanID, a.AgentID)
			}
		})
	case "prune":
		n, err := store.PruneArtifacts(ctx, time.Now())
		if err != nil {
			return err
		}
		return emit(map[string]int{"pruned": n}, func(w *tabwriter.Writer) { fmt.Fprintf(w, "pruned %d artifact(s)\n", n) })
	case "lineages":
		list, err := store.Lineages(ctx)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "LINEAGE\tKIND\tLABEL\tOBSERVATIONS\tCURSOR\tLAST INGESTED")
			for _, l := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n", l.Namespace, l.Kind, l.Label, l.Observations, l.Cursor, fmtTime(l.LastIngested))
			}
		})
	case "entities":
		list, err := store.Entities(ctx)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ENTITY\tREV\tLINK\tNODE\tADDRESSES")
			for _, e := range list {
				for i, n := range e.Nodes {
					id, rev, link := e.ID, strconv.FormatInt(e.Revision, 10), e.Link
					if i > 0 {
						id, rev, link = "", "", ""
					}
					var addrs []string
					for _, a := range n.Addresses {
						addrs = append(addrs, a.String())
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", id, rev, link, n.Key, strings.Join(addrs, ","))
				}
			}
		})
	case "relations":
		list, err := store.Relations(ctx)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "STRENGTH\tKIND\tVALUE\tENTITIES")
			for _, r := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Strength, r.Kind, r.Value, strings.Join(r.Entities, ","))
			}
		})
	case "conflicts":
		list, err := store.Conflicts(ctx)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "REASON\tKIND\tNODE A\tNODE B\tVALUE A\tVALUE B")
			for _, c := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", c.Reason, c.Kind, c.NodeA, c.NodeB, c.ValueA, c.ValueB)
			}
		})
	case "review":
		if *join == *separate {
			return errors.New("give exactly one of --join or --separate")
		}
		action := central.DecisionJoin
		if *separate {
			action = central.DecisionSeparate
		}
		d, err := store.Decide(ctx, central.Decision{Action: action, NodeA: *nodeA, NodeB: *nodeB, Note: *note, Actor: *actor, Expect: expected})
		if err != nil {
			return err
		}
		return emit(d, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "decision %d: %s, %d node(s) moved\n", d.ID, d.Action, d.Moved)
		})
	case "revert":
		d, err := store.Revert(ctx, *decision, *note, *actor, expected)
		if err != nil {
			return err
		}
		return emit(d, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "decision %d reverts %d, %d node(s) moved\n", d.ID, d.Target, d.Moved)
		})
	case "decisions":
		list, err := store.Decisions(ctx)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tACTION\tNODES / TARGET\tACTOR\tDECIDED\tREVERTED BY\tNOTE")
			for _, d := range list {
				subject := d.NodeA + " " + d.NodeB
				if d.Action == central.DecisionRevert {
					subject = strconv.FormatInt(d.Target, 10)
				}
				reverted := ""
				if d.RevertedBy != 0 {
					reverted = strconv.FormatInt(d.RevertedBy, 10)
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Action, subject, d.Actor, fmtTime(d.DecidedAt), reverted, d.Note)
			}
		})
	case "history":
		list, err := store.History(ctx, *nodeFlag)
		if err != nil {
			return err
		}
		return emit(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tNODE\tFROM\tTO\tCAUSE\tAT")
			for _, e := range list {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Node, e.FromEntity, e.ToEntity, e.Cause, fmtTime(e.At))
			}
		})
	case "export":
		if *outFile == "" {
			return store.Export(ctx, out)
		}
		f, err := os.OpenFile(*outFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if err := store.Export(ctx, f); err != nil {
			f.Close()
			_ = os.Remove(*outFile)
			return err
		}
		return f.Close()
	case "restore":
		var r io.Reader = os.Stdin
		if *inFile != "" {
			f, err := os.Open(*inFile)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		return store.Restore(ctx, r)
	default:
		return fmt.Errorf("unknown central command %q (try nyxr central help)", cmd)
	}
}

func parseExpect(raw string) ([]central.EntityVersion, error) {
	if raw == "" {
		return nil, nil
	}
	var out []central.EntityVersion
	for _, item := range strings.Split(raw, ",") {
		id, rev, ok := strings.Cut(strings.TrimSpace(item), "@")
		n, err := strconv.ParseInt(rev, 10, 64)
		if !ok || err != nil || id == "" {
			return nil, fmt.Errorf("--expect wants ENTITY@REVISION, got %q", item)
		}
		out = append(out, central.EntityVersion{ID: id, Revision: n})
	}
	return out, nil
}

// copyOut writes verified artifact bytes. A file that failed verification
// mid-copy is removed rather than left looking complete.
func copyOut(r io.Reader, path string, stdout io.Writer) error {
	if path == "" {
		_, err := io.Copy(stdout, r)
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

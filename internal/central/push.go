package central

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

// PushOptions controls a lineage push.
type PushOptions struct {
	// Kind is LineageController for a fleet controller's database.
	Kind  string
	Label string
	// BatchSize bounds observations per ingested batch (default 500).
	BatchSize int
	// UploadCaptures uploads capture files that exist at their recorded
	// path and match their recorded hash. Captures recorded on agents stay
	// pending until UploadDir runs on the agent host.
	UploadCaptures bool
	// CaptureRetention sets the retention of registered captures; zero
	// keeps them until an operator prunes.
	CaptureRetention time.Duration
}

// PushResult summarizes a push.
type PushResult struct {
	Lineage  string       `json:"lineage"`
	Batches  int          `json:"batches"`
	Ingested IngestResult `json:"ingested"`
	Uploaded int          `json:"uploaded"`
	Pending  int          `json:"pending"`
}

func (r *PushResult) add(in IngestResult) {
	r.Batches++
	r.Ingested.Observations += in.Observations
	r.Ingested.Duplicates += in.Duplicates
	r.Ingested.Conflicts += in.Conflicts
	r.Ingested.Scans += in.Scans
	r.Ingested.Artifacts += in.Artifacts
	r.Ingested.Moved += in.Moved
	r.Ingested.MembersApplied = r.Ingested.MembersApplied || in.MembersApplied
	r.Ingested.Revision = in.Revision
}

// Push copies a scanner or controller database into the central store from
// the lineage's cursor. It is safe to rerun, to interrupt, and to run from
// two places at once: every part of a batch is idempotent.
func Push(ctx context.Context, src *storage.Store, dst Store, opts PushOptions) (PushResult, error) {
	var out PushResult
	ns, err := src.Namespace(ctx)
	if err != nil {
		return out, err
	}
	out.Lineage = ns
	if opts.Kind == "" {
		opts.Kind = LineageStandalone
	}
	if opts.BatchSize <= 0 || opts.BatchSize > MaxBatchRecords {
		opts.BatchSize = 500
	}
	lineages, err := dst.Lineages(ctx)
	if err != nil {
		return out, err
	}
	var cursor int64
	for _, l := range lineages {
		if l.Namespace == ns {
			cursor = l.Cursor
		}
	}
	scans, err := src.LineageScans(ctx)
	if err != nil {
		return out, err
	}
	head := Batch{Lineage: ns, Kind: opts.Kind, Label: opts.Label}
	captures := map[string]string{} // artifact ID -> local path
	for _, ls := range scans {
		head.Scans = append(head.Scans, ScanRecord{Scan: ls.Scan, AgentID: ls.AgentID})
		if c := ls.Scan.Capture; c != nil && c.ArtifactID != "" {
			ref := ArtifactRef{ID: c.ArtifactID, Kind: "pcapng", MediaType: "application/vnd.tcpdump.pcap", Size: c.Bytes,
				ScanID: ls.Scan.ID, AgentID: ls.AgentID, Access: AccessRestricted}
			if opts.CaptureRetention > 0 {
				ref.RetainUntil = ls.Scan.Started.Add(opts.CaptureRetention)
			}
			head.Artifacts = append(head.Artifacts, ref)
			if ls.AgentID == "" && c.Path != "" {
				captures[c.ArtifactID] = c.Path
			}
		}
	}
	for len(head.Scans) > 0 || len(head.Artifacts) > 0 {
		b := Batch{Lineage: ns, Kind: opts.Kind, Label: opts.Label}
		n := min(len(head.Scans), MaxBatchRecords/2)
		b.Scans, head.Scans = head.Scans[:n], head.Scans[n:]
		m := min(len(head.Artifacts), MaxBatchRecords/2)
		b.Artifacts, head.Artifacts = head.Artifacts[:m], head.Artifacts[m:]
		res, err := dst.Ingest(ctx, b)
		if err != nil {
			return out, fmt.Errorf("ingest scans: %w", err)
		}
		out.add(res)
	}
	for {
		rows, err := src.LineageObservations(ctx, cursor, opts.BatchSize)
		if err != nil {
			return out, err
		}
		if len(rows) == 0 {
			break
		}
		b := Batch{Lineage: ns, Kind: opts.Kind, Label: opts.Label, Cursor: rows[len(rows)-1].RowID}
		for _, r := range rows {
			b.Observations = append(b.Observations, ObservationRecord{ArtifactID: r.ArtifactID, Source: r.Source,
				AgentID: r.AgentID, LeaseID: r.LeaseID, JobID: r.JobID, Attempt: r.Attempt, Fleet: r.Fleet, ClockOffset: r.ClockOffset})
		}
		res, err := dst.Ingest(ctx, b)
		if err != nil {
			return out, fmt.Errorf("ingest observations after row %d: %w", cursor, err)
		}
		out.add(res)
		cursor = b.Cursor
	}
	members, err := src.LineageMembers(ctx)
	if err != nil {
		return out, err
	}
	res, err := dst.Ingest(ctx, Batch{Lineage: ns, Kind: opts.Kind, Label: opts.Label,
		Members: &MemberSnapshot{Revision: members.Revision, Members: members.Members}})
	if err != nil {
		return out, fmt.Errorf("ingest membership: %w", err)
	}
	out.add(res)
	if opts.UploadCaptures {
		pending, err := dst.Artifacts(ctx, ArtifactPending, 0)
		if err != nil {
			return out, err
		}
		for _, a := range pending {
			path, ok := captures[a.ID]
			if !ok {
				continue
			}
			if err := uploadFile(ctx, dst, a.ArtifactRef, path); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // the capture was moved or deleted; it stays pending
				}
				return out, fmt.Errorf("upload %s: %w", path, err)
			}
			out.Uploaded++
		}
	}
	pending, err := dst.Artifacts(ctx, ArtifactPending, 0)
	if err != nil {
		return out, err
	}
	for _, a := range pending {
		if a.Lineage == ns {
			out.Pending++
		}
	}
	return out, nil
}

func uploadFile(ctx context.Context, dst Store, ref ArtifactRef, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = dst.PutArtifact(ctx, ref, f)
	return err
}

// UploadDir uploads the files below dir whose hash matches an artifact the
// central store holds as pending (or missing): on a fleet agent, the
// captures in its --evidence-dir that the controller pushed as references.
// Files nothing references are never uploaded. maxFiles bounds the walk.
func UploadDir(ctx context.Context, dst Store, dir string, maxFiles int) (uploaded, scanned int, err error) {
	if maxFiles <= 0 {
		maxFiles = 10000
	}
	want := map[string]ArtifactRef{}
	for _, state := range []string{ArtifactPending, ArtifactMissing} {
		list, err := dst.Artifacts(ctx, state, 0)
		if err != nil {
			return 0, 0, err
		}
		for _, a := range list {
			want[a.ID] = a.ArtifactRef
		}
	}
	if len(want) == 0 {
		return 0, 0, nil
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if scanned++; scanned > maxFiles {
			return fmt.Errorf("more than %d files below %s", maxFiles, dir)
		}
		id, err := hashFile(path)
		if err != nil {
			return err
		}
		ref, ok := want[id]
		if !ok {
			return nil
		}
		if err := uploadFile(ctx, dst, ref, path); err != nil {
			return fmt.Errorf("upload %s: %w", path, err)
		}
		delete(want, id)
		uploaded++
		return nil
	})
	return uploaded, scanned, err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

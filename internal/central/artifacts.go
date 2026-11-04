package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"
)

// parseArtifactID validates "sha256:<64 lowercase hex>" and returns the hex.
func parseArtifactID(id string) (string, error) {
	h, ok := strings.CutPrefix(id, "sha256:")
	b, err := hex.DecodeString(h)
	if !ok || err != nil || len(b) != sha256.Size || h != hex.EncodeToString(b) {
		return "", fmt.Errorf("artifact ID %q must be sha256:<64 lowercase hex digits>", id)
	}
	return h, nil
}

func objectKey(hexID string) string { return "sha256/" + hexID[:2] + "/" + hexID }

func normalizeRef(ref ArtifactRef) (ArtifactRef, error) {
	if ref.Access == "" {
		ref.Access = AccessRestricted
	}
	if ref.Access != AccessInternal && ref.Access != AccessRestricted {
		return ref, fmt.Errorf("artifact access must be %s or %s", AccessInternal, AccessRestricted)
	}
	ref.Kind = strings.TrimSpace(ref.Kind)
	if ref.Kind == "" || len(ref.Kind) > 64 {
		return ref, errors.New("artifact kind is required (at most 64 bytes)")
	}
	if len(ref.MediaType) > 128 || len(ref.Lineage) > 128 || len(ref.ScanID) > 128 || len(ref.AgentID) > 128 {
		return ref, errors.New("artifact metadata field too long")
	}
	if ref.Size < 0 {
		return ref, errors.New("artifact size must be nonnegative")
	}
	return ref, nil
}

// registerArtifact records a reference without bytes. An existing artifact
// keeps its state, access policy and retention; a later explicit retention
// extends it, but a reference without one never removes it.
func registerArtifact(ctx context.Context, t tx, ref ArtifactRef, now time.Time) (bool, error) {
	if _, err := parseArtifactID(ref.ID); err != nil {
		return false, err
	}
	ref, err := normalizeRef(ref)
	if err != nil {
		return false, err
	}
	res, err := t.exec(ctx, `INSERT INTO artifacts(id, kind, media_type, size, state, access, retain_until, lineage, scan_id, agent_id, registered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		ref.ID, ref.Kind, ref.MediaType, ref.Size, ArtifactPending, ref.Access, ts(ref.RetainUntil), ref.Lineage, ref.ScanID, ref.AgentID, ts(now))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 && !ref.RetainUntil.IsZero() {
		_, err = t.exec(ctx, `UPDATE artifacts SET retain_until = ? WHERE id = ? AND retain_until <> '' AND retain_until < ?`,
			ts(ref.RetainUntil), ref.ID, ts(ref.RetainUntil))
	}
	return n == 1, err
}

// PutArtifact spools r to a temporary file while hashing it, bounded by
// MaxArtifact, verifies the hash against ref.ID when given, stores the bytes
// under their content address and marks the artifact available. Storing the
// same bytes again is a no-op apart from retention and a missing object
// being restored.
func (s *DB) PutArtifact(ctx context.Context, ref ArtifactRef, r io.Reader) (Artifact, error) {
	if s.objects == nil {
		return Artifact{}, errors.New("no object store configured for artifact bytes")
	}
	ref, err := normalizeRef(ref)
	if err != nil {
		return Artifact{}, err
	}
	spool, err := os.CreateTemp("", "nyxr-artifact-*")
	if err != nil {
		return Artifact{}, err
	}
	defer func() { spool.Close(); _ = os.Remove(spool.Name()) }()
	if err := spool.Chmod(0o600); err != nil {
		return Artifact{}, err
	}
	h := sha256.New()
	limit := s.MaxArtifact
	if limit <= 0 {
		limit = DefaultMaxArtifact
	}
	n, err := io.Copy(io.MultiWriter(spool, h), io.LimitReader(r, limit+1))
	if err != nil {
		return Artifact{}, err
	}
	if n > limit {
		return Artifact{}, fmt.Errorf("artifact exceeds the %d byte limit", limit)
	}
	hexID := hex.EncodeToString(h.Sum(nil))
	id := "sha256:" + hexID
	if ref.ID != "" && ref.ID != id {
		return Artifact{}, fmt.Errorf("artifact hash mismatch: content is %s, expected %s", id, ref.ID)
	}
	if ref.Size != 0 && ref.Size != n {
		return Artifact{}, fmt.Errorf("artifact size %d, expected %d", n, ref.Size)
	}
	ref.ID, ref.Size = id, n
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return Artifact{}, err
	}
	key := objectKey(hexID)
	if err := s.objects.Put(ctx, key, spool, n, hexID); err != nil {
		return Artifact{}, fmt.Errorf("store artifact object: %w", err)
	}
	now := s.now().UTC()
	err = s.write(ctx, func(t tx, _ int64) error {
		if _, err := registerArtifact(ctx, t, ref, now); err != nil {
			return err
		}
		_, err := t.exec(ctx, `UPDATE artifacts SET state = ?, object_key = ?, size = ?, stored_at = ?,
			media_type = CASE WHEN media_type = '' THEN ? ELSE media_type END WHERE id = ?`,
			ArtifactAvailable, key, n, ts(now), ref.MediaType, id)
		return err
	})
	if err != nil {
		return Artifact{}, err
	}
	a, _, err := s.artifact(ctx, id)
	return a, err
}

const artifactColumns = `id, kind, media_type, size, state, object_key, access, retain_until, lineage, scan_id, agent_id, registered_at, stored_at`

func artifactRow(row interface{ Scan(...any) error }) (Artifact, error) {
	var a Artifact
	var retain, registered, stored string
	err := row.Scan(&a.ID, &a.Kind, &a.MediaType, &a.Size, &a.State, &a.ObjectKey, &a.Access, &retain, &a.Lineage, &a.ScanID, &a.AgentID, &registered, &stored)
	a.RetainUntil, a.Registered, a.Stored = parseTS(retain), parseTS(registered), parseTS(stored)
	return a, err
}

func (s *DB) artifact(ctx context.Context, id string) (Artifact, bool, error) {
	a, err := artifactRow(s.db.QueryRowContext(ctx, s.q(`SELECT `+artifactColumns+` FROM artifacts WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	return a, err == nil, err
}

// OpenArtifact returns the verified bytes of an available artifact. The
// reader fails at EOF if the object no longer matches its hash. An object
// that vanished from storage marks the artifact missing.
func (s *DB) OpenArtifact(ctx context.Context, id string, grant Grant) (io.ReadCloser, Artifact, error) {
	hexID, err := parseArtifactID(id)
	if err != nil {
		return nil, Artifact{}, err
	}
	a, ok, err := s.artifact(ctx, id)
	if err != nil {
		return nil, a, err
	}
	if !ok {
		return nil, a, fmt.Errorf("%w: %s is not registered", ErrArtifactUnavailable, id)
	}
	if a.Access == AccessRestricted && !grant.Restricted {
		return nil, a, fmt.Errorf("%w: %s is %s", ErrAccessDenied, id, a.Access)
	}
	if a.State != ArtifactAvailable {
		return nil, a, fmt.Errorf("%w: %s is %s", ErrArtifactUnavailable, id, a.State)
	}
	if s.objects == nil {
		return nil, a, errors.New("no object store configured for artifact bytes")
	}
	rc, err := s.objects.Get(ctx, a.ObjectKey)
	if errors.Is(err, ErrObjectNotFound) {
		if werr := s.write(ctx, func(t tx, _ int64) error {
			_, err := t.exec(ctx, `UPDATE artifacts SET state = ? WHERE id = ? AND state = ?`, ArtifactMissing, id, ArtifactAvailable)
			return err
		}); werr != nil {
			return nil, a, werr
		}
		a.State = ArtifactMissing
		return nil, a, fmt.Errorf("%w: %s object is missing from %s", ErrArtifactUnavailable, id, s.objects.Location())
	}
	if err != nil {
		return nil, a, err
	}
	return &verifyingReader{rc: rc, h: sha256.New(), want: hexID, size: a.Size}, a, nil
}

type verifyingReader struct {
	rc   io.ReadCloser
	h    hash.Hash
	want string
	size int64
	n    int64
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	v.h.Write(p[:n])
	v.n += int64(n)
	if v.n > v.size {
		return n, errors.New("artifact object is larger than registered")
	}
	if errors.Is(err, io.EOF) && (v.n != v.size || hex.EncodeToString(v.h.Sum(nil)) != v.want) {
		return n, errors.New("artifact object does not match its hash")
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.rc.Close() }

// Artifacts lists artifacts, optionally of one state, newest first.
func (s *DB) Artifacts(ctx context.Context, state string, limit int) ([]Artifact, error) {
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	query := `SELECT ` + artifactColumns + ` FROM artifacts`
	args := []any{}
	if state != "" {
		query += ` WHERE state = ?`
		args = append(args, state)
	}
	query += ` ORDER BY registered_at DESC, id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Artifact{}
	for rows.Next() {
		a, err := artifactRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneArtifacts deletes the bytes of available artifacts whose retention
// ended before now. Their metadata stays, marked expired, so references
// still resolve to an explained absence.
func (s *DB) PruneArtifacts(ctx context.Context, now time.Time) (int, error) {
	if s.objects == nil {
		return 0, errors.New("no object store configured for artifact bytes")
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, object_key FROM artifacts WHERE state = ? AND retain_until <> '' AND retain_until < ?`),
		ArtifactAvailable, ts(now))
	if err != nil {
		return 0, err
	}
	type expired struct{ id, key string }
	var due []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.id, &e.key); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	pruned := 0
	for _, e := range due {
		// Mark first: a crash between the two steps leaves an orphan object,
		// never a row claiming bytes that are gone.
		var changed bool
		if err := s.write(ctx, func(t tx, _ int64) error {
			res, err := t.exec(ctx, `UPDATE artifacts SET state = ? WHERE id = ? AND state = ? AND retain_until <> '' AND retain_until < ?`,
				ArtifactExpired, e.id, ArtifactAvailable, ts(now))
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			changed = n == 1
			return nil
		}); err != nil {
			return pruned, err
		}
		if !changed {
			continue
		}
		if err := s.objects.Delete(ctx, e.key); err != nil {
			return pruned, err
		}
		pruned++
	}
	return pruned, nil
}

package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

// graph is the reconciliation input, loaded inside a write transaction.
type graph struct {
	nodes       []string            // sorted node keys
	lineage     map[string]string   // node -> lineage
	values      map[string]kindVals // node -> scoped kind -> current values
	joins       []pair              // active manual joins, by decision ID
	separations []pair
	// pred maps a node to the nodes its addresses belonged to before: a
	// provisional node replaced by the lineage's local identity, or local
	// identities the lineage merged or split. Entity IDs follow addresses.
	pred map[string][]string
}

type kindVals map[string]map[string]bool

type pair struct {
	id   int64
	a, b string
}

// loadGraph assigns every address its node (the lineage's reported local
// identity, else a provisional per-address node) and reads the current
// scoped value of each address and kind: the value seen last, so a replaced
// cloud instance behind a reused address does not conflict with itself.
func loadGraph(ctx context.Context, t tx) (*graph, error) {
	g := &graph{lineage: map[string]string{}, values: map[string]kindVals{}, pred: map[string][]string{}}
	rows, err := t.query(ctx, `SELECT a.lineage, a.address, a.node, COALESCE(m.node, '') FROM addresses a
		LEFT JOIN members m ON m.lineage = a.lineage AND m.address = a.address ORDER BY a.lineage, a.address`)
	if err != nil {
		return nil, err
	}
	type key struct{ lineage, address string }
	nodeOf := map[key]string{}
	type change struct{ lineage, address, node string }
	var changes []change
	for rows.Next() {
		var lineage, address, stored, member string
		if err := rows.Scan(&lineage, &address, &stored, &member); err != nil {
			rows.Close()
			return nil, err
		}
		want := member
		if want == "" {
			addr, _ := netip.ParseAddr(address)
			want = provisionalNode(lineage, addr)
		}
		if want != stored {
			changes = append(changes, change{lineage, address, want})
			g.pred[want] = append(g.pred[want], stored)
		}
		nodeOf[key{lineage, address}] = want
		g.lineage[want] = lineage
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range changes {
		if _, err := t.exec(ctx, `UPDATE addresses SET node = ? WHERE lineage = ? AND address = ?`, c.node, c.lineage, c.address); err != nil {
			return nil, err
		}
	}
	for node := range g.lineage {
		g.nodes = append(g.nodes, node)
	}
	sort.Strings(g.nodes)

	rows, err = t.query(ctx, `SELECT lineage, address, kind, value, last_seen FROM signals WHERE scoped = 1
		ORDER BY lineage, address, kind, last_seen DESC, value DESC`)
	if err != nil {
		return nil, err
	}
	type current struct{ lineage, address, kind string }
	seen := map[current]bool{}
	for rows.Next() {
		var lineage, address, kind, value, last string
		if err := rows.Scan(&lineage, &address, &kind, &value, &last); err != nil {
			rows.Close()
			return nil, err
		}
		c := current{lineage, address, kind}
		if seen[c] {
			continue // an older value of this address and kind
		}
		seen[c] = true
		node, ok := nodeOf[key{lineage, address}]
		if !ok {
			continue
		}
		if g.values[node] == nil {
			g.values[node] = kindVals{}
		}
		if g.values[node][kind] == nil {
			g.values[node][kind] = map[string]bool{}
		}
		g.values[node][kind][value] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The latest decision on a pair supersedes earlier ones; reverted
	// decisions do not count, so reverting the latest restores the previous.
	rows, err = t.query(ctx, `SELECT id, action, node_a, node_b FROM decisions
		WHERE action IN ('join', 'separate') AND reverted_by = 0 ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	decided := map[[2]string]bool{}
	for rows.Next() {
		var p pair
		var action string
		if err := rows.Scan(&p.id, &action, &p.a, &p.b); err != nil {
			rows.Close()
			return nil, err
		}
		k := [2]string{p.a, p.b}
		if decided[k] {
			continue
		}
		decided[k] = true
		if _, ok := g.lineage[p.a]; !ok {
			continue
		}
		if _, ok := g.lineage[p.b]; !ok {
			continue
		}
		if action == DecisionJoin {
			g.joins = append(g.joins, p)
		} else {
			g.separations = append(g.separations, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(g.joins, func(i, j int) bool { return g.joins[i].id < g.joins[j].id })
	return g, rows.Err()
}

// partition is union-find over nodes with per-component scoped values.
type partition struct {
	parent    map[string]string
	values    map[string]kindVals // root -> values
	conflicts []Conflict
}

func newPartition(g *graph) *partition {
	p := &partition{parent: map[string]string{}, values: map[string]kindVals{}}
	for _, n := range g.nodes {
		p.parent[n] = n
		vals := kindVals{}
		for kind, set := range g.values[n] {
			vals[kind] = map[string]bool{}
			for v := range set {
				vals[kind][v] = true
			}
			if len(set) > 1 {
				a, b := twoOf(set)
				p.conflicts = append(p.conflicts, Conflict{Reason: "lineage_contradiction", Kind: kind, NodeA: n, NodeB: n, ValueA: a, ValueB: b})
			}
		}
		p.values[n] = vals
	}
	return p
}

func twoOf(set map[string]bool) (string, string) {
	vals := make([]string, 0, len(set))
	for v := range set {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	return vals[0], vals[1]
}

func (p *partition) find(n string) string {
	for p.parent[n] != n {
		p.parent[n] = p.parent[p.parent[n]]
		n = p.parent[n]
	}
	return n
}

// valueConflict reports a scoped kind for which the two components hold
// different current values.
func (p *partition) valueConflict(ra, rb string) (kind, va, vb string, ok bool) {
	kinds := make([]string, 0, len(p.values[ra]))
	for k := range p.values[ra] {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		other := p.values[rb][k]
		if len(other) == 0 {
			continue
		}
		for _, x := range sortedKeys(p.values[ra][k]) {
			for _, y := range sortedKeys(other) {
				if x != y {
					return k, x, y, true
				}
			}
		}
	}
	return "", "", "", false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (p *partition) separated(g *graph, ra, rb string) (pair, bool) {
	for _, s := range g.separations {
		x, y := p.find(s.a), p.find(s.b)
		if (x == ra && y == rb) || (x == rb && y == ra) {
			return s, true
		}
	}
	return pair{}, false
}

func (p *partition) union(ra, rb string) {
	if rb < ra {
		ra, rb = rb, ra
	}
	p.parent[rb] = ra
	for k, set := range p.values[rb] {
		if p.values[ra][k] == nil {
			p.values[ra][k] = map[string]bool{}
		}
		for v := range set {
			p.values[ra][k][v] = true
		}
	}
	delete(p.values, rb)
}

// solve partitions nodes. Manual joins apply first, in decision order, then
// scoped signal edges in (kind, value, node) order, so the result depends
// only on the stored evidence and decisions, never on arrival order. A join
// that would put separated nodes together, or two different values of one
// scoped kind into one entity, is refused and kept as a conflict.
func solve(g *graph) *partition {
	p := newPartition(g)
	for _, j := range g.joins {
		ra, rb := p.find(j.a), p.find(j.b)
		if ra == rb {
			continue
		}
		if s, blocked := p.separated(g, ra, rb); blocked {
			p.conflicts = append(p.conflicts, Conflict{Reason: fmt.Sprintf("join_%d_blocked_by_separation_%d", j.id, s.id), NodeA: j.a, NodeB: j.b})
			continue
		}
		if kind, va, vb, ok := p.valueConflict(ra, rb); ok {
			// The operator decided; keep the contradiction visible.
			p.conflicts = append(p.conflicts, Conflict{Reason: fmt.Sprintf("join_%d_contradicts_scoped_value", j.id), Kind: kind, NodeA: j.a, NodeB: j.b, ValueA: va, ValueB: vb})
		}
		p.union(ra, rb)
	}
	type edgeKey struct{ kind, value string }
	holders := map[edgeKey][]string{}
	for _, n := range g.nodes {
		for kind, set := range g.values[n] {
			for v := range set {
				k := edgeKey{kind, v}
				holders[k] = append(holders[k], n)
			}
		}
	}
	keys := make([]edgeKey, 0, len(holders))
	for k, nodes := range holders {
		if len(nodes) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].value < keys[j].value
	})
	for _, k := range keys {
		nodes := holders[k]
		sort.Strings(nodes)
		for _, n := range nodes[1:] {
			ra, rb := p.find(nodes[0]), p.find(n)
			if ra == rb {
				continue
			}
			if s, blocked := p.separated(g, ra, rb); blocked {
				p.conflicts = append(p.conflicts, Conflict{Reason: fmt.Sprintf("separated_by_decision_%d", s.id), Kind: k.kind, NodeA: nodes[0], NodeB: n, ValueA: k.value, ValueB: k.value})
				continue
			}
			if kind, va, vb, ok := p.valueConflict(ra, rb); ok {
				p.conflicts = append(p.conflicts, Conflict{Reason: "scoped_value_conflict", Kind: kind, NodeA: nodes[0], NodeB: n, ValueA: va, ValueB: vb})
				continue
			}
			p.union(ra, rb)
		}
	}
	return p
}

// reconcile recomputes the partition and persists only the difference:
// node moves with audit events, entity revisions, and the conflict list.
// An entity keeps its ID through a change when it holds the most of the
// component's nodes (lowest ID on a tie); a split-off part gets a new ID.
func reconcile(ctx context.Context, t tx, revision int64, cause string, decision int64, now time.Time) (int, error) {
	g, err := loadGraph(ctx, t)
	if err != nil {
		return 0, err
	}
	p := solve(g)

	prev := map[string]int64{}
	rows, err := t.query(ctx, `SELECT node, entity FROM nodes`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var node string
		var entity int64
		if err := rows.Scan(&node, &entity); err != nil {
			rows.Close()
			return 0, err
		}
		prev[node] = entity
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	components := map[string][]string{}
	for _, n := range g.nodes {
		r := p.find(n)
		components[r] = append(components[r], n)
	}
	roots := make([]string, 0, len(components))
	for r := range components {
		roots = append(roots, r)
	}
	sort.Slice(roots, func(i, j int) bool { return components[roots[i]][0] < components[roots[j]][0] })

	assigned := map[string]int64{}
	claimed := map[int64]bool{}
	touched := map[int64]bool{}
	created := map[int64]bool{}
	for _, r := range roots {
		count := map[int64]int{}
		for _, n := range components[r] {
			if e, ok := prev[n]; ok {
				count[e]++
				continue
			}
			for _, p := range g.pred[n] {
				if e, ok := prev[p]; ok {
					count[e]++
				}
			}
		}
		candidates := make([]int64, 0, len(count))
		for e := range count {
			candidates = append(candidates, e)
		}
		sort.Slice(candidates, func(i, j int) bool {
			if count[candidates[i]] != count[candidates[j]] {
				return count[candidates[i]] > count[candidates[j]]
			}
			return candidates[i] < candidates[j]
		})
		var entity int64
		for _, e := range candidates {
			if !claimed[e] {
				entity = e
				break
			}
		}
		if entity == 0 {
			if entity, err = t.nextID(ctx, "next_entity"); err != nil {
				return 0, err
			}
			if _, err := t.exec(ctx, `INSERT INTO entities(id, revision, created_at, updated_at) VALUES (?, 0, ?, ?)`, entity, ts(now), ts(now)); err != nil {
				return 0, err
			}
			created[entity] = true
		}
		claimed[entity] = true
		for _, n := range components[r] {
			assigned[n] = entity
		}
	}

	moved := 0
	event := func(node string, from, to int64, why string) error {
		id, err := t.nextID(ctx, "next_event")
		if err != nil {
			return err
		}
		_, err = t.exec(ctx, `INSERT INTO events(id, node, from_entity, to_entity, cause, decision, revision, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, node, from, to, why, decision, revision, ts(now))
		return err
	}
	for _, n := range g.nodes {
		to, from := assigned[n], prev[n]
		if to == from {
			continue
		}
		why := cause
		if from == 0 {
			why += ":new_node"
			if _, err := t.exec(ctx, `INSERT INTO nodes(node, lineage, entity) VALUES (?, ?, ?)`, n, g.lineage[n], to); err != nil {
				return 0, err
			}
		} else {
			moved++
			touched[from] = true
			if _, err := t.exec(ctx, `UPDATE nodes SET entity = ? WHERE node = ?`, to, n); err != nil {
				return 0, err
			}
		}
		touched[to] = true
		if err := event(n, from, to, why); err != nil {
			return 0, err
		}
	}
	// A provisional node disappears once the lineage reports its address's
	// local identity (and a local identity disappears when its lineage
	// merges or splits it): retire it with an event.
	stale := make([]string, 0)
	for n := range prev {
		if _, ok := assigned[n]; !ok {
			stale = append(stale, n)
		}
	}
	sort.Strings(stale)
	for _, n := range stale {
		touched[prev[n]] = true
		if _, err := t.exec(ctx, `DELETE FROM nodes WHERE node = ?`, n); err != nil {
			return 0, err
		}
		if err := event(n, prev[n], 0, cause+":node_retired"); err != nil {
			return 0, err
		}
	}
	for e := range touched {
		if claimed[e] {
			if _, err := t.exec(ctx, `UPDATE entities SET revision = revision + 1, updated_at = ? WHERE id = ?`, ts(now), e); err != nil {
				return 0, err
			}
		} else if !created[e] {
			if _, err := t.exec(ctx, `DELETE FROM entities WHERE id = ?`, e); err != nil {
				return 0, err
			}
		}
	}
	if _, err := t.exec(ctx, `DELETE FROM conflicts`); err != nil {
		return 0, err
	}
	for _, c := range p.conflicts {
		if _, err := t.exec(ctx, `INSERT INTO conflicts(reason, kind, node_a, node_b, value_a, value_b) VALUES (?, ?, ?, ?, ?, ?)`,
			c.Reason, c.Kind, c.NodeA, c.NodeB, c.ValueA, c.ValueB); err != nil {
			return 0, err
		}
	}
	return moved, nil
}

func checkExpect(ctx context.Context, t tx, expect []EntityVersion) error {
	for _, ev := range expect {
		id, ok := parseEntityName(ev.ID)
		if !ok {
			return fmt.Errorf("invalid entity ID %q", ev.ID)
		}
		var rev int64
		err := t.row(ctx, `SELECT revision FROM entities WHERE id = ?`, id).Scan(&rev)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && rev != ev.Revision) {
			return fmt.Errorf("%w: %s", ErrStaleRevision, ev.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func nodeEntity(ctx context.Context, t tx, node string) (int64, error) {
	var e int64
	err := t.row(ctx, `SELECT entity FROM nodes WHERE node = ?`, node).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("unknown node %q", node)
	}
	return e, err
}

func validNote(note, actor string) (string, error) {
	note = strings.TrimSpace(note)
	if len(note) == 0 || len(note) > 500 {
		return "", errors.New("decision note must be 1 to 500 characters")
	}
	if len(actor) > 128 {
		return "", errors.New("decision actor is at most 128 bytes")
	}
	return note, nil
}

// Decide records a manual join or separation of two nodes and applies it in
// the same transaction. The latest decision on a pair supersedes earlier
// ones. A join that another separation still blocks, or a separation that
// another join still bridges, is refused with nothing changed.
func (s *DB) Decide(ctx context.Context, d Decision) (DecisionRecord, error) {
	var out DecisionRecord
	if d.Action != DecisionJoin && d.Action != DecisionSeparate {
		return out, errors.New("decision must be join or separate")
	}
	note, err := validNote(d.Note, d.Actor)
	if err != nil {
		return out, err
	}
	if d.NodeA == d.NodeB || d.NodeA == "" {
		return out, errors.New("two distinct nodes are required")
	}
	a, b := d.NodeA, d.NodeB
	if b < a {
		a, b = b, a
	}
	now := s.now().UTC()
	err = s.write(ctx, func(t tx, revision int64) error {
		if err := checkExpect(ctx, t, d.Expect); err != nil {
			return err
		}
		if _, err := nodeEntity(ctx, t, a); err != nil {
			return err
		}
		if _, err := nodeEntity(ctx, t, b); err != nil {
			return err
		}
		id, err := t.nextID(ctx, "next_decision")
		if err != nil {
			return err
		}
		if _, err := t.exec(ctx, `INSERT INTO decisions(id, action, node_a, node_b, note, actor, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, d.Action, a, b, note, d.Actor, ts(now)); err != nil {
			return err
		}
		moved, err := reconcile(ctx, t, revision, "decision:"+d.Action, id, now)
		if err != nil {
			return err
		}
		ea, err := nodeEntity(ctx, t, a)
		if err != nil {
			return err
		}
		eb, err := nodeEntity(ctx, t, b)
		if err != nil {
			return err
		}
		if d.Action == DecisionJoin && ea != eb {
			return errors.New("join refused: an active separation keeps these nodes apart; revert it first")
		}
		if d.Action == DecisionSeparate && ea == eb {
			return errors.New("separation refused: another active join still connects these nodes; revert it first")
		}
		out = DecisionRecord{ID: id, Action: d.Action, NodeA: a, NodeB: b, Note: note, Actor: d.Actor, DecidedAt: now, Moved: moved}
		return nil
	})
	return out, err
}

// Revert undoes a join or separation. The previous decision on the same pair,
// if any, becomes effective again; the reverted one stays in the audit.
func (s *DB) Revert(ctx context.Context, target int64, note, actor string, expect []EntityVersion) (DecisionRecord, error) {
	var out DecisionRecord
	note, err := validNote(note, actor)
	if err != nil {
		return out, err
	}
	now := s.now().UTC()
	err = s.write(ctx, func(t tx, revision int64) error {
		if err := checkExpect(ctx, t, expect); err != nil {
			return err
		}
		var action string
		var revertedBy int64
		err := t.row(ctx, `SELECT action, reverted_by FROM decisions WHERE id = ?`, target).Scan(&action, &revertedBy)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("decision %d does not exist", target)
		}
		if err != nil {
			return err
		}
		if action == DecisionRevert {
			return errors.New("a revert cannot be reverted; record a new decision instead")
		}
		if revertedBy != 0 {
			return fmt.Errorf("decision %d was already reverted by %d", target, revertedBy)
		}
		id, err := t.nextID(ctx, "next_decision")
		if err != nil {
			return err
		}
		if _, err := t.exec(ctx, `INSERT INTO decisions(id, action, target, note, actor, decided_at) VALUES (?, 'revert', ?, ?, ?, ?)`,
			id, target, note, actor, ts(now)); err != nil {
			return err
		}
		if _, err := t.exec(ctx, `UPDATE decisions SET reverted_by = ? WHERE id = ?`, id, target); err != nil {
			return err
		}
		moved, err := reconcile(ctx, t, revision, fmt.Sprintf("revert:%d", target), id, now)
		out = DecisionRecord{ID: id, Action: DecisionRevert, Target: target, Note: note, Actor: actor, DecidedAt: now, Moved: moved}
		return err
	})
	return out, err
}

// Decisions lists every decision in order.
func (s *DB) Decisions(ctx context.Context) ([]DecisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, action, node_a, node_b, target, note, actor, decided_at, reverted_by FROM decisions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DecisionRecord{}
	for rows.Next() {
		var d DecisionRecord
		var at string
		if err := rows.Scan(&d.ID, &d.Action, &d.NodeA, &d.NodeB, &d.Target, &d.Note, &d.Actor, &at, &d.RevertedBy); err != nil {
			return nil, err
		}
		d.DecidedAt = parseTS(at)
		out = append(out, d)
	}
	return out, rows.Err()
}

// History returns the membership audit of one node, or of all nodes.
func (s *DB) History(ctx context.Context, node string) ([]Event, error) {
	query, args := `SELECT id, node, from_entity, to_entity, cause, decision, revision, at FROM events`, []any{}
	if node != "" {
		query += ` WHERE node = ?`
		args = append(args, node)
	}
	rows, err := s.db.QueryContext(ctx, s.q(query+` ORDER BY id`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var from, to int64
		var at string
		if err := rows.Scan(&e.ID, &e.Node, &from, &to, &e.Cause, &e.Decision, &e.Revision, &at); err != nil {
			return nil, err
		}
		if from != 0 {
			e.FromEntity = entityName(from)
		}
		if to != 0 {
			e.ToEntity = entityName(to)
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Conflicts lists the contradictions of the last reconciliation.
func (s *DB) Conflicts(ctx context.Context) ([]Conflict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT reason, kind, node_a, node_b, value_a, value_b FROM conflicts ORDER BY node_a, node_b, reason, kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Conflict{}
	for rows.Next() {
		var c Conflict
		if err := rows.Scan(&c.Reason, &c.Kind, &c.NodeA, &c.NodeB, &c.ValueA, &c.ValueB); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Entities returns every reconciled entity with its nodes, addresses and
// portable IDs.
func (s *DB) Entities(ctx context.Context) ([]Entity, error) {
	var out []Entity
	err := s.read(ctx, func(t tx) error {
		var ns string
		if err := t.row(ctx, `SELECT namespace FROM central_meta WHERE id = 1`).Scan(&ns); err != nil {
			return err
		}
		byID := map[int64]*Entity{}
		var order []int64
		rows, err := t.query(ctx, `SELECT id, revision, updated_at FROM entities ORDER BY id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var e Entity
			var updated string
			if err := rows.Scan(&id, &e.Revision, &updated); err != nil {
				rows.Close()
				return err
			}
			e.ID, e.Updated = entityName(id), parseTS(updated)
			e.GlobalID = "urn:nyxr:central:" + ns + ":" + e.ID
			e.Nodes, e.PortableIDs = []Node{}, []string{}
			byID[id] = &e
			order = append(order, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		entityOf := map[string]int64{}
		nodeIndex := map[string]int{}
		rows, err = t.query(ctx, `SELECT node, lineage, entity FROM nodes ORDER BY node`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var n Node
			var entity int64
			if err := rows.Scan(&n.Key, &n.Lineage, &entity); err != nil {
				rows.Close()
				return err
			}
			if e := byID[entity]; e != nil {
				n.Addresses = []netip.Addr{}
				nodeIndex[n.Key] = len(e.Nodes)
				e.Nodes = append(e.Nodes, n)
				entityOf[n.Key] = entity
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = t.query(ctx, `SELECT node, address FROM addresses ORDER BY node, address`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var node, address string
			if err := rows.Scan(&node, &address); err != nil {
				rows.Close()
				return err
			}
			if e := byID[entityOf[node]]; e != nil {
				if addr, err := netip.ParseAddr(address); err == nil {
					e.Nodes[nodeIndex[node]].Addresses = append(e.Nodes[nodeIndex[node]].Addresses, addr)
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// Portable IDs and the scoped-signal link type.
		holders := map[int64]map[string]map[string]bool{} // entity -> portable ID -> nodes
		rows, err = t.query(ctx, `SELECT DISTINCT a.node, s.kind, s.value FROM signals s
			JOIN addresses a ON a.lineage = s.lineage AND a.address = s.address WHERE s.scoped = 1`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var node, kind, value string
			if err := rows.Scan(&node, &kind, &value); err != nil {
				rows.Close()
				return err
			}
			e := entityOf[node]
			if byID[e] == nil {
				continue
			}
			id := storage.PortableIdentityID(storage.IdentityValue{Kind: kind, Value: value, Scoped: true})
			if holders[e] == nil {
				holders[e] = map[string]map[string]bool{}
			}
			if holders[e][id] == nil {
				holders[e][id] = map[string]bool{}
			}
			holders[e][id][node] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		manual := map[int64]bool{}
		rows, err = t.query(ctx, `SELECT node_a, node_b FROM decisions WHERE action = 'join' AND reverted_by = 0`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a, b string
			if err := rows.Scan(&a, &b); err != nil {
				rows.Close()
				return err
			}
			if ea, ok := entityOf[a]; ok && ea == entityOf[b] {
				manual[ea] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range order {
			e := byID[id]
			signal := false
			for pid, nodes := range holders[id] {
				e.PortableIDs = append(e.PortableIDs, pid)
				if len(nodes) > 1 {
					signal = true
				}
			}
			sort.Strings(e.PortableIDs)
			switch {
			case len(e.Nodes) <= 1:
				e.Link = "single"
			case signal && manual[id]:
				e.Link = "scoped_signal+manual"
			case manual[id]:
				e.Link = "manual"
			default:
				e.Link = "scoped_signal"
			}
			if len(e.Nodes) > 0 {
				out = append(out, *e)
			}
		}
		return nil
	})
	return out, err
}

// Relations lists clue values shared by more than one entity: weak clues,
// and device-scoped strong values seen in different lineages. They are
// leads for an operator, never merge keys.
func (s *DB) Relations(ctx context.Context) ([]Relation, error) {
	var out []Relation
	err := s.read(ctx, func(t tx) error {
		rows, err := t.query(ctx, `SELECT 'weak', c.kind, c.value, n.entity FROM clues c
				JOIN addresses a ON a.lineage = c.lineage AND a.address = c.address JOIN nodes n ON n.node = a.node
			UNION
			SELECT 'device', s.kind, s.value, n.entity FROM signals s
				JOIN addresses a ON a.lineage = s.lineage AND a.address = s.address JOIN nodes n ON n.node = a.node
				WHERE s.scoped = 0`)
		if err != nil {
			return err
		}
		defer rows.Close()
		type key struct{ strength, kind, value string }
		groups := map[key]map[int64]bool{}
		for rows.Next() {
			var k key
			var entity int64
			if err := rows.Scan(&k.strength, &k.kind, &k.value, &entity); err != nil {
				return err
			}
			if groups[k] == nil {
				groups[k] = map[int64]bool{}
			}
			groups[k][entity] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for k, entities := range groups {
			if len(entities) < 2 {
				continue
			}
			r := Relation{Kind: k.kind, Value: k.value, Strength: k.strength}
			ids := make([]int64, 0, len(entities))
			for e := range entities {
				ids = append(ids, e)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, e := range ids {
				r.Entities = append(r.Entities, entityName(e))
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Strength != out[j].Strength {
				return out[i].Strength < out[j].Strength
			}
			if out[i].Kind != out[j].Kind {
				return out[i].Kind < out[j].Kind
			}
			return out[i].Value < out[j].Value
		})
		return nil
	})
	if out == nil {
		out = []Relation{}
	}
	return out, err
}

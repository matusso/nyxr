package storage

import (
	"context"
	"sort"
)

// IdentityHypothesis is a possible relationship suggested by shared weak
// clues. Scores are conservative heuristics, never automatic merge decisions.
type IdentityHypothesis struct {
	OtherID    string   `json:"other_id"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Blocked    bool     `json:"blocked"`
}

func enrichIdentityHypotheses(ctx context.Context, s *Store, graph []IdentityAsset) error {
	byID := make(map[string]int, len(graph))
	addressID := map[string]string{}
	for i := range graph {
		byID[graph[i].ID] = i
		graph[i].Hypotheses = []IdentityHypothesis{}
		if len(graph[i].Addresses) > 1 {
			links := map[identityValue]map[string]bool{}
			kinds := map[string]bool{}
			for _, signal := range graph[i].Signals {
				if !signal.Active {
					continue
				}
				key := identityValue{signal.Kind, signal.Value}
				if links[key] == nil {
					links[key] = map[string]bool{}
				}
				links[key][signal.Address.String()] = true
			}
			for key, addresses := range links {
				if len(addresses) < 2 {
					continue
				}
				kinds[key.kind] = true
				score := 85
				if key.kind == "snmp.engine_id" || key.kind == "smb.server_guid" || key.kind == "ssh.host_key_sha256" {
					score = 95
				}
				if externalKinds[key.kind] {
					score = 99
				}
				if score > graph[i].LinkConfidence {
					graph[i].LinkConfidence = score
				}
			}
			if len(kinds) > 1 && graph[i].LinkConfidence > 0 {
				graph[i].LinkConfidence += 3
				if graph[i].LinkConfidence > 99 {
					graph[i].LinkConfidence = 99
				}
			}
		}
		for _, address := range graph[i].Addresses {
			addressID[address.Address.String()] = graph[i].ID
		}
	}
	reviews, err := s.IdentityReviews(ctx)
	if err != nil {
		return err
	}
	latest := map[string]IdentityReview{}
	for _, review := range reviews {
		latest[review.AddressA.String()+"|"+review.AddressB.String()] = review
	}
	blockedPairs := map[string]bool{}
	for _, review := range latest {
		left, right := addressID[review.AddressA.String()], addressID[review.AddressB.String()]
		if left == "" || right == "" {
			continue
		}
		if review.Decision == "join" && left == right && len(graph[byID[left]].Addresses) > 1 {
			graph[byID[left]].LinkConfidence = 100
		}
		if review.Decision == "separate" && left != right {
			if right < left {
				left, right = right, left
			}
			blockedPairs[left+"|"+right] = true
		}
	}
	relations, err := s.IdentityRelations(ctx)
	if err != nil {
		return err
	}
	type candidate struct {
		kinds    map[string]bool
		evidence []string
	}
	candidates := map[string]*candidate{}
	for _, relation := range relations {
		key := relation.LeftID + "|" + relation.RightID
		c := candidates[key]
		if c == nil {
			c = &candidate{kinds: map[string]bool{}}
			candidates[key] = c
		}
		c.kinds[relation.Kind] = true
		c.evidence = append(c.evidence, relation.Kind+": "+relation.Value)
	}
	for key, c := range candidates {
		var left, right string
		for i := range key {
			if key[i] == '|' {
				left, right = key[:i], key[i+1:]
				break
			}
		}
		li, lok := byID[left]
		ri, rok := byID[right]
		if !lok || !rok {
			continue
		}
		score := 0
		if c.kinds["hostname"] {
			score += 35
		}
		if c.kinds["upnp_uuid"] {
			score += 45
		}
		if c.kinds["lldp_chassis_id"] {
			score += 55
		}
		if c.kinds["certificate_sha256"] {
			score += 25
		}
		if c.kinds["certificate_dns_name"] {
			score += 10
		}
		if score > 70 {
			score = 70
		}
		blocked := blockedPairs[key] || strongSignalConflict(graph[li], graph[ri])
		if blocked {
			score = 0
		}
		sort.Strings(c.evidence)
		graph[li].Hypotheses = append(graph[li].Hypotheses, IdentityHypothesis{OtherID: right, Confidence: score, Evidence: c.evidence, Blocked: blocked})
		graph[ri].Hypotheses = append(graph[ri].Hypotheses, IdentityHypothesis{OtherID: left, Confidence: score, Evidence: c.evidence, Blocked: blocked})
	}
	for i := range graph {
		sort.Slice(graph[i].Hypotheses, func(a, b int) bool {
			x, y := graph[i].Hypotheses[a], graph[i].Hypotheses[b]
			if x.Confidence != y.Confidence {
				return x.Confidence > y.Confidence
			}
			return x.OtherID < y.OtherID
		})
	}
	return nil
}

func strongSignalConflict(a, b IdentityAsset) bool {
	for _, kind := range []string{"snmp.engine_id", "smb.server_guid", "ssh.host_key_sha256",
		"kubernetes.node_uid", "cloud.aws.instance_id", "cloud.azure.vm_id", "cloud.gcp.instance_id"} {
		left, right := map[string]bool{}, map[string]bool{}
		for _, signal := range a.Signals {
			if signal.Active && signal.Kind == kind {
				left[signal.Value] = true
			}
		}
		for _, signal := range b.Signals {
			if signal.Active && signal.Kind == kind {
				right[signal.Value] = true
			}
		}
		if len(left) == 0 || len(right) == 0 {
			continue
		}
		shared := false
		for value := range left {
			if right[value] {
				shared = true
				break
			}
		}
		if !shared {
			return true
		}
	}
	return false
}

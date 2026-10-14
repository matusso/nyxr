package storage

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packet"
)

const lldpFrameSchema = "nyxr/lldp-frame/v1"
const maxRetainedLLDPFrame = 2048
const maxRetainedLLDPBytesPerImport = 16 << 20

// PassiveLink is an LLDP neighbor seen on an imported Ethernet capture.
// ManagementAddress and IdentityID may be empty; LLDP need not advertise one.
type PassiveLink struct {
	ID                int64              `json:"id"`
	ScanID            string             `json:"scan_id"`
	ObservedAt        time.Time          `json:"observed_at"`
	ValidUntil        time.Time          `json:"valid_until"`
	Validity          string             `json:"validity"`
	LocalInterface    string             `json:"local_interface,omitempty"`
	VLANID            uint16             `json:"vlan_id,omitempty"`
	SourceMAC         string             `json:"source_mac"`
	ChassisID         string             `json:"chassis_id"`
	PortID            string             `json:"port_id"`
	TTLSeconds        uint16             `json:"ttl_seconds,omitempty"`
	FrameIndex        int                `json:"frame_index,omitempty"`
	FrameHash         string             `json:"frame_hash,omitempty"`
	Source            *observe.SourceRef `json:"source,omitempty"`
	EvidenceStatus    string             `json:"evidence_status"`
	Conflict          bool               `json:"conflict,omitempty"`
	ManagementAddress string             `json:"management_address,omitempty"`
	IdentityID        string             `json:"identity_id,omitempty"`
}

// ImportPassiveCapture stores source-address sightings and LLDP neighbors
// from a pcap/pcapng file. Passive source MACs never become automatic merge
// keys. The frame and observation batches are bounded independently of input.
func (s *Store) ImportPassiveCapture(ctx context.Context, input io.Reader, localInterface string) (observe.Scan, error) {
	reader, err := capture.NewReader(input)
	if err != nil {
		return observe.Scan{}, err
	}
	now := time.Now().UTC()
	scan := observe.Scan{ID: observe.NewScanID(now), Profile: "passive-import", Started: now, Status: "running"}
	if err := s.BeginScan(ctx, scan); err != nil {
		return scan, err
	}
	decoder := packet.NewDecoder()
	batch := make([]observe.Observation, 0, 256)
	addresses := map[netip.Addr]bool{}
	retainedLLDPBytes := 0
	finish := func(importErr error) (observe.Scan, error) {
		if len(batch) > 0 && importErr == nil {
			if err := s.AddObservations(ctx, batch); err != nil && importErr == nil {
				importErr = err
			}
		}
		scan.Finished = time.Now().UTC()
		scan.Targets = len(addresses)
		scan.Status = "completed"
		if importErr != nil {
			scan.Status, scan.Error = "failed", importErr.Error()
		}
		if err := s.FinishScan(ctx, scan); err != nil && importErr == nil {
			importErr = err
		}
		return scan, importErr
	}
	for frames := 0; frames < 1_000_000; frames++ {
		record, err := reader.NextRecord()
		if errors.Is(err, io.EOF) {
			return finish(nil)
		}
		if err != nil {
			return finish(err)
		}
		if len(record.Data) > 65535 {
			continue
		}
		at := record.Timestamp
		if at.IsZero() {
			at = now
		}
		mac, vlan, kind, payload, ok := ethernetHeader(record.Data)
		if !ok {
			continue
		}
		fields := map[string]string{"capture.source_mac": mac}
		if localInterface != "" {
			fields["capture.interface"] = localInterface
		}
		if vlan != 0 {
			fields["vlan.id"] = fmt.Sprint(vlan)
		}
		if decoded, valid := decoder.Decode(record.Data); valid && decoded.Source.IsValid() &&
			!decoded.Source.IsMulticast() && !decoded.Source.IsUnspecified() {
			o := observe.Observation{Kind: observe.KindHost, Timestamp: at, Target: decoded.Source,
				Transport: "passive", State: "observed", Confidence: 60, Reason: "source packet in capture",
				Probe: "pcap-passive", MAC: mac, Fields: fields}
			o.Stamp(scan.ID)
			batch = append(batch, o)
			addresses[o.Target] = true
			scan.Observations++
		}
		if kind == 0x88cc {
			chassis, port, management, ttl, valid := parseLLDP(payload)
			if valid {
				link := PassiveLink{ScanID: scan.ID, ObservedAt: at, LocalInterface: localInterface,
					VLANID: vlan, SourceMAC: mac, ChassisID: chassis, PortID: port, ManagementAddress: management.String(),
					TTLSeconds: ttl, FrameIndex: frames, FrameHash: observe.ArtifactID(record.Data),
					ValidUntil: at.Add(time.Duration(ttl) * time.Second)}
				if !management.IsValid() {
					link.ManagementAddress = ""
				}
				var source []byte
				if len(record.Data) <= maxRetainedLLDPFrame &&
					retainedLLDPBytes+len(record.Data) <= maxRetainedLLDPBytesPerImport {
					var err error
					source, err = json.Marshal(struct {
						Schema     string `json:"schema"`
						ScanID     string `json:"scan_id"`
						FrameIndex int    `json:"frame_index"`
						Frame      []byte `json:"frame"`
					}{lldpFrameSchema, scan.ID, frames, record.Data})
					if err != nil {
						return finish(err)
					}
					link.Source = &observe.SourceRef{Owner: "next-gen", SourceSchema: lldpFrameSchema,
						ArtifactID: observe.ArtifactID(source), RunID: scan.ID}
					retainedLLDPBytes += len(record.Data)
				}
				if err := s.addPassiveLink(ctx, link, source); err != nil {
					return finish(err)
				}
				if management.IsValid() {
					lldpFields := map[string]string{"lldp.chassis_id": chassis, "lldp.port_id": port,
						"capture.source_mac": mac}
					if localInterface != "" {
						lldpFields["capture.interface"] = localInterface
					}
					if vlan != 0 {
						lldpFields["vlan.id"] = fmt.Sprint(vlan)
					}
					o := observe.Observation{Kind: observe.KindHost, Timestamp: at, Target: management,
						Transport: "passive", State: "observed", Confidence: 70, Reason: "LLDP management address",
						Probe: "lldp-passive", MAC: mac, Fields: lldpFields}
					o.Stamp(scan.ID)
					batch = append(batch, o)
					addresses[o.Target] = true
					scan.Observations++
				}
			}
		}
		if len(batch) >= 256 {
			if err := s.AddObservations(ctx, batch); err != nil {
				batch = nil
				return finish(err)
			}
			batch = batch[:0]
		}
	}
	return finish(errors.New("capture exceeds one million frames"))
}

func ethernetHeader(frame []byte) (string, uint16, uint16, []byte, bool) {
	if len(frame) < 14 {
		return "", 0, 0, nil, false
	}
	mac := net.HardwareAddr(frame[6:12]).String()
	kind := binary.BigEndian.Uint16(frame[12:14])
	at := 14
	var vlan uint16
	for i := 0; i < 2 && (kind == 0x8100 || kind == 0x88a8); i++ {
		if len(frame) < at+4 {
			return "", 0, 0, nil, false
		}
		vlan = binary.BigEndian.Uint16(frame[at:at+2]) & 0x0fff
		kind = binary.BigEndian.Uint16(frame[at+2 : at+4])
		at += 4
	}
	return mac, vlan, kind, frame[at:], true
}

func parseLLDP(payload []byte) (string, string, netip.Addr, uint16, bool) {
	var chassis, port string
	var management netip.Addr
	var ttl uint16
	for len(payload) >= 2 {
		header := binary.BigEndian.Uint16(payload[:2])
		kind, size := header>>9, int(header&0x1ff)
		payload = payload[2:]
		if len(payload) < size {
			return "", "", netip.Addr{}, 0, false
		}
		value := payload[:size]
		payload = payload[size:]
		if kind == 0 {
			break
		}
		switch kind {
		case 1:
			if len(value) > 1 && len(value) <= 256 {
				chassis = fmt.Sprintf("%d:%s", value[0], hex.EncodeToString(value[1:]))
			}
		case 2:
			if len(value) > 1 && len(value) <= 256 {
				port = fmt.Sprintf("%d:%s", value[0], hex.EncodeToString(value[1:]))
			}
		case 3:
			if len(value) == 2 {
				ttl = binary.BigEndian.Uint16(value)
			}
		case 8:
			if len(value) < 2 {
				continue
			}
			length := int(value[0])
			if length < 2 || length+1 > len(value) {
				continue
			}
			address, ok := netip.AddrFromSlice(value[2 : 1+length])
			if ok && ((value[1] == 1 && address.Is4()) || (value[1] == 2 && address.Is6())) &&
				!address.IsMulticast() && !address.IsUnspecified() {
				management = address
			}
		}
	}
	return chassis, port, management, ttl, chassis != "" && port != ""
}

func (s *Store) addPassiveLink(ctx context.Context, link PassiveLink, source []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	artifact := ""
	if link.Source != nil {
		artifact = link.Source.ArtifactID
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO passive_links(scan_id, observed_at, local_interface, vlan_id,
		source_mac, chassis_id, port_id, management_address, ttl_seconds, frame_index, frame_hash, valid_until, source_artifact_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		link.ScanID, ts(link.ObservedAt), link.LocalInterface, link.VLANID, link.SourceMAC,
		link.ChassisID, link.PortID, link.ManagementAddress, link.TTLSeconds, link.FrameIndex, link.FrameHash,
		ts(link.ValidUntil), artifact).Scan(&id)
	if err != nil {
		return err
	}
	if len(source) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO passive_link_sources(link_id, artifact_id, source) VALUES (?, ?, ?)`,
			id, artifact, source); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PassiveLinks(ctx context.Context) ([]PassiveLink, error) {
	links, _, err := s.passiveLinks(ctx, 0, time.Time{})
	return links, err
}

func (s *Store) passiveLinks(ctx context.Context, limit int, at time.Time) ([]PassiveLink, bool, error) {
	query := `SELECT p.id, p.scan_id, p.observed_at, p.valid_until, p.local_interface, p.vlan_id,
		p.source_mac, p.chassis_id, p.port_id, p.management_address, p.ttl_seconds, p.frame_index, p.frame_hash,
		p.source_artifact_id,
		COALESCE((SELECT e.to_identity FROM identity_membership_events e
			WHERE e.address = p.management_address AND e.observed_at <= p.observed_at
			ORDER BY e.observed_at DESC, e.id DESC LIMIT 1), '')
		FROM passive_links p`
	args := []any{}
	if !at.IsZero() {
		query += ` WHERE (p.ttl_seconds > 0 AND p.observed_at <= ? AND p.valid_until > ?)
			OR (p.ttl_seconds = 0 AND p.observed_at = ?)`
		args = append(args, ts(at), ts(at), ts(at))
	}
	query += ` ORDER BY p.observed_at DESC, p.id DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit+1)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	out := []PassiveLink{}
	truncated := false
	for rows.Next() {
		var link PassiveLink
		var observed, until string
		var artifact string
		if err := rows.Scan(&link.ID, &link.ScanID, &observed, &until, &link.LocalInterface, &link.VLANID, &link.SourceMAC,
			&link.ChassisID, &link.PortID, &link.ManagementAddress, &link.TTLSeconds, &link.FrameIndex, &link.FrameHash,
			&artifact, &link.IdentityID); err != nil {
			rows.Close()
			return nil, false, err
		}
		if limit > 0 && len(out) == limit {
			truncated = true
			break
		}
		link.ObservedAt, link.ValidUntil = parseTS(observed), parseTS(until)
		link.Validity = "point_unknown_ttl"
		if link.FrameHash != "" && link.TTLSeconds > 0 {
			link.Validity = "advertised_ttl"
		}
		link.EvidenceStatus = "legacy_unavailable"
		if link.FrameHash != "" {
			link.EvidenceStatus = "hash_only"
		}
		if artifact != "" {
			link.Source = &observe.SourceRef{Owner: "next-gen", SourceSchema: lldpFrameSchema,
				ArtifactID: artifact, RunID: link.ScanID}
			link.EvidenceStatus = "retained"
		}
		out = append(out, link)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

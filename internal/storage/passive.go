package storage

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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

// PassiveLink is an LLDP neighbor seen on an imported Ethernet capture.
// ManagementAddress and IdentityID may be empty; LLDP need not advertise one.
type PassiveLink struct {
	ScanID            string    `json:"scan_id"`
	ObservedAt        time.Time `json:"observed_at"`
	LocalInterface    string    `json:"local_interface,omitempty"`
	VLANID            uint16    `json:"vlan_id,omitempty"`
	SourceMAC         string    `json:"source_mac"`
	ChassisID         string    `json:"chassis_id"`
	PortID            string    `json:"port_id"`
	ManagementAddress string    `json:"management_address,omitempty"`
	IdentityID        string    `json:"identity_id,omitempty"`
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
			chassis, port, management, valid := parseLLDP(payload)
			if valid {
				link := PassiveLink{ScanID: scan.ID, ObservedAt: at, LocalInterface: localInterface,
					VLANID: vlan, SourceMAC: mac, ChassisID: chassis, PortID: port, ManagementAddress: management.String()}
				if !management.IsValid() {
					link.ManagementAddress = ""
				}
				if err := s.addPassiveLink(ctx, link); err != nil {
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

func parseLLDP(payload []byte) (string, string, netip.Addr, bool) {
	var chassis, port string
	var management netip.Addr
	for len(payload) >= 2 {
		header := binary.BigEndian.Uint16(payload[:2])
		kind, size := header>>9, int(header&0x1ff)
		payload = payload[2:]
		if len(payload) < size {
			return "", "", netip.Addr{}, false
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
	return chassis, port, management, chassis != "" && port != ""
}

func (s *Store) addPassiveLink(ctx context.Context, link PassiveLink) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO passive_links(scan_id, observed_at, local_interface, vlan_id,
		source_mac, chassis_id, port_id, management_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		link.ScanID, ts(link.ObservedAt), link.LocalInterface, link.VLANID, link.SourceMAC,
		link.ChassisID, link.PortID, link.ManagementAddress)
	return err
}

func (s *Store) PassiveLinks(ctx context.Context) ([]PassiveLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.scan_id, p.observed_at, p.local_interface, p.vlan_id,
		p.source_mac, p.chassis_id, p.port_id, p.management_address, COALESCE(m.identity_id, 0)
		FROM passive_links p LEFT JOIN assets a ON a.address = p.management_address
		LEFT JOIN identity_members m ON m.asset_id = a.id ORDER BY p.observed_at DESC, p.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PassiveLink{}
	for rows.Next() {
		var link PassiveLink
		var at string
		var identityID int64
		if err := rows.Scan(&link.ScanID, &at, &link.LocalInterface, &link.VLANID, &link.SourceMAC,
			&link.ChassisID, &link.PortID, &link.ManagementAddress, &identityID); err != nil {
			return nil, err
		}
		link.ObservedAt = parseTS(at)
		if identityID != 0 {
			link.IdentityID = identityName(identityID)
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

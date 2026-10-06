package storage

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/matusso/nyxr/internal/capture"
)

func TestPassiveCaptureImportsLLDPTopologyWithoutAutomaticMerge(t *testing.T) {
	frame := []byte{1, 0x80, 0xc2, 0, 0, 0x0e, 2, 1, 2, 3, 4, 5, 0x81, 0x00, 0, 100, 0x88, 0xcc}
	appendTLV := func(kind uint16, value []byte) {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], kind<<9|uint16(len(value)))
		frame = append(frame, header[:]...)
		frame = append(frame, value...)
	}
	appendTLV(1, []byte{4, 2, 1, 2, 3, 4, 5})
	appendTLV(2, []byte{5, 'p', 'o', 'r', 't'})
	appendTLV(3, []byte{0, 120})
	appendTLV(8, []byte{5, 1, 192, 0, 2, 5, 2, 0, 0, 0, 1, 0})
	appendTLV(0, nil)
	var file bytes.Buffer
	writer, err := capture.NewPCAPNGWriter(&file, "en0", 65535, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(t0, frame, len(frame), capture.DirectionRX, 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	s, _ := openTest(t)
	scan, err := s.ImportPassiveCapture(ctx, &file, "en0")
	if err != nil || scan.Observations != 1 || scan.Status != "completed" {
		t.Fatalf("import: %+v, %v", scan, err)
	}
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 1 || graph[0].LinkConfidence != 0 || len(graph[0].Clues) != 4 ||
		len(graph[0].Topology) != 1 || graph[0].Topology[0].PortID != "5:706f7274" {
		t.Fatalf("passive identity: %+v, %v", graph, err)
	}
	links, err := s.PassiveLinks(ctx)
	if err != nil || len(links) != 1 || links[0].VLANID != 100 || links[0].LocalInterface != "en0" ||
		links[0].ManagementAddress != "192.0.2.5" || links[0].IdentityID != graph[0].ID {
		t.Fatalf("LLDP links: %+v, %v", links, err)
	}
}

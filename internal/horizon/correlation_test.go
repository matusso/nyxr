package horizon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

func fixtureProbe(t *testing.T, ipv6 bool) packet.ForgeSpec {
	t.Helper()
	link := testLink()
	target := netip.MustParseAddr("192.0.2.10")
	if ipv6 {
		link.SourceIP = netip.MustParseAddr("2001:db8::1")
		target = netip.MustParseAddr("2001:db8::10")
	}
	return packet.ForgeSpec{SourceMAC: link.SourceMAC, DestinationMAC: link.NextHopMAC, SourceIP: link.SourceIP, DestinationIP: target, Protocol: 6, SourcePort: 50000, DestPort: 443, TCPFlags: 2, Sequence: 42, Window: 64240, HopLimit: 64, ID: 42, DontFragment: true, Experiment: true}
}
func fixtureReply(t *testing.T, sent packet.ForgeSpec, shift bool) []byte {
	t.Helper()
	frames, err := packet.ForgeFrames(sent)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := packet.NewDecoder().Decode(frames[0])
	if shift {
		if p.Destination.Is4() {
			p.Destination = netip.MustParseAddr("192.0.2.99")
		} else {
			p.Destination = netip.MustParseAddr("2001:db8::99")
		}
	}
	reply, err := syntheticReply(frames[0], p, true)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}
func fixtureICMP(t *testing.T, sent packet.ForgeSpec, typ uint8, short bool) []byte {
	t.Helper()
	frames, err := packet.ForgeFrames(sent)
	if err != nil {
		t.Fatal(err)
	}
	quote := frames[0][14:]
	if short {
		h := 20
		if sent.SourceIP.Is6() {
			h = 40
		}
		quote = quote[:h+7]
	}
	eth := &layers.Ethernet{SrcMAC: sent.DestinationMAC, DstMAC: sent.SourceMAC}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if sent.SourceIP.Is4() {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 32, Protocol: layers.IPProtocolICMPv4, SrcIP: netip.MustParseAddr("192.0.2.254").AsSlice(), DstIP: sent.SourceIP.AsSlice()}
		icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, 0)}
		err = gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(quote))
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 32, NextHeader: layers.IPProtocolICMPv6, SrcIP: netip.MustParseAddr("2001:db8::fe").AsSlice(), DstIP: sent.SourceIP.AsSlice()}
		icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, 0)}
		if err = icmp.SetNetworkLayerForChecksum(ip); err == nil {
			err = gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(append(make([]byte, 4), quote...)))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
func withExtension(frame []byte) []byte {
	f := append([]byte(nil), frame[:54]...)
	f[20] = 60
	binary.BigEndian.PutUint16(f[18:20], binary.BigEndian.Uint16(f[18:20])+8)
	f = append(f, 6, 0, 0, 0, 0, 0, 0, 0)
	return append(f, frame[54:]...)
}

// These deterministic files include truncated quotes, malformed frames,
// checksums, extensions, fragments, router errors and changed responder paths.
// Regenerate explicitly with NYXR_UPDATE_FIXTURES=1 go test -run TestPhase2Fixtures.
func TestPhase2Fixtures(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			sent := fixtureProbe(t, ipv6)
			reply := fixtureReply(t, sent, false)
			bad := append([]byte(nil), reply...)
			bad[len(bad)-3] ^= 1
			frames := [][]byte{reply, fixtureReply(t, sent, true), {1, 2, 3}, bad}
			want := 2
			if ipv6 {
				frames = append(frames, withExtension(reply))
				want++
				for _, typ := range []uint8{1, 2, 3, 4} {
					frames = append(frames, fixtureICMP(t, sent, typ, false))
					want++
				}
				frames = append(frames, fixtureICMP(t, sent, 3, true))
				fragment := withExtension(reply)
				fragment[20] = 44
				frames = append(frames, fragment)
				malformed := withExtension(reply)
				malformed[55] = 255
				frames = append(frames, malformed)
			} else {
				for _, typ := range []uint8{3, 11, 12} {
					frames = append(frames, fixtureICMP(t, sent, typ, false))
					want++
				}
				frames = append(frames, fixtureICMP(t, sent, 11, true))
			}
			path := "testdata/correlation-" + name + ".pcapng"
			if os.Getenv("NYXR_UPDATE_FIXTURES") == "1" {
				var data bytes.Buffer
				w, err := capture.NewPCAPNGWriter(&data, "fixture", 2048, "nyxr phase2 fixture")
				if err != nil {
					t.Fatal(err)
				}
				for i, frame := range frames {
					if err := w.WritePacket(time.Unix(1700000000, int64(i)*1000), frame, len(frame), capture.DirectionRX, uint64(i+1), fmt.Sprintf("fixture %d", i)); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReplayCaptureFixtures(bytes.NewReader(data), sent, 1<<20)
			if err != nil || len(got) != want {
				t.Fatalf("fixture replay: %d want %d: %v", len(got), want, err)
			}
			if got[1].Correlation != "ambiguous-path" {
				t.Fatal("path shift promoted to exact")
			}
			for _, f := range got[2:] {
				if f.ResponseClass != "icmp-error" && f.ResponseClass != "syn-ack" {
					t.Fatal(f)
				}
			}
			for _, frame := range frames {
				for n := 0; n < len(frame); n++ {
					_, _ = correlateRich(frame[:n], sent)
				}
			}
			stale := sent
			stale.Sequence++
			if f, ok := correlateRich(reply, stale); ok {
				t.Fatalf("stale token matched: %+v", f)
			}
		})
	}
}

func smallExperiment(t *testing.T) model.Experiment {
	e := testExperiment(t)
	e.Spec.Execution.Replicates = 2
	e.Spec.Limits.MaxPackets = 8
	return e
}
func TestRichRuntimeAndReplay(t *testing.T) {
	for _, mode := range []string{"icmp", "ambiguous", "path-change", "delayed", "cancel-drain", "backend-reply"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			sim, _ := NewSimulator("loss")
			defer sim.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var queue [][]byte
			var old []byte
			sends := 0
			failure := errors.New("fixture backend failure")
			ioBackend := executorIO{PacketIO: sim,
				send: func(ctx context.Context, frames [][]byte) (int, error) {
					p, _ := packet.NewDecoder().Decode(frames[0])
					if p.TCPFlags == 2 {
						sends++
						sent := packet.ForgeSpec{SourceIP: p.Source, DestinationIP: p.Destination, SourceMAC: frames[0][6:12], DestinationMAC: frames[0][:6], Protocol: 6, SourcePort: p.SourcePort, DestPort: p.DestPort, Sequence: p.TCPSeq, TCPFlags: 2, HopLimit: 64, Window: 64240, Experiment: true}
						reply := fixtureReply(t, sent, false)
						switch mode {
						case "icmp":
							queue = append(queue, fixtureICMP(t, sent, 11, false))
						case "ambiguous":
							queue = append(queue, fixtureReply(t, sent, true))
						case "path-change":
							queue = append(queue, reply, fixtureReply(t, sent, true))
						case "delayed":
							if sends == 1 {
								old = reply
							} else if sends == 2 {
								queue = append(queue, old, reply)
							} else {
								queue = append(queue, reply)
							}
						default:
							queue = append(queue, reply)
						}
					}
					return sim.SendBatch(ctx, frames)
				},
				receive: func(window context.Context, buffers [][]byte) (int, error) {
					if mode == "cancel-drain" && ctx.Err() == nil {
						cancel()
						return 0, context.Canceled
					}
					if len(queue) > 0 {
						frame := queue[0]
						queue = queue[1:]
						buffers[0] = buffers[0][:copy(buffers[0], frame)]
						if mode == "backend-reply" {
							return 1, failure
						}
						return 1, nil
					}
					<-window.Done()
					return 0, window.Err()
				},
			}
			r, err := Run(ctx, smallExperiment(t), testPolicy(), testLink(), ioBackend)
			if mode == "cancel-drain" || mode == "backend-reply" {
				if err == nil || r.Completed || sends != 1 {
					t.Fatalf("stop failed %d %v", sends, err)
				}
			} else if err != nil || !r.Completed {
				t.Fatal(err)
			}
			if r.Comparison.Status != "unresolved" {
				t.Fatal("confounded inference")
			}
			switch mode {
			case "icmp":
				if !hasFlag(r.Trials[0].QualityFlags, "icmp-error") || r.PacketsTX != 4 {
					t.Fatal("ICMP cleanup/accounting")
				}
			case "ambiguous":
				if !hasFlag(r.Trials[0].QualityFlags, "ambiguous-correlation") || r.PacketsTX != 4 {
					t.Fatal("ambiguous cleanup/accounting")
				}
			case "path-change":
				if !hasFlag(r.Trials[0].QualityFlags, "path-change") {
					t.Fatal("path change lost")
				}
			case "delayed":
				if !hasFlag(r.Trials[0].QualityFlags, "delayed-response") || r.Trials[1].Evidence[1].RelatedFlowID != r.Trials[0].FlowID {
					t.Fatal("delayed attribution lost")
				}
			case "cancel-drain":
				if len(r.Trials[0].Evidence) != 2 || r.Trials[0].Evidence[1].Direction != "late-rx" || r.PacketsTX != 1 {
					t.Fatal("drain transmitted or lost evidence")
				}
			case "backend-reply":
				if !hasFlag(r.Trials[0].QualityFlags, "cleanup-skipped") {
					t.Fatal("cleanup outcome lost")
				}
			}
			roundTrip(t, r)
		})
	}
}

type metadataIO struct {
	executorIO
	precision, delay int64
	timestampOffset  time.Duration
}

func (m *metadataIO) ReceiveBatchMetadata(ctx context.Context, buffers [][]byte, meta []packetio.ReceiveMetadata) (int, error) {
	n, err := m.executorIO.ReceiveBatch(ctx, buffers)
	if n > 0 {
		meta[0] = packetio.ReceiveMetadata{Timestamp: time.Now().Add(m.timestampOffset), ClockSource: "fixture/clock", ResolutionNS: 1000, PrecisionNS: &m.precision, QueueDelayNS: &m.delay}
	}
	return n, err
}
func TestTimestampMetadata(t *testing.T) {
	t.Parallel()
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	m := &metadataIO{executorIO: executorIO{PacketIO: sim}, precision: 5000, delay: 1234}
	r, err := Run(context.Background(), smallExperiment(t), testPolicy(), testLink(), m)
	if err != nil {
		t.Fatal(err)
	}
	timing := r.Trials[0].Evidence[1].Timing
	if timing.ClockSource != "fixture/clock" || *timing.PrecisionNS != 5000 || *timing.QueueDelayNS != 1234 {
		t.Fatal(timing)
	}
	if r.Trials[0].Evidence[0].Timing.PrecisionNS != nil {
		t.Fatal("uncalibrated software precision invented")
	}
	m.precision, m.delay = 99, 99
	if *timing.PrecisionNS != 5000 || *timing.QueueDelayNS != 1234 {
		t.Fatal("borrowed metadata mutated retained evidence")
	}
	roundTrip(t, r)
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk failure") }
func TestBoundedPCAPNGAndReferences(t *testing.T) {
	t.Parallel()
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), smallExperiment(t), testPolicy(), testLink(), sim)
	if err != nil {
		t.Fatal(err)
	}
	for _, minimize := range []bool{false, true} {
		for _, cap := range []int64{256, 8 << 20} {
			var file bytes.Buffer
			if err := WritePCAPNG(&file, &r, cap, minimize); err != nil {
				t.Fatal(err)
			}
			if int64(file.Len()) > cap || r.CaptureArtifact.Bytes != int64(file.Len()) {
				t.Fatal("encoded cap exceeded")
			}
			if cap == 256 && r.CaptureArtifact.Dropped == 0 {
				t.Fatal("retention cap missing")
			}
			if err := VerifyPCAPNG(r, bytes.NewReader(file.Bytes())); err != nil {
				t.Fatal(err)
			}
			sealed := roundTrip(t, r)
			data, _ := json.Marshal(sealed)
			refs, err := ImportReferences(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if refs.CaptureArtifact.ArtifactID != r.CaptureArtifact.ArtifactID {
				t.Fatal("capture reference lost")
			}
			reader, err := capture.NewReader(bytes.NewReader(file.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for {
				rec, err := reader.NextRecord()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if rec.PacketID != uint64(count) {
					t.Fatal("packet ID mismatch")
				}
			}
			if count != r.CaptureArtifact.Packets {
				t.Fatal("packet accounting")
			}
			corrupt := append([]byte(nil), file.Bytes()...)
			corrupt[len(corrupt)-1] ^= 1
			if VerifyPCAPNG(r, bytes.NewReader(corrupt)) == nil {
				t.Fatal("corrupted capture accepted")
			}
			r.Trials[0].Evidence[0].PacketID++
			sealed, _ = Seal(r)
			data, _ = json.Marshal(sealed)
			if _, err := Replay(bytes.NewReader(data)); err == nil {
				t.Fatal("resealed false packet reference accepted")
			}
		}
	}
	before := r.CaptureArtifact
	if WritePCAPNG(failWriter{}, &r, 8<<20, false) == nil || r.CaptureArtifact != before {
		t.Fatal("write failure installed references")
	}

}

func TestMinimizedPayloadAndLegacyReplay(t *testing.T) {
	t.Parallel()
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), smallExperiment(t), testPolicy(), testLink(), sim)
	if err != nil {
		t.Fatal(err)
	}
	ev := &r.Trials[0].Evidence[1]
	decoded := gopacket.NewPacket(ev.Frame, layers.LayerTypeEthernet, gopacket.Default)
	eth := decoded.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xab}, 100)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	r.CaptureBytes += len(buf.Bytes()) - len(ev.Frame)
	ev.Frame = buf.Bytes()
	var file bytes.Buffer
	if err := WritePCAPNG(&file, &r, 8<<20, true); err != nil {
		t.Fatal(err)
	}
	reader, err := capture.NewReader(bytes.NewReader(file.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = reader.NextRecord()
	rec, err := reader.NextRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Length != len(ev.Frame) || len(rec.Data) != len(ev.Frame)-len(payload) {
		t.Fatal("payload/length minimization failed")
	}
	if !bytes.Equal(ev.Frame[len(ev.Frame)-len(payload):], payload) {
		t.Fatal("raw payload changed")
	}
	roundTrip(t, r)
	// Re-create the original additive-compatible report shape and old features.
	r.CaptureArtifact = nil
	r.CorrelationVersion = ""
	for i := range r.Trials {
		for j := range r.Trials[i].Evidence {
			e := &r.Trials[i].Evidence[j]
			e.PacketID = 0
			e.Timing = nil
		}
		r.Trials[i].Features.ResponseSource = ""
		r.Trials[i].Features.Correlation = ""
	}
	r.Comparison = Compare(r)
	roundTrip(t, r)
}

func TestHostileCaptureLengths(t *testing.T) {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data, 0x0a0d0d0a)
	binary.LittleEndian.PutUint32(data[4:], 0xfffffffc)
	binary.LittleEndian.PutUint32(data[8:], 0x1a2b3c4d)
	if _, err := ReplayCaptureFixtures(bytes.NewReader(data), fixtureProbe(t, false), 4096); err == nil {
		t.Fatal("oversized block accepted")
	}
}

func TestClockShiftMetadata(t *testing.T) {
	for _, offset := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()
			sim, _ := NewSimulator("sack")
			defer sim.Close()
			backend := &metadataIO{executorIO: executorIO{PacketIO: sim}, precision: 5000, delay: 1234, timestampOffset: offset}
			r, err := Run(context.Background(), smallExperiment(t), testPolicy(), testLink(), backend)
			if err != nil {
				t.Fatal(err)
			}
			if !hasFlag(r.Trials[0].QualityFlags, "clock-instability") {
				t.Fatal("clock shift did not gate evidence")
			}
			roundTrip(t, r)
			r.Trials[0].QualityFlags = nil
			sealed, _ := Seal(r)
			data, _ := json.Marshal(sealed)
			if _, err := Replay(bytes.NewReader(data)); err == nil {
				t.Fatal("missing clock flag accepted")
			}
		})
	}
}

package capture

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestReaderRoundTripsOwnPCAPNG(t *testing.T) {
	frames := [][]byte{tcpFrame(t, scanner, target, 1, 2, true, false), tcpFrame(t, target, scanner, 2, 1, true, true)}
	var file bytes.Buffer
	w, err := NewPCAPNGWriter(&file, "eth0", 65535, "nyxr")
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frames {
		if err := w.WritePacket(time.Now(), f, len(f), DirectionTX, uint64(i+1), "comment"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if int64(file.Len()) != w.Bytes() {
		t.Fatalf("byte accounting %d vs %d", w.Bytes(), file.Len())
	}
	r, err := NewReader(&file)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range frames {
		got, err := r.Next()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReaderRejectsUnknownFormat(t *testing.T) {
	if _, err := NewReader(bytes.NewReader([]byte("not a capture file at all, sorry"))); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestBlockSizeMatchesEncoding(t *testing.T) {
	w, err := NewPCAPNGWriter(io.Discard, "", 65535, "nyxr")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 3, 4, 60, 1514} {
		for _, comment := range []string{"", "a", "abcd", "tcp 192.0.2.1:1 > 192.0.2.2:2 [S]"} {
			before := w.Bytes()
			if err := w.WritePacket(time.Now(), make([]byte, n), n, DirectionRX, 1, comment); err != nil {
				t.Fatal(err)
			}
			if got, want := w.Bytes()-before, BlockSize(n, len(comment)); got != want {
				t.Fatalf("data %d comment %q: wrote %d, BlockSize %d", n, comment, got, want)
			}
		}
	}
}

func TestReaderRecordsCarryPCAPNGMetadata(t *testing.T) {
	frame := tcpFrame(t, target, scanner, 2, 1, true, true)
	ts := time.Unix(1700000000, 123456789)
	var file bytes.Buffer
	w, err := NewPCAPNGWriter(&file, "eth0", 65535, "nyxr")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(ts, frame, len(frame)+10, DirectionRX, 42, "syn-ack from target"); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(&file)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.NextRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Data, frame) || !rec.Timestamp.Equal(ts) || rec.Length != len(frame)+10 ||
		rec.Direction != DirectionRX || rec.PacketID != 42 || rec.Comment != "syn-ack from target" {
		t.Fatalf("record %+v", rec)
	}
}

func TestReaderRecordsCarryPCAPTimestamps(t *testing.T) {
	f, err := os.Open("../../tests/pcaps/phase0.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	r.NextRecord()
	rec, err := r.NextRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Timestamp.Unix() != 1 || rec.Length != len(rec.Data) {
		t.Fatalf("second record %+v", rec)
	}
}

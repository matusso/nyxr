package netmon

import (
	"errors"
	"runtime"
	"testing"
)

func TestRead(t *testing.T) {
	if _, err := Read(""); errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	lo := map[string]string{"darwin": "lo0", "linux": "lo"}[runtime.GOOS]
	if _, err := Read(lo); err != nil {
		t.Fatalf("loopback counters: %v", err)
	}
	if _, err := Read("no-such-interface0"); err == nil {
		t.Fatal("unknown interface must fail")
	}
}

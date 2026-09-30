//go:build linux

package main

import "testing"

func TestCapabilityReason(t *testing.T) {
	for status, want := range map[string]string{
		"Name:\tnyxr\nCapEff:\t0000000000000000\n": "",
		"CapEff:\t0000000000002000\n":              "CAP_NET_RAW",
		"CapEff:\t0000000000003000\n":              "CAP_NET_RAW and CAP_NET_ADMIN",
		"CapEff:\t000001ffffffffff\n":              "CAP_NET_RAW and CAP_NET_ADMIN",
	} {
		if got := capabilityReason(status); got != want {
			t.Errorf("%q: got %q want %q", status, got, want)
		}
	}
}

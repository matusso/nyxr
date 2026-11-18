package service

import (
	"bytes"
	"crypto/md5" //nolint:gosec // Vendor IDs are defined as MD5 digests; nothing is protected by them
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type ikeVendor struct {
	label            string // shown in ike.vendors
	product, version string // set when the ID names an implementation
}

type vendorPrefix struct {
	prefix []byte
	vendor ikeVendor
}

func md5Of(s string) []byte {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return sum[:]
}

var (
	msVendorPrefix = md5Of("MS NT5 ISAKMPOAKLEY")
	// Check Point and the opaque IDs below are not digests of a known string.
	// They come from long-published vendor ID lists (e.g. ike-scan's).
	checkPointPrefix = mustHex("f4ed19e0c114eb516faaac0ee37daf2807b4381f")
)

// ikeVendorPrefixes matches IDs that are a digest of a known string, or a
// fixed prefix followed by version bytes.
var ikeVendorPrefixes = []vendorPrefix{
	{md5Of("RFC 3947"), ikeVendor{label: "RFC 3947 NAT-T"}},
	{md5Of("draft-ietf-ipsec-nat-t-ike-00"), ikeVendor{label: "NAT-T draft 00"}},
	{md5Of("draft-ietf-ipsec-nat-t-ike-01"), ikeVendor{label: "NAT-T draft 01"}},
	{md5Of("draft-ietf-ipsec-nat-t-ike-02"), ikeVendor{label: "NAT-T draft 02"}},
	{md5Of("draft-ietf-ipsec-nat-t-ike-02\n"), ikeVendor{label: "NAT-T draft 02n"}},
	{md5Of("draft-ietf-ipsec-nat-t-ike-03"), ikeVendor{label: "NAT-T draft 03"}},
	{md5Of("strongSwan"), ikeVendor{label: "strongSwan", product: "strongSwan"}},
	{md5Of("FRAGMENTATION"), ikeVendor{label: "IKE Fragmentation"}},
	{md5Of("MS-Negotiation Discovery Capable"), ikeVendor{label: "MS-Negotiation Discovery Capable", product: "Microsoft Windows"}},
	{md5Of("IKE CGA version 1"), ikeVendor{label: "IKE CGA version 1", product: "Microsoft Windows"}},
	{md5Of("Vid-Initial-Contact"), ikeVendor{label: "Vid-Initial-Contact", product: "Microsoft Windows"}},
	{md5Of("CISCO-UNITY")[:14], ikeVendor{label: "Cisco Unity", product: "Cisco"}},
	{md5Of("draft-ietf-ipsra-isakmp-xauth-06.txt")[:8], ikeVendor{label: "XAUTH"}},
	{mustHex("afcad71368a1f1c96b8696fc7757"), ikeVendor{label: "Dead Peer Detection"}},
	{mustHex("1d6e178f6c2c0be284985465450fe9d4"), ikeVendor{label: "FortiGate", product: "Fortinet FortiGate"}},
	{mustHex("1f07f70eaa6514d3b0fa96542a50"), ikeVendor{label: "Cisco VPN Concentrator", product: "Cisco VPN Concentrator"}},
}

// Windows sends MS NT5 ISAKMPOAKLEY followed by a 4-byte release number.
var msWindowsReleases = map[uint32]string{
	2: "2000", 3: "XP SP1", 4: "2003/XP SP2", 5: "Vista", 6: "7/Server 2008 R2",
	7: "8/Server 2012", 8: "8.1/Server 2012 R2", 9: "10/Server 2016 or later",
}

// strongSwan up to 5.x sends MD5("strongSwan <version>") unless configured
// otherwise; the table is built on first use.
var strongSwanVersions = sync.OnceValue(func() map[string]string {
	m := make(map[string]string)
	for major := 2; major <= 6; major++ {
		for minor := 0; minor <= 12; minor++ {
			for patch := 0; patch <= 14; patch++ {
				v := fmt.Sprintf("%d.%d.%d", major, minor, patch)
				m[string(md5Of("strongSwan "+v))] = v
			}
		}
	}
	return m
})

// identifyVendor names a Vendor ID payload body and, where its encoding
// carries one, the implementation's version.
func identifyVendor(vid []byte) ikeVendor {
	if v, ok := strongSwanVersions()[string(vid)]; ok {
		return ikeVendor{label: "strongSwan " + v, product: "strongSwan", version: v}
	}
	if bytes.HasPrefix(vid, msVendorPrefix) {
		v := ikeVendor{label: "Microsoft Windows", product: "Microsoft Windows"}
		if len(vid) >= 20 {
			release := binary.BigEndian.Uint32(vid[16:20])
			if name, ok := msWindowsReleases[release]; ok {
				v.version = name
			} else {
				v.version = "release " + strconv.Itoa(int(release))
			}
			v.label += " " + v.version
		}
		return v
	}
	if bytes.HasPrefix(vid, checkPointPrefix) {
		// shortcut: product and version codes are reported raw; map the
		// Check Point release table when a real gateway's codes are at hand.
		v := ikeVendor{label: "Check Point", product: "Check Point"}
		if len(vid) >= 28 {
			switch binary.BigEndian.Uint32(vid[20:24]) {
			case 1:
				v.product = "Check Point Firewall-1"
			case 2:
				v.product = "Check Point SecureClient"
			}
			v.version = "version code " + strconv.Itoa(int(binary.BigEndian.Uint32(vid[24:28])))
			v.label = v.product + " " + v.version
		}
		return v
	}
	for _, known := range ikeVendorPrefixes {
		if bytes.HasPrefix(vid, known.prefix) {
			return known.vendor
		}
	}
	// Openswan and Libreswan send 12 bytes starting with "OE".
	if len(vid) == 12 && bytes.HasPrefix(vid, []byte("OE")) {
		return ikeVendor{label: "Openswan/Libreswan", product: "Openswan/Libreswan"}
	}
	if text, ok := printableVendor(vid); ok {
		v := ikeVendor{label: text}
		if lower := strings.ToLower(text); strings.Contains(lower, "cisco") || strings.Contains(lower, "flexvpn") {
			v.product = "Cisco"
		}
		return v
	}
	return ikeVendor{label: "unknown " + hex.EncodeToString(vid)}
}

// printableVendor accepts IDs sent as plain text, such as Cisco's IKEv2
// copyright string or "FLEXVPN-SUPPORTED".
func printableVendor(vid []byte) (string, bool) {
	if len(vid) < 6 {
		return "", false
	}
	for _, c := range vid {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(vid), true
}

package config

import (
	"sort"
	"strings"
)

// portSets are named shorthands accepted by ResolvePorts. Keys are matched
// case-insensitively with dashes removed, so "top-100" and "top100" are equal.
// top100 is a curated list of commonly open TCP ports; it is not derived from a
// measured frequency ranking and is documented as such.
var portSets = map[string][]uint16{
	// Common native and HTTP database endpoints. Port membership schedules an
	// identity exchange; it is never evidence of a database by itself.
	"database": {
		1433, 1521, 2379, 2380, 26257, 27017, 27018, 27019, 28015, 29015,
		3000, 3306, 33060, 4000, 4200, 5000, 5432, 5433, 5984, 6379, 6380,
		7000, 7474, 7473, 7687, 8000, 8001, 8086, 8123, 8529, 9042, 9000,
		9092, 9200, 9300, 11210, 11211, 1234, 14240, 2480, 2484, 50000,
		5555, 6333, 6334, 19530, 19531, 7700, 8108, 8888, 10000, 10100,
	},
	"top100": {
		7, 20, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 106, 110, 111,
		113, 119, 123, 135, 137, 139, 143, 144, 161, 179, 199, 389, 427,
		443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
		646, 873, 990, 993, 995, 1025, 1026, 1027, 1080, 1433, 1434, 1521, 1720,
		1723, 1755, 1900, 2000, 2001, 2049, 2121, 3000, 3128, 3268, 3306,
		3389, 4899, 5000, 5060, 5432, 5631, 5666, 5800, 5900, 5985, 6000,
		6001, 6379, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9100, 9200,
		9999, 10000, 11211, 27017, 32768, 49152, 49153, 49154,
	},
}

// ResolvePorts expands a port specification. In addition to the numeric list
// and range syntax handled by ParsePorts, it accepts the keyword "all" for the
// full 1..65535 range and any named set in portSets. Named sets and numeric
// lists are not mixed within one specification.
func ResolvePorts(s string) ([]uint16, error) {
	key := strings.ToLower(strings.TrimSpace(s))
	if key == "all" {
		return ParsePorts("1-65535")
	}
	if set, ok := portSets[strings.ReplaceAll(key, "-", "")]; ok {
		out := append([]uint16(nil), set...)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out, nil
	}
	return ParsePorts(s)
}

// PortSetNames lists the named port sets, sorted, for help output.
func PortSetNames() []string {
	names := make([]string, 0, len(portSets)+1)
	names = append(names, "all")
	for name := range portSets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

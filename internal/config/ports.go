package config

import (
	"sort"
	"strings"
)

// portSets are named shorthands accepted by ResolvePorts. Keys are matched
// case-insensitively with dashes removed, so "top-100" and "top100" are equal.
// top100 is a curated list of commonly open TCP ports; it is not derived from a
// measured frequency ranking and is documented as such. The frequency-ranked
// top1000, top2000, top5000 and top8387 sets live in nmapPortSets.
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
	// HTTP and HTTPS listeners: standard, alternate, admin panels, control
	// panels (cPanel, Plesk, Webmin), app servers and dev servers.
	"web": {
		80, 81, 443, 591, 593, 2082, 2083, 2086, 2087, 2095, 2096, 3000,
		3001, 4000, 4200, 4343, 4433, 4443, 5000, 5001, 5601, 5800, 7000,
		7001, 7080, 7443, 8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082,
		8083, 8088, 8090, 8181, 8443, 8444, 8800, 8880, 8888, 9000, 9001,
		9080, 9090, 9200, 9443, 10000, 10443, 18080,
	},
	// UDP ports with a built-in payload: DNS, DHCP, TFTP, Kerberos, RPC, NTP,
	// NetBIOS, SNMP, CLDAP, SLP, IKE, DB2, IPMI, Citrix, L2TP, RADIUS, SSDP,
	// STUN, SIP, mDNS, LLMNR, CoAP, TeamSpeak, Memcached, games and BACnet.
	"udp": {
		53, 67, 69, 88, 111, 123, 137, 161, 389, 427, 500, 523, 623, 1604,
		1701, 1812, 1813, 1900, 2049, 3478, 5060, 5353, 5355, 5683, 9987,
		11211, 23000, 27015, 27900, 27960, 28900, 47808,
	},
	// TCP services a Windows host and an Active Directory domain propagate:
	// MSRPC endpoint mapper (135), NetBIOS session (139), SMB (445), RDP
	// (3389), WinRM (5985/5986/47001), RPC-over-HTTP (593), LDAP/Global
	// Catalog and Kerberos for domain controllers (88/389/464/636/3268/3269),
	// SQL Server (1433), Hyper-V/VMConnect (2179), WSDAPI (5357), VNC remote
	// control (5900) and the usual dynamic RPC range (49152-49154).
	"windows": {
		88, 135, 139, 389, 445, 464, 593, 636, 1433, 2179, 3268, 3269, 3389,
		5357, 5900, 5985, 5986, 47001, 49152, 49153, 49154,
	},
	// Network file systems and object storage: ONC RPC portmapper (111),
	// NetBIOS/SMB (139/445), AFP (548), Lustre (988), NFS (2049), iSCSI (3260),
	// Ceph monitor v2/v1 (3300/6789) and OSD (6800/6801), Garage (3900), Ceph
	// RADOS Gateway (7480), HDFS namenode RPC/HTTP (8020/9870/9864/50070),
	// SeaweedFS S3 (8333), MinIO API/console (9000/9001), NFS mountd (20048)
	// and GlusterFS management (24007).
	"filesystem": {
		111, 139, 445, 548, 988, 2049, 3260, 3300, 3900, 6789, 6800, 6801,
		7480, 8020, 8333, 9000, 9001, 9864, 9870, 20048, 24007, 50070,
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
// full 1..65535 range and any named set in portSets or nmapPortSets. Named
// sets and numeric lists are not mixed within one specification.
func ResolvePorts(s string) ([]uint16, error) {
	key := strings.ToLower(strings.TrimSpace(s))
	if key == "all" {
		return ParsePorts("1-65535")
	}
	name := strings.ReplaceAll(key, "-", "")
	if set, ok := portSets[name]; ok {
		out := append([]uint16(nil), set...)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out, nil
	}
	if spec, ok := nmapPortSets[name]; ok {
		return ParsePorts(spec)
	}
	return ParsePorts(s)
}

// PortSetNames lists the named port sets, sorted, for help output.
func PortSetNames() []string {
	names := make([]string, 0, len(portSets)+len(nmapPortSets)+1)
	names = append(names, "all")
	for name := range portSets {
		names = append(names, name)
	}
	for name := range nmapPortSets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

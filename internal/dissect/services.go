package dissect

type servicePort struct {
	proto string
	port  uint16
}

// wellKnown names common services so the listing reads at a glance. It is a
// hint from the port number only; nothing in the capture confirms it.
var wellKnown = map[servicePort]string{
	{"tcp", 21}: "ftp", {"tcp", 22}: "ssh", {"tcp", 23}: "telnet", {"tcp", 25}: "smtp",
	{"tcp", 53}: "domain", {"udp", 53}: "domain", {"udp", 67}: "dhcp", {"udp", 69}: "tftp",
	{"tcp", 80}: "http", {"tcp", 88}: "kerberos", {"tcp", 110}: "pop3", {"udp", 123}: "ntp",
	{"tcp", 135}: "msrpc", {"udp", 137}: "netbios-ns", {"tcp", 139}: "netbios-ssn",
	{"tcp", 143}: "imap", {"udp", 161}: "snmp", {"udp", 162}: "snmptrap", {"tcp", 179}: "bgp",
	{"tcp", 389}: "ldap", {"tcp", 443}: "https", {"udp", 443}: "quic", {"tcp", 445}: "microsoft-ds",
	{"udp", 500}: "isakmp", {"tcp", 502}: "modbus", {"udp", 514}: "syslog", {"tcp", 587}: "submission",
	{"tcp", 636}: "ldaps", {"tcp", 993}: "imaps", {"tcp", 995}: "pop3s", {"tcp", 1433}: "ms-sql",
	{"udp", 1900}: "ssdp", {"tcp", 2049}: "nfs", {"tcp", 3306}: "mysql", {"tcp", 3389}: "rdp",
	{"udp", 5353}: "mdns", {"tcp", 5432}: "postgresql", {"tcp", 5900}: "vnc", {"tcp", 6379}: "redis",
	{"tcp", 8080}: "http-proxy", {"tcp", 8443}: "https-alt", {"tcp", 9200}: "elasticsearch",
	{"udp", 47808}: "bacnet", {"tcp", 27017}: "mongodb",
}

// ServiceName returns the conventional service on proto ("tcp" or "udp") and
// port, or "" when the port is not in nyxr's short list.
func ServiceName(proto string, port uint16) string {
	return wellKnown[servicePort{proto, port}]
}

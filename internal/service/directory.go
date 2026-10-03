package service

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// This file identifies directory services: LDAP (and Active Directory, which it
// recognizes from the rootDSE) and Kerberos. Both probes are unauthenticated
// and read-only. The LDAP probe reads the rootDSE, which servers publish to
// anonymous clients. The Kerberos probe sends one AS-REQ for a non-existent
// principal and reads the KDC's error reply; it never authenticates.

func intOf(b []byte) int {
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

// ldapRootDSERequest builds an anonymous LDAPv3 base search of the rootDSE for
// the operational attributes that identify the server and, for a domain
// controller, its forest and domain.
func ldapRootDSERequest() []byte {
	names := []string{
		"defaultNamingContext", "rootDomainNamingContext", "namingContexts",
		"dnsHostName", "ldapServiceName", "serverName",
		"domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
		"isGlobalCatalogReady", "supportedSASLMechanisms", "supportedLDAPVersion",
		"vendorName", "vendorVersion",
	}
	var attrContent []byte
	for _, n := range names {
		attrContent = append(attrContent, derTLV(0x04, []byte(n))...)
	}
	var body []byte
	body = append(body, derTLV(0x04, nil)...)                   // baseObject: "" (rootDSE)
	body = append(body, derTLV(0x0a, []byte{0x00})...)          // scope: baseObject
	body = append(body, derTLV(0x0a, []byte{0x00})...)          // derefAliases: never
	body = append(body, derTLV(0x02, []byte{0x00})...)          // sizeLimit: 0
	body = append(body, derTLV(0x02, []byte{0x00})...)          // timeLimit: 0
	body = append(body, derTLV(0x01, []byte{0x00})...)          // typesOnly: false
	body = append(body, derTLV(0x87, []byte("objectClass"))...) // filter: present
	body = append(body, derTLV(0x30, attrContent)...)           // attributes
	searchReq := derTLV(0x63, body)                             // [APPLICATION 3]
	msg := append(derTLV(0x02, []byte{0x01}), searchReq...)     // messageID 1
	return derTLV(0x30, msg)                                    // LDAPMessage
}

// probeLDAP reads the rootDSE and reports LDAP, naming an Active Directory
// domain controller when the directory-specific attributes are present.
func (e *Engine) probeLDAP(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeLDAP, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeLDAP
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeLDAP)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	if _, err := rc.Write(ldapRootDSERequest()); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	data, err := readSome(rc, e.cfg.MaxEvidence, 300*time.Millisecond)
	e.finish(&ev, rc, err)
	if !parseLDAP(o, data) {
		return false
	}
	matched = true
	return true
}

func parseLDAP(o *observe.Observation, data []byte) bool {
	attrs := map[string][]string{}
	resultCode := -1
	found := false
	for _, m := range children(data) {
		if m.class != classUniversal || m.tag != 0x10 || !m.constructed {
			continue
		}
		fields := children(m.content) // messageID, protocolOp
		if len(fields) < 2 || fields[1].class != classApplication {
			continue
		}
		switch fields[1].tag {
		case 4: // searchResultEntry
			found = true
			parts := children(fields[1].content) // objectName, attributes
			if len(parts) < 2 {
				continue
			}
			for _, pa := range children(parts[1].content) {
				kv := children(pa.content) // type, vals
				if len(kv) < 2 {
					continue
				}
				name := string(kv[0].content)
				for _, v := range children(kv[1].content) {
					attrs[name] = append(attrs[name], string(v.content))
				}
			}
		case 5: // searchResultDone
			found = true
			if d := children(fields[1].content); len(d) > 0 && d[0].class == classUniversal && d[0].tag == 0x0a {
				resultCode = intOf(d[0].content)
			}
		case 1: // bindResponse: a server that demands a bind still proves LDAP
			found = true
		}
	}
	if !found {
		return false
	}
	o.Service, o.Confidence, o.Probe = "ldap", 100, ProbeLDAP
	o.Reason = "LDAPv3 search response"
	first := func(k string) string {
		if v := attrs[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	// Active Directory publishes these operational attributes; other LDAP
	// servers do not.
	isAD := len(attrs["domainControllerFunctionality"]) > 0 || first("ldapServiceName") != "" || len(attrs["isGlobalCatalogReady"]) > 0
	if isAD {
		o.Product = "Active Directory"
		o.Reason = "LDAP rootDSE identifies an Active Directory domain controller"
		addAttr(o, "ad.domain", dnToDomain(first("defaultNamingContext")))
		addAttr(o, "ad.forest", dnToDomain(first("rootDomainNamingContext")))
		addAttr(o, "ad.dc_dns", first("dnsHostName"))
		addAttr(o, "ad.server", first("serverName"))
		addAttr(o, "ad.domain_level", adFunctionalLevel(first("domainFunctionality")))
		addAttr(o, "ad.forest_level", adFunctionalLevel(first("forestFunctionality")))
		if len(attrs["isGlobalCatalogReady"]) > 0 {
			addAttr(o, "ad.global_catalog", strings.ToLower(first("isGlobalCatalogReady")))
		}
	} else if v := first("vendorName"); v != "" {
		o.Product, o.Version = v, first("vendorVersion")
	}
	addAttr(o, "ldap.service_name", first("ldapServiceName"))
	addAttr(o, "ldap.naming_contexts", strings.Join(attrs["namingContexts"], ", "))
	addAttr(o, "ldap.sasl_mechanisms", strings.Join(attrs["supportedSASLMechanisms"], ", "))
	if resultCode >= 0 && !isAD && len(attrs) == 0 {
		addAttr(o, "ldap.result_code", strconv.Itoa(resultCode))
	}
	return true
}

// dnToDomain turns a distinguished name such as "DC=corp,DC=example" into the
// dotted domain "corp.example".
func dnToDomain(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "dc=") {
			parts = append(parts, rdn[3:])
		}
	}
	return strings.Join(parts, ".")
}

// adFunctionalLevel maps a functional-level number to its Windows Server
// release. Level 7 is the last distinct value; 2019 and later also report 7.
func adFunctionalLevel(s string) string {
	switch s {
	case "":
		return ""
	case "0":
		return "Windows 2000"
	case "1":
		return "Windows Server 2003 interim"
	case "2":
		return "Windows Server 2003"
	case "3":
		return "Windows Server 2008"
	case "4":
		return "Windows Server 2008 R2"
	case "5":
		return "Windows Server 2012"
	case "6":
		return "Windows Server 2012 R2"
	case "7":
		return "Windows Server 2016 or later"
	}
	return s
}

// kerberosASREQ is a complete AS-REQ for the non-existent principal
// krbtgt/NYXR.INVALID. A live KDC answers with a KRB-ERROR (or, rarely, an
// AS-REP); either proves Kerberos. It requests AES etypes only and no
// pre-authentication, so it never submits or guesses a credential.
var kerberosASREQ = mustHex("6a6d306ba103020105a20302010aa45f305da006030400408100a20e1b0c4e5958522e494e56414c4944" +
	"a321301fa003020101a11830161b066b72627467741b0c4e5958522e494e56414c4944a511180f3230333030313031303030303030" +
	"5aa703020101a8083006020112020111")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("service: invalid embedded payload: " + err.Error())
	}
	return b
}

var krbErrorNames = map[int]string{
	6:  "C_PRINCIPAL_UNKNOWN",
	7:  "S_PRINCIPAL_UNKNOWN",
	25: "PREAUTH_REQUIRED",
	68: "WRONG_REALM",
}

// probeKerberos sends the AS-REQ over TCP (a 4-octet length prefix per
// RFC 4120) and parses the KDC's reply for the error code and service realm.
func (e *Engine) probeKerberos(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeKerberos, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeKerberos
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeKerberos)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	frame := make([]byte, 4+len(kerberosASREQ))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(kerberosASREQ)))
	copy(frame[4:], kerberosASREQ)
	if _, err := rc.Write(frame); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	var lh [4]byte
	if _, err := io.ReadFull(rc, lh[:]); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	n := int(binary.BigEndian.Uint32(lh[:]))
	if n < 2 || n > 0x10000 {
		e.finish(&ev, rc, nil)
		return false
	}
	resp := make([]byte, n)
	_, err = io.ReadFull(rc, resp)
	e.finish(&ev, rc, err)
	if err != nil {
		return false
	}
	elem, _, ok := readTLV(resp)
	if !ok || elem.class != classApplication || (elem.tag != 11 && elem.tag != 30) {
		return false
	}
	o.Service, o.Confidence, o.Probe = "kerberos", 100, ProbeKerberos
	if elem.tag == 11 { // AS-REP
		o.Reason = "Kerberos AS-REP"
		matched = true
		return true
	}
	o.Reason = "Kerberos KRB-ERROR from the KDC"
	seq := children(elem.content) // [APPLICATION 30] wraps a SEQUENCE
	if len(seq) == 0 {
		matched = true
		return true
	}
	for _, f := range children(seq[0].content) {
		if f.class != classContext {
			continue
		}
		inner := children(f.content)
		if len(inner) == 0 {
			continue
		}
		switch f.tag {
		case 6: // error-code
			code := intOf(inner[0].content)
			name := krbErrorNames[code]
			if name == "" {
				addAttr(o, "kerberos.error_code", strconv.Itoa(code))
			} else {
				addAttr(o, "kerberos.error", name)
			}
		case 9: // service realm — ignore the realm we sent
			if realm := string(inner[0].content); realm != "" && realm != "NYXR.INVALID" {
				addAttr(o, "kerberos.realm", realm)
			}
		}
	}
	matched = true
	return true
}

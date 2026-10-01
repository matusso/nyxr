package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/dissect"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/tui"
	"github.com/matusso/nyxr/internal/ui"
)

const (
	tcpFIN = 1
	tcpSYN = 2
	tcpRST = 4
	tcpPSH = 8
	tcpACK = 16
	tcpURG = 32
)

// Port states ordered by strength; a stronger observation replaces a weaker one.
const (
	stateFiltered = iota + 1
	stateClosed
	stateOpen
)

var stateNames = map[int]string{stateFiltered: "filtered", stateClosed: "closed", stateOpen: "open"}

type portKey struct {
	proto string
	port  uint16
}

type portFinding struct {
	state  int
	reason string
}

type hostFinding struct {
	addr  netip.Addr
	ports map[portKey]*portFinding
	up    string // why the host is known to be up, when it has no ports
}

type endpoint struct {
	addr netip.Addr
	port uint16
}

type flowKey struct {
	proto string
	a, b  endpoint
}

// captureAnalysis infers host and port state from the packets of a capture,
// the same way a scanner reads replies: SYN-ACK means open, RST to a SYN means
// closed, ICMP port unreachable closes a UDP port, and any reply on a UDP flow
// marks the responder's port open.
type captureAnalysis struct {
	frames    int
	decoded   int
	protocols map[string]int
	hosts     map[netip.Addr]*hostFinding
	synSent   map[endpoint]bool
	initiator map[flowKey]endpoint
}

func newCaptureAnalysis() *captureAnalysis {
	return &captureAnalysis{
		protocols: map[string]int{},
		hosts:     map[netip.Addr]*hostFinding{},
		synSent:   map[endpoint]bool{},
		initiator: map[flowKey]endpoint{},
	}
}

func (a *captureAnalysis) host(addr netip.Addr) *hostFinding {
	h := a.hosts[addr]
	if h == nil {
		h = &hostFinding{addr: addr, ports: map[portKey]*portFinding{}}
		a.hosts[addr] = h
	}
	return h
}

func (a *captureAnalysis) mark(addr netip.Addr, proto string, port uint16, state int, reason string) {
	h := a.host(addr)
	k := portKey{proto, port}
	f := h.ports[k]
	if f == nil {
		f = &portFinding{}
		h.ports[k] = f
	}
	if state > f.state {
		f.state, f.reason = state, reason
	}
}

func (a *captureAnalysis) markUp(addr netip.Addr, reason string) {
	h := a.host(addr)
	if h.up == "" {
		h.up = reason
	}
}

func orderedFlow(proto string, x, y endpoint) flowKey {
	if y.addr.Less(x.addr) || (y.addr == x.addr && y.port < x.port) {
		x, y = y, x
	}
	return flowKey{proto, x, y}
}

func (a *captureAnalysis) add(d packet.Decoded) {
	a.decoded++
	a.protocols[d.Protocol]++
	src := endpoint{d.Source, d.SourcePort}
	dst := endpoint{d.Destination, d.DestPort}
	switch d.Protocol {
	case "tcp":
		switch {
		case d.TCPFlags&(tcpSYN|tcpACK) == tcpSYN|tcpACK:
			a.mark(d.Source, "tcp", d.SourcePort, stateOpen, "syn-ack")
		case d.TCPFlags&tcpSYN != 0:
			a.synSent[dst] = true
		case d.TCPFlags&tcpRST != 0 && a.synSent[src]:
			a.mark(d.Source, "tcp", d.SourcePort, stateClosed, "reset")
		}
	case "udp":
		k := orderedFlow("udp", src, dst)
		first, seen := a.initiator[k]
		if !seen {
			a.initiator[k] = src
		} else if first != src {
			a.mark(d.Source, "udp", d.SourcePort, stateOpen, "udp-response")
		}
	case "icmp", "icmp6":
		a.addICMP(d)
	}
}

func (a *captureAnalysis) addICMP(d packet.Decoded) {
	v6 := d.Protocol == "icmp6"
	switch {
	case !v6 && d.ICMPType == 0, v6 && d.ICMPType == 129:
		a.markUp(d.Source, "echo-reply")
	case !v6 && d.ICMPType == 3, v6 && d.ICMPType == 1:
		portUnreachable := (!v6 && d.ICMPCode == 3) || (v6 && d.ICMPCode == 4)
		state, reason := stateFiltered, "icmp-unreach"
		if portUnreachable {
			state, reason = stateClosed, "port-unreach"
		}
		switch {
		case d.UDPQuote.Valid:
			a.mark(d.UDPQuote.Destination, "udp", d.UDPQuote.DestPort, state, reason)
		case d.Quote.Valid && !portUnreachable:
			a.mark(d.Quote.Destination, "tcp", d.Quote.DestPort, stateFiltered, reason)
		}
	}
}

// sortedHosts returns the hosts with at least one port or liveness signal.
func (a *captureAnalysis) sortedHosts() []*hostFinding {
	hosts := make([]*hostFinding, 0, len(a.hosts))
	for _, h := range a.hosts {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].addr.Less(hosts[j].addr) })
	return hosts
}

func (h *hostFinding) sortedPorts() []portKey {
	keys := make([]portKey, 0, len(h.ports))
	for k := range h.ports {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	return keys
}

func (h *hostFinding) count(state int) int {
	n := 0
	for _, f := range h.ports {
		if f.state == state {
			n++
		}
	}
	return n
}

func runDecode(args []string, out io.Writer, style *ui.Styler) error {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "one JSON object per decoded packet")
	packetsFlag := fs.Bool("packets", false, "list every decoded packet")
	allFlag := fs.Bool("all", false, "also list closed and filtered ports")
	tuiFlag := fs.Bool("tui", false, "browse and inspect packets interactively")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			decodeUsage(out)
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("decode requires one pcap or pcapng file")
	}
	path := fs.Arg(0)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := capture.NewReader(f)
	if err != nil {
		return err
	}
	if *tuiFlag {
		return browseCapture(r, filepath.Base(path), style)
	}
	decoder := packet.NewDecoder()
	encoder := json.NewEncoder(out)
	analysis := newCaptureAnalysis()
	for {
		data, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		analysis.frames++
		decoded, ok := decoder.Decode(data)
		if !ok {
			continue
		}
		if *jsonFlag {
			if err := encoder.Encode(decoded); err != nil {
				return err
			}
			continue
		}
		analysis.add(decoded)
		if *packetsFlag {
			if _, err := fmt.Fprintln(out, packetLine(style, analysis.frames, decoded)); err != nil {
				return err
			}
		}
	}
	if *jsonFlag {
		return nil
	}
	if *packetsFlag && analysis.decoded > 0 {
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	_, err = io.WriteString(out, decodeReport(style, filepath.Base(path), analysis, *allFlag))
	return err
}

// browseCapture loads every frame and opens the interactive packet browser on
// the process's terminal.
func browseCapture(r capture.FrameReader, name string, style *ui.Styler) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("--tui needs an interactive terminal")
	}
	var recs []capture.Record
	for {
		rec, err := r.NextRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		recs = append(recs, rec)
	}
	// The styler decided color for stdout already: --no-color, NO_COLOR, tty.
	return tui.Run(os.Stdin, os.Stdout, tui.New(name, recs, style.Enabled()))
}

func decodeUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr decode [flags] capture.pcap[ng]

Summarizes an Ethernet pcap or pcapng capture: the hosts seen and the ports
the replies prove open (TCP SYN-ACK, UDP responses), closed (RST, ICMP port
unreachable) or filtered (other ICMP unreachables).

Flags:
  --tui       browse packets interactively: list, decoded layers with what
              each field means, and a hex dump of the selected field
  --all       also list closed and filtered ports
  --packets   list every decoded packet before the summary
  --json      print one JSON object per decoded packet instead
  --no-color  disable ANSI color
`)
}

// decodeReport renders the capture summary and the per-host port listing.
func decodeReport(s *ui.Styler, name string, a *captureAnalysis, all bool) string {
	var b strings.Builder
	sep := s.Dim(" • ")
	hosts := a.sortedHosts()
	open, closed, filtered, live := 0, 0, 0, 0
	for _, h := range hosts {
		open += h.count(stateOpen)
		closed += h.count(stateClosed)
		filtered += h.count(stateFiltered)
		if h.count(stateOpen) > 0 || h.count(stateClosed) > 0 || h.up != "" {
			live++
		}
	}

	if s.Enabled() {
		b.WriteString(s.Cyan("▸") + " ")
	}
	b.WriteString(s.Bold(name) + "\n")
	row := func(k, v string) { fmt.Fprintf(&b, "  %s %s\n", s.Key(fmt.Sprintf("%-10s", k)), v) }
	frames := s.Bold(strconv.Itoa(a.frames)) + s.Dim(" frames") + sep +
		s.Bold(strconv.Itoa(a.decoded)) + s.Dim(" decoded")
	if skipped := a.frames - a.decoded; skipped > 0 {
		frames += sep + s.Yellow(strconv.Itoa(skipped)) + s.Dim(" skipped")
	}
	row("packets", frames)
	if len(a.protocols) > 0 {
		names := make([]string, 0, len(a.protocols))
		for p := range a.protocols {
			names = append(names, p)
		}
		sort.Strings(names)
		parts := make([]string, len(names))
		for i, p := range names {
			parts[i] = s.Dim(p+" ") + s.Bold(strconv.Itoa(a.protocols[p]))
		}
		row("protocols", strings.Join(parts, sep))
	}
	findings := s.Green(strconv.Itoa(open) + " open")
	if closed > 0 {
		findings += sep + s.Red(strconv.Itoa(closed)+" closed")
	}
	if filtered > 0 {
		findings += sep + s.Yellow(strconv.Itoa(filtered)+" filtered")
	}
	row("hosts", s.Bold(strconv.Itoa(live))+s.Dim(" responding"))
	row("ports", findings)

	shown := 0
	for _, h := range hosts {
		ports := h.sortedPorts()
		var rows [][]string
		for _, k := range ports {
			f := h.ports[k]
			if f.state != stateOpen && !all {
				continue
			}
			state := stateNames[f.state]
			proto := strconv.Itoa(int(k.port)) + "/" + k.proto
			rows = append(rows, append(markCell(s, state),
				s.Cyan(proto),
				s.StateText(state),
				serviceCell(s, k),
				s.Dim(f.reason),
			))
		}
		if len(rows) > 0 {
			rows = append([][]string{append(markCell(s, ""),
				s.Header("PORT"), s.Header("STATE"), s.Header("SERVICE"), s.Header("REASON"))}, rows...)
		}
		if len(rows) == 0 && h.up == "" {
			continue
		}
		shown++
		b.WriteByte('\n')
		b.WriteString(hostHeader(s, h))
		b.WriteByte('\n')
		if len(rows) > 0 {
			var t strings.Builder
			s.Table(&t, rows)
			b.WriteString(t.String())
		}
	}
	if shown == 0 {
		b.WriteString("\n" + s.Dim("  no open ports found in this capture") + "\n")
	}
	return b.String()
}

// markCell is the indented leading column of a port row: a colored state
// glyph in color mode, plain indentation otherwise.
func markCell(s *ui.Styler, state string) []string {
	if !s.Enabled() {
		return []string{"  "}
	}
	switch state {
	case "":
		return []string{"    "}
	case "open":
		return []string{"    " + s.Green("●")}
	case "closed":
		return []string{"    " + s.Red("○")}
	default:
		return []string{"    " + s.Yellow("◐")}
	}
}

func hostHeader(s *ui.Styler, h *hostFinding) string {
	open, closed, filtered := h.count(stateOpen), h.count(stateClosed), h.count(stateFiltered)
	var parts []string
	if open > 0 {
		parts = append(parts, s.Green(strconv.Itoa(open)+" open"))
	}
	if closed > 0 {
		parts = append(parts, s.Red(strconv.Itoa(closed)+" closed"))
	}
	if filtered > 0 {
		parts = append(parts, s.Yellow(strconv.Itoa(filtered)+" filtered"))
	}
	if open == 0 && h.up != "" {
		parts = append(parts, s.Green("up")+s.Dim(" ("+h.up+")"))
	}
	if !s.Enabled() {
		return h.addr.String() + "  " + strings.Join(parts, " • ")
	}
	glyph := s.Green("◆")
	if open == 0 && closed == 0 && h.up == "" {
		glyph = s.Dim("◇")
	}
	return glyph + " " + s.Bold(h.addr.String()) + "  " + strings.Join(parts, s.Dim(" • "))
}

// packetLine renders one decoded packet for --packets.
func packetLine(s *ui.Styler, n int, d packet.Decoded) string {
	ep := func(addr netip.Addr, port uint16) string {
		if port == 0 {
			return s.Bold(addr.String())
		}
		host := addr.String()
		if addr.Is6() {
			host = "[" + host + "]"
		}
		return s.Bold(host) + s.Cyan(":"+strconv.Itoa(int(port)))
	}
	num := s.Gray(fmt.Sprintf("%6d", n))
	proto := s.Dim(fmt.Sprintf("%-5s", d.Protocol))
	line := num + "  " + proto + " " + ep(d.Source, d.SourcePort) + s.Dim(" → ") + ep(d.Destination, d.DestPort)
	switch d.Protocol {
	case "tcp":
		flags := tcpFlagNames(d.TCPFlags)
		switch {
		case d.TCPFlags&(tcpSYN|tcpACK) == tcpSYN|tcpACK:
			flags = s.Green(flags)
		case d.TCPFlags&tcpRST != 0:
			flags = s.Red(flags)
		case d.TCPFlags&tcpSYN != 0:
			flags = s.Yellow(flags)
		default:
			flags = s.Dim(flags)
		}
		line += "  " + flags
	case "icmp", "icmp6":
		line += "  " + s.Magenta(icmpName(d))
	}
	return line
}

func tcpFlagNames(f uint8) string {
	names := []struct {
		bit  uint8
		name string
	}{{tcpSYN, "SYN"}, {tcpACK, "ACK"}, {tcpFIN, "FIN"}, {tcpRST, "RST"}, {tcpPSH, "PSH"}, {tcpURG, "URG"}}
	var out []string
	for _, n := range names {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

func icmpName(d packet.Decoded) string {
	if d.Protocol == "icmp6" {
		switch d.ICMPType {
		case 128:
			return "echo request"
		case 129:
			return "echo reply"
		case 1:
			if d.ICMPCode == 4 {
				return "port unreachable"
			}
			return "unreachable code " + strconv.Itoa(int(d.ICMPCode))
		case 135:
			return "neighbor solicitation"
		case 136:
			return "neighbor advertisement"
		}
	} else {
		switch d.ICMPType {
		case 8:
			return "echo request"
		case 0:
			return "echo reply"
		case 11:
			return "time exceeded"
		case 3:
			switch d.ICMPCode {
			case 1:
				return "host unreachable"
			case 3:
				return "port unreachable"
			case 13:
				return "admin prohibited"
			}
			return "unreachable code " + strconv.Itoa(int(d.ICMPCode))
		}
	}
	return fmt.Sprintf("type %d code %d", d.ICMPType, d.ICMPCode)
}

func serviceCell(s *ui.Styler, k portKey) string {
	if name := dissect.ServiceName(k.proto, k.port); name != "" {
		return s.BoldCyan(name)
	}
	return s.Dim("-")
}

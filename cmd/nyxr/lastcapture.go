package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packetio"
)

// lastCaptureGrace keeps the capture open after the last probe so late
// replies are recorded, as the pipeline does for --pcapng.
const lastCaptureGrace = 300 * time.Millisecond

// warnCaptureRoute warns when socket probes to the first target leave through
// another interface than --interface (a VPN's utun, say): the capture would
// then record nothing. Raw SYN-only scans send on --interface itself.
func warnCaptureRoute(cfg config.Config, warn io.Writer, route func(netip.Addr) string) {
	if warn == nil || cfg.Interface == "" || len(cfg.Targets) == 0 || (cfg.TCPMode == "syn" && !cfg.UDP && !cfg.ICMP) {
		return
	}
	target := cfg.Targets[0]
	if via := route(target); via != "" && via != cfg.Interface {
		fmt.Fprintf(warn, "nyxr: traffic to %s leaves via %s, not --interface %s; the capture will miss it (use --interface %s)\n", target, via, cfg.Interface, via)
	}
}

// routeInterface names the interface the kernel routes target through, or ""
// when unknown. Connecting a UDP socket picks the route without sending.
func routeInterface(target netip.Addr) string {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(target, 9)))
	if err != nil {
		return ""
	}
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	_ = conn.Close()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap() == local {
				return iface.Name
			}
		}
	}
	return ""
}

// lastCapturePath is ~/.nyxr/last.pcapng, the capture of the newest scan.
func lastCapturePath() (string, error) {
	home, err := homeDir()
	if err != nil {
		return "", errors.New("cannot locate home directory for last.pcapng")
	}
	return filepath.Join(home, ".nyxr", "last.pcapng"), nil
}

// lastCapture keeps ~/.nyxr/last.pcapng for "nyxr decode --last". Each scan
// replaces it; a scan that cannot capture leaves none, so the file never
// belongs to an older scan. It is best effort and never fails the scan.
type lastCapture struct {
	path string
	warn io.Writer
	rec  *capture.Recorder
	// link is the --pcapng file the pipeline writes; it is linked (or
	// copied) to path once the scan ends instead of capturing twice.
	link string
}

// startLastCapture removes the previous last.pcapng and, when the scan uses a
// raw interface, starts capturing its traffic. Without --interface there is
// nothing to capture from, and it returns nil.
func startLastCapture(r config.Resolved, open packetio.Opener, warn io.Writer) *lastCapture {
	if warn == nil {
		warn = io.Discard
	}
	path, err := lastCapturePath()
	if err != nil {
		fmt.Fprintln(warn, "nyxr: last.pcapng not recorded:", err)
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(warn, "nyxr: last.pcapng not recorded:", err)
		return nil
	}
	if r.PCAPNG == "" && r.Config.Interface == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintln(warn, "nyxr: last.pcapng not recorded:", err)
		return nil
	}
	lc := &lastCapture{path: path, warn: warn}
	if r.PCAPNG != "" {
		lc.link = r.PCAPNG
		return lc
	}
	if open == nil {
		open = packetio.OpenLive
	}
	src, err := open(r.Config.Interface)
	if err != nil {
		fmt.Fprintf(warn, "nyxr: last.pcapng not recorded: capture on %s: %v\n", r.Config.Interface, err)
		return nil
	}
	var match func(netip.Addr) bool
	if r.Config.TargetStream != nil {
		match = r.Config.TargetStream.Contains
	}
	lc.rec, err = capture.Start(context.Background(), src, capture.Options{
		Path: path, Interface: r.Config.Interface, Targets: r.Config.Targets, TargetMatch: match,
	})
	if err != nil {
		_ = src.Close()
		_ = os.Remove(path)
		fmt.Fprintln(warn, "nyxr: last.pcapng not recorded:", err)
		return nil
	}
	return lc
}

// finish stops the capture, or links the --pcapng file, and hands the file
// to the invoking user under sudo so an unprivileged decode can read it.
func (lc *lastCapture) finish() {
	if lc == nil {
		return
	}
	var err error
	if lc.rec != nil {
		time.Sleep(lastCaptureGrace)
		_, err = lc.rec.Stop()
	} else {
		err = linkOrCopy(lc.link, lc.path)
	}
	if err != nil {
		fmt.Fprintln(lc.warn, "nyxr: last.pcapng:", err)
	}
	if _, statErr := os.Lstat(lc.path); statErr == nil {
		giveToInvoker(filepath.Dir(lc.path), lc.path)
	}
}

// linkOrCopy makes dst a hard link to src, or a copy when src is on another
// file system. startLastCapture removes dst before each scan, so a link never
// lets the next scan overwrite the --pcapng file.
func linkOrCopy(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	if os.Link(src, dst) == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

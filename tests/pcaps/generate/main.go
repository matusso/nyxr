// Command generate writes deterministic Ethernet PCAP fixtures for parser tests.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func main() {
	frames := [][]byte{
		frame(false, "tcp", false), frame(false, "udp", false),
		frame(true, "tcp", false), frame(true, "udp", false),
		frame(false, "icmp", false), frame(true, "icmp", false),
		frame(false, "tcp", true), quoteFrame(),
		{1, 2, 3}, frame(false, "tcp", false)[:27],
	}
	out, err := os.Create(filepath.Join("tests", "pcaps", "phase0.pcap"))
	if err != nil {
		panic(err)
	}
	defer out.Close()
	write := func(v any) {
		if err := binary.Write(out, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	write(uint32(0xa1b2c3d4))
	write(uint16(2))
	write(uint16(4))
	write(uint32(0))
	write(uint32(0))
	write(uint32(65535))
	write(uint32(1))
	for i, data := range frames {
		write(uint32(i))
		write(uint32(0))
		write(uint32(len(data)))
		write(uint32(len(data)))
		if _, err := out.Write(data); err != nil {
			panic(err)
		}
	}
	fmt.Printf("wrote %d deterministic frames\n", len(frames))
}

func frame(v6 bool, protocol string, vlan bool) []byte {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	stack := []gopacket.SerializableLayer{eth}
	if vlan {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4})
	} else if v6 {
		eth.EthernetType = layers.EthernetTypeIPv6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
	}
	var network gopacket.NetworkLayer
	if v6 {
		next := layers.IPProtocolTCP
		if protocol == "udp" {
			next = layers.IPProtocolUDP
		}
		if protocol == "icmp" {
			next = layers.IPProtocolICMPv6
		}
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: next, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		stack = append(stack, ip)
		network = ip
	} else {
		next := layers.IPProtocolTCP
		if protocol == "udp" {
			next = layers.IPProtocolUDP
		}
		if protocol == "icmp" {
			next = layers.IPProtocolICMPv4
		}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: next, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		stack = append(stack, ip)
		network = ip
	}
	switch protocol {
	case "tcp":
		tcp := &layers.TCP{SrcPort: 443, DstPort: 50000, Seq: 7, Ack: 9, SYN: true, ACK: true}
		if err := tcp.SetNetworkLayerForChecksum(network); err != nil {
			panic(err)
		}
		stack = append(stack, tcp)
	case "udp":
		udp := &layers.UDP{SrcPort: 53, DstPort: 50000}
		if err := udp.SetNetworkLayerForChecksum(network); err != nil {
			panic(err)
		}
		stack = append(stack, udp, gopacket.Payload{1, 2, 3})
	case "icmp":
		if v6 {
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}
			if err := icmp.SetNetworkLayerForChecksum(network); err != nil {
				panic(err)
			}
			stack = append(stack, icmp, gopacket.Payload{1, 2, 3, 4})
		} else {
			stack = append(stack, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}, gopacket.Payload{1, 2, 3, 4})
		}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func quoteFrame() []byte {
	request := frame(false, "tcp", false)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.ParseIP("192.0.2.2"), DstIP: net.ParseIP("192.0.2.1")}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 13)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(request[14:42])); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

//go:build linux

package netmon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readAll() (map[string]Counters, error) {
	dirs, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	out := map[string]Counters{}
	for _, d := range dirs {
		stat := func(name string) uint64 {
			b, err := os.ReadFile(filepath.Join("/sys/class/net", d.Name(), "statistics", name))
			if err != nil {
				return 0
			}
			v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			return v
		}
		out[d.Name()] = Counters{
			RxPackets: stat("rx_packets"), TxPackets: stat("tx_packets"),
			RxBytes: stat("rx_bytes"), TxBytes: stat("tx_bytes"),
		}
	}
	return out, nil
}

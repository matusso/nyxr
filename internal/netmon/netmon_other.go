//go:build !darwin && !linux

package netmon

func readAll() (map[string]Counters, error) { return nil, ErrUnsupported }

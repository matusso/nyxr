package probe

import (
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/nmapdb"
)

func TestFromNmapUDPUsesOnlyApplicablePortPayloads(t *testing.T) {
	const source = `Exclude U:9998
Probe UDP directed q|hello|
ports 9999
Probe UDP excluded q|skip|
ports 9998
Probe UDP generic q|not mapped|
Probe TCP other q|tcp|
ports 9999
`
	db, err := nmapdb.Parse(strings.NewReader(source), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := FromNmapUDP(db, []uint16{9998, 9999})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Name != "nmap-directed" ||
		selected[0].Matcher != "any" || len(selected[0].Ports) != 1 || selected[0].Ports[0] != 9999 {
		t.Fatalf("unexpected imported probes: %+v", selected)
	}
}

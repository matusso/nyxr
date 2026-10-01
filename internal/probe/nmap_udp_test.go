package probe

import (
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/nmapdb"
)

func TestFromNmapUDPUsesPortListsOnlyForOrdering(t *testing.T) {
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
	if len(selected) != 3 || selected[0].Name != "nmap-directed" ||
		selected[1].Name != "nmap-excluded" || selected[2].Name != "nmap-generic" ||
		len(ForPort(selected, 9997)) != 3 || ForPort(selected, 9998)[0].Name != "nmap-excluded" {
		t.Fatalf("unexpected imported probes: %+v", selected)
	}
}

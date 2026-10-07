package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func TestDatabaseMatchers(t *testing.T) {
	mysql := []byte{0, 0, 0, 0, 10, '8', '.', '4', '.', '0', 0, 1, 2, 3}
	length := len(mysql) - 4
	copy(mysql[:3], []byte{byte(length), byte(length >> 8), byte(length >> 16)})
	var o observe.Observation
	if !matchDatabaseBanner(&o, mysql) || o.Service != "mysql" || o.Version != "8.4.0" {
		t.Fatalf("MySQL greeting: %+v", o)
	}
	if matchDatabaseBanner(&observe.Observation{}, []byte("hello mysql")) {
		t.Fatal("text banner matched as MySQL")
	}
	for _, tc := range []struct {
		name  string
		match databaseMatcher
		data  []byte
		want  string
	}{
		{"redis", matchRedis, []byte("+PONG\r\n"), "redis"},
		{"redis auth", matchRedis, []byte("-NOAUTH Authentication required.\r\n"), "redis"},
		{"memcached", matchMemcached, []byte("VERSION 1.6.32\r\n"), "memcached"},
		{"postgres", matchPostgres, []byte("S"), "postgresql"},
		{"bolt", matchBolt, []byte{0, 0, 0, 5}, "bolt"},
		{"cql", matchCQL, []byte{0x84, 0, 0, 0, 6, 0, 0, 0, 0}, "cql"},
		{"tds", matchTDS, []byte{4, 1, 0, 20, 0, 0, 1, 0, 0, 0, 6, 0, 6, 0xff, 16, 0, 0, 0, 0, 0}, "mssql"},
		{"elastic", matchHTTPDatabase, []byte("HTTP/1.1 200 OK\r\nX-Elastic-Product: Elasticsearch\r\n\r\n{}"), "elasticsearch"},
		{"opensearch", matchHTTPDatabase, []byte("HTTP/1.1 200 OK\r\n\r\n{\"cluster_name\":\"c\",\"version\":{\"distribution\": \"opensearch\",\"number\":\"3.2.0\"}}"), "opensearch"},
		{"couchdb", matchHTTPDatabase, []byte("HTTP/1.1 200 OK\r\n\r\n{\"couchdb\":\"Welcome\",\"version\":\"3.4.2\"}"), "couchdb"},
		{"zookeeper refused", matchZooKeeper, []byte("srvr is not executed because it is not in the whitelist.\n"), "zookeeper"},
		{"zookeeper not serving", matchZooKeeper, []byte("This ZooKeeper instance is not currently serving requests\n"), "zookeeper"},
	} {
		o = observe.Observation{}
		if !tc.match(tc.data, &o) || o.Service != tc.want || o.Fingerprint != observe.FingerprintMatched {
			t.Fatalf("%s: %+v", tc.name, o)
		}
	}
	for _, tc := range []struct {
		match databaseMatcher
		data  []byte
	}{
		{matchRedis, []byte("+OK\r\n")},
		{matchMemcached, []byte("ERROR\r\n")},
		{matchPostgres, []byte("X")},
		{matchBolt, []byte{0, 0, 0, 0}},
		{matchCQL, []byte{0x84, 0, 0, 0, 5, 0, 0, 0, 0}},
		{matchTDS, []byte{4, 1, 0, 10, 0, 0, 1, 0, 0xff, 0}},
		{matchHTTPDatabase, []byte("HTTP/1.1 200 OK\r\n\r\n{}")},
		{matchZooKeeper, []byte("imok")},
	} {
		if tc.match(tc.data, &observe.Observation{}) {
			t.Fatalf("false database match: %q", tc.data)
		}
	}
}

func TestZooKeeperSrvr(t *testing.T) {
	reply := "Zookeeper version: 3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, built on 2024-02-12 22:16 UTC\n" +
		"Latency min/avg/max: 0/0.0/0\nReceived: 1\nSent: 0\nConnections: 1\nOutstanding: 0\nZxid: 0x0\nMode: standalone\nNode count: 5\n"
	var o observe.Observation
	if !matchZooKeeper([]byte(reply), &o) || o.Service != "zookeeper" || o.Version != "3.8.4" || o.Attributes["zookeeper.mode"] != "standalone" {
		t.Fatalf("ZooKeeper srvr: %+v", o)
	}
}

func TestMongoHelloAndResponse(t *testing.T) {
	request := mongoHello()
	if int(binary.LittleEndian.Uint32(request)) != len(request) || binary.LittleEndian.Uint32(request[12:]) != 2013 {
		t.Fatalf("bad MongoDB request: %x", request)
	}
	response := append([]byte(nil), request...)
	binary.LittleEndian.PutUint32(response[8:], 0x6e797872)
	var o observe.Observation
	if !matchMongo(response, &o) || o.Service != "mongodb" {
		t.Fatalf("MongoDB response: %+v", o)
	}
	binary.LittleEndian.PutUint32(response[8:], 99)
	if matchMongo(response, &observe.Observation{}) {
		t.Fatal("unrelated request ID matched MongoDB")
	}
}

func TestDatabaseProfileInterrogatesRedis(t *testing.T) {
	var calls int
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		call := calls
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if call == 1 { // passive banner read
				_, _ = io.Copy(io.Discard, server)
				return
			}
			request := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
			if _, err := io.ReadFull(server, request); err == nil && bytes.Equal(request, []byte("*1\r\n$4\r\nPING\r\n")) {
				_, _ = server.Write([]byte("+PONG\r\n"))
			}
		}()
		return client, nil
	}
	e, err := Start(context.Background(), Config{Probes: []string{ProbeDatabase}, Timeout: time.Second, Workers: 1, Dial: dial}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 6379})
	if o.Service != "redis" || o.Fingerprint != observe.FingerprintMatched || len(o.Evidence) != 2 || o.Evidence[1].Matched != ProbeDatabase {
		t.Fatalf("Redis interrogation: %+v", o)
	}
}

func TestDatabaseProbeFindsPostgresOnUnusualPort(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		var request [8]byte
		if _, err := io.ReadFull(c, request[:]); err != nil {
			return // passive banner connection
		}
		// Like PostgreSQL, reject anything but a startup-shaped packet.
		if bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			_, _ = c.Write([]byte("N"))
		}
	})
	e, err := Start(context.Background(), Config{
		Probes:   []string{ProbeBanner, ProbeSSH, ProbeTLS, ProbeHTTP, ProbeDatabase},
		Fallback: []string{ProbeTLS, ProbeHTTP, ProbeDatabase}, Timeout: 500 * time.Millisecond, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	if o.Service != "postgresql" || o.Attributes["postgresql.ssl_supported"] != "false" {
		t.Fatalf("PostgreSQL on unusual port not identified: %+v", o)
	}
	if last := o.ProbesAttempted[len(o.ProbesAttempted)-1]; last != ProbeDatabase {
		t.Fatalf("database probe should follow TLS and HTTP: %v", o.ProbesAttempted)
	}
}

func TestDatabaseProbeStopsOnSilentPort(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	e, err := Start(context.Background(), Config{
		Probes: []string{ProbeDatabase}, Fallback: []string{ProbeDatabase}, Timeout: 200 * time.Millisecond, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	var exchanges int
	for _, ev := range o.Evidence {
		if ev.Probe == ProbeDatabase {
			exchanges++
		}
	}
	if o.Fingerprint != observe.FingerprintUnknown || exchanges != 1 {
		t.Fatalf("silent port should end the database probe after one exchange, got %d: %+v", exchanges, o)
	}
}

// tdsServer answers a TDS PRELOGIN like SQL Server and drops anything else,
// as SQL Server does with a request of another protocol.
func tdsServer(c net.Conn) {
	var header [8]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 0x12 {
		return
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[2:4]))-len(header))
	if _, err := io.ReadFull(c, body); err == nil {
		_, _ = c.Write([]byte{4, 1, 0, 20, 0, 0, 1, 0, 0, 0, 6, 0, 6, 0xff, 16, 0, 0, 0, 0, 0})
	}
}

func TestDatabaseFoundOnAnyPort(t *testing.T) {
	postgres := func(c net.Conn) {
		var request [8]byte
		if _, err := io.ReadFull(c, request[:]); err == nil && bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			_, _ = c.Write([]byte("S"))
		}
	}
	for _, tc := range []struct {
		name   string
		port   uint16
		handle func(net.Conn)
		want   string
	}{
		{"mssql on unusual port", 14330, tdsServer, "mssql"},
		{"mssql on postgres port", 5432, tdsServer, "mssql"},
		{"postgres on pgbouncer port", 6432, postgres, "postgresql"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := serve(t, tc.handle)
			// The database profile's probe and fallback settings.
			e, err := Start(context.Background(), Config{
				Probes: []string{ProbeDatabase}, Fallback: []string{ProbeDatabase}, Timeout: 300 * time.Millisecond, Workers: 1,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, net.JoinHostPort(listener.Addr.String(), strconv.Itoa(int(listener.Port))))
				},
			}, func(observe.Observation) {})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			o := e.Interrogate(context.Background(), Target{Addr: listener.Addr, Port: tc.port})
			if o.Service != tc.want || o.Fingerprint != observe.FingerprintMatched {
				t.Fatalf("%s not identified on %d: %+v", tc.want, tc.port, o)
			}
		})
	}
}

package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// A port selects an exchange, never an identity. Unknown replies stay in the
// observation as evidence. Protocols sharing a wire format (for example
// Valkey/Redis and Scylla/Cassandra) are named by protocol, not guessed product.
var databasePorts = portSet(
	1234, 1433, 1521, 2379, 2380, 2480, 2484, 26257, 27017, 27018, 27019,
	28015, 29015, 3000, 3306, 33060, 4000, 4200, 5000, 5432, 5433, 5555,
	5984, 6333, 6334, 6379, 6380, 7000, 7473, 7474, 7687, 7700, 8000,
	8001, 8086, 8108, 8123, 8529, 8888, 9000, 9042, 9092, 9200, 9300,
	10000, 10100, 11210, 11211, 14240, 19530, 19531, 50000,
)

var (
	redisPorts    = portSet(6379, 6380)
	memcachePorts = portSet(11211)
	postgresPorts = portSet(5432, 5433, 26257)
	mongoPorts    = portSet(27017, 27018, 27019)
	boltPorts     = portSet(7687)
	cqlPorts      = portSet(9042)
	tdsPorts      = portSet(1433)
	httpDBPorts   = portSet(2379, 2380, 2480, 3000, 4000, 4200, 5000, 5555, 5984,
		6333, 7000, 7473, 7474, 7700, 8000, 8001, 8086, 8108, 8123, 8529,
		8888, 9000, 9200, 10000, 10100, 14240, 19530)
)

// matchDatabaseBanner validates the server-first MySQL/MariaDB packet. A
// generic text banner or a familiar port number is not sufficient.
func matchDatabaseBanner(o *observe.Observation, data []byte) bool {
	if len(data) < 7 || data[3] != 0 || data[4] != 10 {
		return false
	}
	length := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	if length < 3 || length > 1<<20 || length+4 < len(data) {
		return false
	}
	version, _, ok := bytes.Cut(data[5:], []byte{0})
	if !ok || len(version) < 2 || len(version) > 100 {
		return false
	}
	for _, b := range version {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	product := "MySQL-compatible"
	if bytes.Contains(bytes.ToLower(version), []byte("mariadb")) {
		product = "MariaDB"
	}
	identifyDatabase(o, "mysql", product, string(version), "MySQL protocol v10 greeting", 100)
	return true
}

func identifyDatabase(o *observe.Observation, service, product, version, reason string, confidence int) {
	o.Service, o.Product, o.Version = service, product, version
	o.Probe, o.Reason, o.Confidence = ProbeDatabase, reason, confidence
	o.Fingerprint = observe.FingerprintMatched
}

func (e *Engine) probeDatabase(ctx context.Context, t Target, o *observe.Observation, redisHint bool) bool {
	switch {
	case redisHint || redisPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, []byte("*1\r\n$4\r\nPING\r\n"), matchRedis)
	case memcachePorts[t.Port]:
		return e.databaseExchange(ctx, t, o, []byte("version\r\n"), matchMemcached)
	case postgresPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, []byte{0, 0, 0, 8, 4, 210, 22, 47}, matchPostgres)
	case mongoPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, mongoHello(), matchMongo)
	case boltPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, boltHello, matchBolt)
	case cqlPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, []byte{4, 0, 0, 0, 5, 0, 0, 0, 0}, matchCQL)
	case tdsPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, tdsPrelogin, matchTDS)
	case httpDBPorts[t.Port]:
		return e.databaseExchange(ctx, t, o, []byte("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"), matchHTTPDatabase)
	default:
		// Server-first protocols and currently unsupported ports remain unknown.
		return false
	}
}

type databaseMatcher func([]byte, *observe.Observation) bool

func (e *Engine) databaseExchange(ctx context.Context, t Target, o *observe.Observation, request []byte, match databaseMatcher) bool {
	ev := observe.Evidence{Probe: ProbeDatabase, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeDatabase)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	if _, err = rc.Write(request); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	data, err := readSome(rc, min(e.cfg.MaxEvidence, 4096), 100*time.Millisecond)
	e.finish(&ev, rc, err)
	if !match(data, o) {
		return false
	}
	ev.Matched = ProbeDatabase
	return true
}

func matchRedis(data []byte, o *observe.Observation) bool {
	line, _, _ := bytes.Cut(data, []byte("\r\n"))
	if !bytes.Equal(line, []byte("+PONG")) && !bytes.HasPrefix(line, []byte("-NOAUTH ")) &&
		!bytes.HasPrefix(line, []byte("-NOPERM ")) {
		return false
	}
	identifyDatabase(o, "redis", "", "", "RESP PING response", 100)
	return true
}

func matchMemcached(data []byte, o *observe.Observation) bool {
	line, _, _ := bytes.Cut(data, []byte("\r\n"))
	if !bytes.HasPrefix(line, []byte("VERSION ")) || len(line) > 120 {
		return false
	}
	version := strings.TrimSpace(string(line[len("VERSION "):]))
	if version == "" {
		return false
	}
	identifyDatabase(o, "memcached", "Memcached", version, "Memcached version response", 100)
	return true
}

func matchPostgres(data []byte, o *observe.Observation) bool {
	if len(data) != 1 || data[0] != 'S' && data[0] != 'N' {
		return false
	}
	identifyDatabase(o, "postgresql", "PostgreSQL-compatible", "", "PostgreSQL SSLRequest response", 85)
	o.Attributes = map[string]string{"postgresql.ssl_supported": strconv.FormatBool(data[0] == 'S')}
	return true
}

func mongoHello() []byte {
	// OP_MSG section zero: {hello: 1, $db: "admin"}. No authentication or
	// database read is attempted.
	doc := []byte{0, 0, 0, 0, 0x10, 'h', 'e', 'l', 'l', 'o', 0, 1, 0, 0, 0,
		0x02, '$', 'd', 'b', 0, 6, 0, 0, 0, 'a', 'd', 'm', 'i', 'n', 0, 0}
	binary.LittleEndian.PutUint32(doc, uint32(len(doc)))
	msg := make([]byte, 16+4+1+len(doc))
	binary.LittleEndian.PutUint32(msg, uint32(len(msg)))
	binary.LittleEndian.PutUint32(msg[4:], 0x6e797872) // request ID
	binary.LittleEndian.PutUint32(msg[12:], 2013)      // OP_MSG
	copy(msg[21:], doc)
	return msg
}

func matchMongo(data []byte, o *observe.Observation) bool {
	if len(data) < 26 || int(binary.LittleEndian.Uint32(data)) != len(data) ||
		binary.LittleEndian.Uint32(data[8:]) != 0x6e797872 || binary.LittleEndian.Uint32(data[12:]) != 2013 || data[20] != 0 {
		return false
	}
	doc := data[21:]
	size := int(binary.LittleEndian.Uint32(doc))
	if len(doc) < 5 || size < 5 || size > len(doc) || doc[size-1] != 0 {
		return false
	}
	identifyDatabase(o, "mongodb", "MongoDB-compatible", "", "MongoDB OP_MSG hello response", 95)
	return true
}

var boltHello = []byte{0x60, 0x60, 0xb0, 0x17, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 1}

func matchBolt(data []byte, o *observe.Observation) bool {
	if len(data) != 4 || !bytes.Equal(data, []byte{0, 0, 0, 5}) &&
		!bytes.Equal(data, []byte{0, 0, 0, 4}) && !bytes.Equal(data, []byte{0, 0, 0, 3}) &&
		!bytes.Equal(data, []byte{0, 0, 0, 1}) {
		return false
	}
	identifyDatabase(o, "bolt", "Neo4j-compatible", fmt.Sprint(data[3]), "Bolt protocol version negotiation", 100)
	return true
}

func matchCQL(data []byte, o *observe.Observation) bool {
	if len(data) < 9 || data[0] != 0x84 || data[1] != 0 || data[2] != 0 || data[3] != 0 ||
		data[4] != 6 || int(binary.BigEndian.Uint32(data[5:9])) != len(data)-9 {
		return false
	}
	identifyDatabase(o, "cql", "Cassandra-compatible", "4", "CQL OPTIONS/SUPPORTED exchange", 100)
	return true
}

// TDS PRELOGIN asks for the server version without credentials.
var tdsPrelogin = []byte{0x12, 0x01, 0, 0x14, 0, 0, 1, 0, 0, 0, 6, 0, 6, 0xff, 0, 0, 0, 0, 0, 0}

func matchTDS(data []byte, o *observe.Observation) bool {
	if len(data) < 15 || data[0] != 4 || int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return false
	}
	payload := data[8:]
	var version []byte
	for cursor := 0; cursor < len(payload); {
		if payload[cursor] == 0xff {
			break
		}
		if cursor+5 > len(payload) {
			return false
		}
		offset, length := int(binary.BigEndian.Uint16(payload[cursor+1:cursor+3])), int(binary.BigEndian.Uint16(payload[cursor+3:cursor+5]))
		if offset < 6 || offset+length > len(payload) {
			return false
		}
		if payload[cursor] == 0 && length >= 6 {
			version = payload[offset : offset+length]
		}
		cursor += 5
	}
	if len(version) == 0 {
		return false
	}
	identifyDatabase(o, "mssql", "SQL Server-compatible", "", "TDS PRELOGIN version response", 95)
	return true
}

func matchHTTPDatabase(data []byte, o *observe.Observation) bool {
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return false
	}
	head, body, ok := bytes.Cut(data, []byte("\r\n\r\n"))
	if !ok {
		return false
	}
	lowerHead := strings.ToLower(string(head))
	var document map[string]json.RawMessage
	_ = json.Unmarshal(body, &document)
	var versionInfo map[string]json.RawMessage
	_ = json.Unmarshal(document["version"], &versionInfo)
	var service, product, version, reason string
	switch {
	case strings.Contains(lowerHead, "x-elastic-product: elasticsearch"):
		service, product, version, reason = "elasticsearch", "Elasticsearch", jsonString(versionInfo, "number"), "Elasticsearch HTTP product header"
	case jsonString(document, "tagline") == "You Know, for Search" && document["cluster_name"] != nil:
		service, product, version, reason = "elasticsearch", "Elasticsearch", jsonString(versionInfo, "number"), "Elasticsearch root document"
	case jsonString(document, "cluster_name") != "" && jsonString(versionInfo, "distribution") == "opensearch":
		service, product, version, reason = "opensearch", "OpenSearch", jsonString(versionInfo, "number"), "OpenSearch root document"
	case jsonString(document, "couchdb") == "Welcome":
		service, product, version, reason = "couchdb", "CouchDB", jsonString(document, "version"), "CouchDB root document"
	case strings.Contains(lowerHead, "x-influxdb-version:"):
		service, product, reason = "influxdb", "InfluxDB", "InfluxDB HTTP version header"
	case strings.Contains(lowerHead, "server: arangodb"):
		service, product, reason = "arangodb", "ArangoDB", "ArangoDB HTTP server header"
	case strings.Contains(lowerHead, "x-clickhouse-server-display-name:"):
		service, product, reason = "clickhouse", "ClickHouse", "ClickHouse HTTP server header"
	case strings.Contains(lowerHead, "server: qdrant") ||
		strings.Contains(strings.ToLower(jsonString(document, "title")), "qdrant") && jsonString(document, "version") != "":
		service, product, version, reason = "qdrant", "Qdrant", jsonString(document, "version"), "Qdrant HTTP identity"
	case strings.Contains(lowerHead, "server: meilisearch"):
		service, product, reason = "meilisearch", "Meilisearch", "Meilisearch HTTP server header"
	case jsonString(document, "bolt_routing") != "" && document["transaction"] != nil:
		service, product, reason = "neo4j", "Neo4j", "Neo4j HTTP discovery document"
	default:
		return false
	}
	identifyDatabase(o, service, product, version, reason, 95)
	return true
}

func jsonString(document map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(document[key], &value)
	return value
}

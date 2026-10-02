package service

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestMailGreetingsIdentified(t *testing.T) {
	tests := []struct {
		name, banner, service, product, attribute, value string
	}{
		{
			name: "SMTP", banner: "220 mail.mjch.eu ESMTP (c) 1982 Sinclair Research\r\n",
			service: "smtp", attribute: "smtp.hostname", value: "mail.mjch.eu",
		},
		{
			name: "POP3", banner: "+OK Dovecot ready on mail.zeroone.sk\r\n",
			service: "pop3", product: "Dovecot",
		},
		{
			name: "ManageSieve",
			banner: "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n" +
				"\"SIEVE\" \"fileinto reject envelope\"\r\n" +
				"\"NOTIFY\" \"mailto\"\r\n" +
				"\"SASL\" \"PLAIN LOGIN\"\r\n" +
				"STARTTLS\r\n" +
				"\"VERSION\" \"1.0\"\r\n" +
				"OK \"Dovecot ready on mail.zeroone.sk\"\r\n",
			service: "sieve", product: "Dovecot Pigeonhole",
			attribute: "sieve.starttls", value: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := serve(t, func(c net.Conn) { _, _ = io.WriteString(c, tt.banner) })
			o := testEngine(t).Interrogate(context.Background(), target)
			if o.Service != tt.service || o.Product != tt.product || o.Confidence < 90 || o.Fingerprint != observe.FingerprintMatched {
				t.Fatalf("unexpected identity: %+v", o)
			}
			if tt.attribute != "" && o.Attributes[tt.attribute] != tt.value {
				t.Fatalf("missing attribute %s: %+v", tt.attribute, o.Attributes)
			}
			if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeBanner ||
				string(o.Evidence[0].Response) != tt.banner || len(o.Evidence[0].Request) != 0 {
				t.Fatalf("banner evidence lost: %+v", o.Evidence)
			}
		})
	}
}

func TestMailMatcherRejectsAmbiguousGreetings(t *testing.T) {
	for _, banner := range []string{
		"220 ProFTPD FTP server ready\r\n",
		"220 mail.example.test ready\r\n",
		"+OK ready\r\n",
		"\"SIEVE\" \"fileinto\"\r\n\"VERSION\" \"1.0\"\r\n",
		"\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\nOK \"ready\"\r\n",
	} {
		var o observe.Observation
		if matchMailBanner(&o, []byte(banner)) {
			t.Errorf("ambiguous greeting was classified: %q -> %+v", banner, o)
		}
	}
}

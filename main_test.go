package main

import (
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// MockProvider for testing without a real Proxmox instance.
type MockProvider struct {
	data map[string]net.IP
}

func (m *MockProvider) GetIp(vmName string) (net.IP, error) {
	if ip, ok := m.data[vmName]; ok {
		return ip, nil
	}
	return nil, fmt.Errorf("vm not found: %q", vmName)
}

// mockWriter captures the response written by handleDNSRequest.
type mockWriter struct {
	msg *dns.Msg
}

func (m *mockWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (m *mockWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (m *mockWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockWriter) Close() error                { return nil }
func (m *mockWriter) TsigStatus() error           { return nil }
func (m *mockWriter) TsigTimersOnly(bool)         {}
func (m *mockWriter) Hijack()                     {}

func setupTest() {
	suffix = ".lab.lan"
	ttl = 60
	provider = &MockProvider{
		data: map[string]net.IP{
			"web01": net.ParseIP("192.168.1.50"),
		},
	}
}

func TestHandleDNSRequest(t *testing.T) {
	setupTest()

	tests := []struct {
		name      string
		query     string
		qtype     uint16
		wantRcode int
		wantIP    string
	}{
		{"valid A lookup", "web01.lab.lan.", dns.TypeA, dns.RcodeSuccess, "192.168.1.50"},
		{"case insensitive", "WEB01.LAB.LAN.", dns.TypeA, dns.RcodeSuccess, "192.168.1.50"},
		{"missing VM", "db01.lab.lan.", dns.TypeA, dns.RcodeNameError, ""},
		{"wrong suffix returns empty", "web01.wrong.com.", dns.TypeA, dns.RcodeSuccess, ""},
		{"AAAA ignored", "web01.lab.lan.", dns.TypeAAAA, dns.RcodeSuccess, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.query, tt.qtype)

			w := &mockWriter{}
			handleDNSRequest(w, req)

			if w.msg == nil {
				t.Fatal("handler did not write a response")
			}
			if w.msg.Rcode != tt.wantRcode {
				t.Errorf("rcode: want %d, got %d", tt.wantRcode, w.msg.Rcode)
			}
			if tt.wantIP != "" {
				if len(w.msg.Answer) == 0 {
					t.Fatal("expected A record in answer, got none")
				}
				a, ok := w.msg.Answer[0].(*dns.A)
				if !ok {
					t.Fatalf("answer[0] is not *dns.A")
				}
				if got := a.A.String(); got != tt.wantIP {
					t.Errorf("IP: want %s, got %s", tt.wantIP, got)
				}
				if a.Hdr.Ttl != uint32(ttl) {
					t.Errorf("TTL: want %d, got %d", ttl, a.Hdr.Ttl)
				}
			} else if tt.wantRcode == dns.RcodeSuccess && len(w.msg.Answer) != 0 {
				t.Errorf("expected no answer records, got %d", len(w.msg.Answer))
			}
		})
	}
}

func TestHandleDNSRequestEmptyQuestion(t *testing.T) {
	setupTest()
	req := &dns.Msg{} // no question section
	w := &mockWriter{}
	handleDNSRequest(w, req)
	if w.msg == nil {
		t.Fatal("handler did not write a response for empty question")
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("expected no answers for empty question, got %d", len(w.msg.Answer))
	}
}

func TestVersionString(t *testing.T) {
	settings := func(kv ...string) []debug.BuildSetting {
		var s []debug.BuildSetting
		for i := 0; i+1 < len(kv); i += 2 {
			s = append(s, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return s
	}

	tests := []struct {
		name      string
		ver       string
		buildTime string
		bi        *debug.BuildInfo
		wantAll   []string
		wantNone  []string
	}{
		{
			name:    "version shown",
			ver:     "1.1",
			wantAll: []string{"version:  1.1", "revision: unknown"},
		},
		{
			name:    "sha truncated to 12",
			ver:     "1.1",
			bi:      &debug.BuildInfo{Settings: settings("vcs.revision", "abc123def456789full")},
			wantAll:  []string{"abc123def456"},
			wantNone: []string{"abc123def456789full"},
		},
		{
			name:    "dirty flag",
			ver:     "1.1",
			bi:      &debug.BuildInfo{Settings: settings("vcs.revision", "abc123def456", "vcs.modified", "true")},
			wantAll: []string{"abc123def456-dirty"},
		},
		{
			name:    "vcs.time shown as committed",
			ver:     "1.1",
			bi:      &debug.BuildInfo{Settings: settings("vcs.revision", "abc123def456", "vcs.time", "2026-06-09T14:30:00Z")},
			wantAll: []string{"committed:", "2026-06-09 14:30:00 UTC"},
		},
		{
			name:      "ldflags buildTime shown as built, overrides vcs.time",
			ver:       "1.1",
			buildTime: "2026-06-09T14:30:00Z",
			bi:        &debug.BuildInfo{Settings: settings("vcs.time", "2026-06-08T10:00:00Z")},
			wantAll:   []string{"built:", "2026-06-09 14:30:00 UTC"},
			wantNone:  []string{"committed:"},
		},
		{
			name:      "invalid buildTime is silently ignored",
			ver:       "1.1",
			buildTime: "not-a-date",
			wantAll:   []string{"revision: unknown"},
			wantNone:  []string{"built:", "committed:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := versionString(tt.ver, tt.buildTime, tt.bi)
			for _, want := range tt.wantAll {
				if !strings.Contains(got, want) {
					t.Errorf("want %q in output, got:\n%s", want, got)
				}
			}
			for _, none := range tt.wantNone {
				if strings.Contains(got, none) {
					t.Errorf("did not want %q in output, got:\n%s", none, got)
				}
			}
		})
	}
}

func TestCacheConcurrency(t *testing.T) {
	cache = make(map[string]net.IP)
	var wg sync.WaitGroup

	// 100 goroutines writing and reading simultaneously; run with -race to detect data races.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := fmt.Sprintf("vm-%d", n%10)
			cacheMutex.Lock()
			cache[name] = net.ParseIP("1.1.1.1")
			cacheMutex.Unlock()
			cacheMutex.RLock()
			_ = cache[name]
			cacheMutex.RUnlock()
		}(i)
	}
	wg.Wait()
}

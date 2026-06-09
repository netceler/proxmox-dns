package main

import (
	"fmt"
	"net"
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

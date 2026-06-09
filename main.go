package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/miekg/dns"
)

// appVersion is the application version. Bump this on each release.
var appVersion = "1.2"

// buildTime is injected at build time: -ldflags "-X main.buildTime=<RFC3339>"
var buildTime string

// VmProvider allows swapping Proxmox for a mock in tests.
type VmProvider interface {
	GetIp(vmName string) (net.IP, error)
}

type ProxmoxProvider struct {
	client *proxmox.Client
}

var (
	ttl      int
	ipPrefix string
	bind     string
	suffix   string
	insecure bool
	provider VmProvider

	cache      = make(map[string]net.IP)
	cacheMutex sync.RWMutex
)

func printVersion() {
	bi, _ := debug.ReadBuildInfo()
	fmt.Print(versionString(appVersion, buildTime, bi))
}

// versionString builds the version output. Separated from printVersion for testing.
func versionString(ver, bt string, bi *debug.BuildInfo) string {
	var revision, vcsTime string
	var modified bool
	if bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				vcsTime = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}

	rev := "unknown"
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		rev = revision
		if modified {
			rev += "-dirty"
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "version:  %s\n", ver)
	fmt.Fprintf(&sb, "revision: %s\n", rev)

	var t time.Time
	label := "built"
	if bt != "" {
		t, _ = time.Parse(time.RFC3339, bt)
	} else if vcsTime != "" {
		t, _ = time.Parse(time.RFC3339, vcsTime)
		label = "committed"
	}
	if !t.IsZero() {
		utc := t.UTC().Format("2006-01-02 15:04:05 UTC")
		local := t.Local().Format("2006-01-02 15:04:05 MST")
		fmt.Fprintf(&sb, "%s: %s / %s\n", label, utc, local)
	}
	return sb.String()
}

func main() {
	version := flag.Bool("version", false, "Print build version and exit")
	flag.IntVar(&ttl, "ttl", 3600, "DNS TTL in seconds")
	flag.StringVar(&ipPrefix, "ipPrefix", "192.168.1.", "IP prefix to filter")
	flag.BoolVar(&insecure, "insecure", false, "Allow self-signed TLS certs (insecure)")
	flag.StringVar(&bind, "bind", ":53", "Address to listen on")
	flag.StringVar(&suffix, "suffix", ".lab.lan", "Domain suffix")
	flag.Parse()

	if *version {
		printVersion()
		os.Exit(0)
	}

	p := &ProxmoxProvider{}
	if err := p.login(); err != nil {
		log.Fatalf("Proxmox login failed: %v", err)
	}
	provider = p

	// Session watchdog: refresh Proxmox session every 30 minutes.
	go func() {
		t := time.NewTicker(30 * time.Minute)
		for range t.C {
			if err := p.login(); err != nil {
				log.Printf("Session refresh failed: %v", err)
			}
		}
	}()

	// Cache janitor: clear the IP cache every TTL seconds.
	go func() {
		t := time.NewTicker(time.Duration(ttl) * time.Second)
		for range t.C {
			cacheMutex.Lock()
			cache = make(map[string]net.IP)
			cacheMutex.Unlock()
			log.Println("Cache cleared")
		}
	}()

	startDNS()
}

func (p *ProxmoxProvider) login() error {
	tlsconf := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in via --insecure flag
	c, err := proxmox.NewClient(os.Getenv("PM_API_URL"), nil, "", tlsconf, "", 10, false)
	if err != nil {
		return err
	}
	if err = c.Login(context.Background(), os.Getenv("PM_USER"), os.Getenv("PM_PASS"), ""); err != nil {
		return err
	}
	p.client = c
	return nil
}

func (p *ProxmoxProvider) GetIp(vmName string) (net.IP, error) {
	cacheMutex.RLock()
	if ip, ok := cache[vmName]; ok {
		cacheMutex.RUnlock()
		return ip, nil
	}
	cacheMutex.RUnlock()

	ctx := context.Background()
	vmr, err := p.client.GetVmRefByName(ctx, proxmox.GuestName(vmName))
	if err != nil {
		return nil, err
	}

	ifaces, err := p.client.GetVmAgentNetworkInterfaces(ctx, vmr)
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		for _, addr := range iface.IpAddresses {
			if strings.HasPrefix(addr.String(), ipPrefix) {
				cacheMutex.Lock()
				cache[vmName] = addr
				cacheMutex.Unlock()
				return addr, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching IP found for %q", vmName)
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	query := strings.ToLower(q.Name)
	cleanSuffix := strings.ToLower(strings.Trim(suffix, ".")) + "."

	if q.Qtype == dns.TypeA && strings.HasSuffix(query, cleanSuffix) {
		vmName := strings.TrimSuffix(strings.TrimSuffix(query, cleanSuffix), ".")
		if ip, err := provider.GetIp(vmName); err == nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				A:   ip,
			})
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
	}
	w.WriteMsg(m)
}

func startDNS() {
	dns.HandleFunc(".", handleDNSRequest)
	log.Printf("Starting DNS server on %s", bind)

	srv := &dns.Server{Addr: bind, Net: "udp"}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case err := <-errCh:
		log.Fatalf("UDP error: %v", err)
	}

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.ShutdownContext(ctx); err != nil {
		log.Printf("DNS shutdown error: %v", err)
	}
}

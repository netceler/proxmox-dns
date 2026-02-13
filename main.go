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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/miekg/dns"
)

var (
	ttl      int
	ipPrefix string
	bind     string
	suffix   string
	insecure bool
	client   *proxmox.Client
	
	cache      = make(map[string]net.IP)
	cacheMutex sync.RWMutex
)

func main() {
	flag.IntVar(&ttl, "ttl", 3600, "DNS TTL")
	flag.StringVar(&ipPrefix, "ipPrefix", "192.168.1.", "IP prefix")
	flag.BoolVar(&insecure, "insecure", true, "Insecure TLS")
	flag.StringVar(&bind, "bind", ":53", "Bind address")
	flag.StringVar(&suffix, "suffix", ".lab.lan", "Domain suffix")
	flag.Parse()

	if err := login(); err != nil {
		log.Fatalf("Initial login failed: %v", err)
	}

	// Refresh session every 30 mins
	go func() {
		for range time.Tick(30 * time.Minute) {
			if err := login(); err != nil {
				log.Printf("Session refresh failed: %v", err)
			}
		}
	}()

	startDNS()
}

func login() error {
	tlsconf := &tls.Config{InsecureSkipVerify: insecure}
	
	// New signature: (apiURL, httpClient, apiToken, tlsConfig, proxy, timeout, taskTimeout)
	c, err := proxmox.NewClient(os.Getenv("PM_API_URL"), nil, "", tlsconf, "", 10, false)
	if err != nil {
		return err
	}
	
	// New signature: (ctx, user, password, otp)
	err = c.Login(context.Background(), os.Getenv("PM_USER"), os.Getenv("PM_PASS"), "")
	if err != nil {
		return err
	}
	client = c
	return nil
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	query := strings.ToLower(r.Question[0].Name)
	cleanSuffix := strings.ToLower(strings.Trim(suffix, ".")) + "."

	if r.Question[0].Qtype == dns.TypeA && strings.HasSuffix(query, cleanSuffix) {
		vmName := strings.TrimSuffix(query, cleanSuffix)
		vmName = strings.TrimSuffix(vmName, ".")

		if ip, err := getIP(vmName); err == nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				A:   ip,
			}
			m.Answer = append(m.Answer, rr)
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
	}
	w.WriteMsg(m)
}

func getIP(vmName string) (net.IP, error) {
	cacheMutex.RLock()
	if ip, ok := cache[vmName]; ok {
		cacheMutex.RUnlock()
		return ip, nil
	}
	cacheMutex.RUnlock()

	ctx := context.Background()

	// New signature: (ctx, name)
	vmr, err := client.GetVmRefByName(ctx, proxmox.GuestName(vmName))
	if err != nil {
		return nil, err
	}

	// New signature: (ctx, vmr)
	ifaces, err := client.GetVmAgentNetworkInterfaces(ctx, vmr)
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Field name changed from IPAddresses to IpAddresses
		for _, addr := range iface.IpAddresses {
			if strings.HasPrefix(addr.String(), ipPrefix) {
				cacheMutex.Lock()
				cache[vmName] = addr
				cacheMutex.Unlock()
				return addr, nil
			}
		}
	}
	return nil, fmt.Errorf("no IP found")
}

func startDNS() {
	dns.HandleFunc(".", handleDNSRequest)
	log.Printf("Starting DNS on %s", bind)
	
	go func() {
		if err := (&dns.Server{Addr: bind, Net: "udp"}).ListenAndServe(); err != nil {
			log.Fatalf("UDP: %v", err)
		}
	}()
	
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

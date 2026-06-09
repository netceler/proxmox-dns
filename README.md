# proxmox-dns

A DNS server that resolves VM/LXC hostnames to their IP addresses by querying the [Proxmox VE API](https://pve.proxmox.com/pve-docs/api-viewer/).

## Configuration

### Proxmox connection

The following environment variables must be set before starting proxmox-dns:

| Variable | Description | Example |
|---|---|---|
| `PM_API_URL` | Full URL to the Proxmox API | `https://proxmox.example.com:8006/api2/json` |
| `PM_USER` | Proxmox user in `user@realm` format | `root@pam` |
| `PM_PASS` | Password for the Proxmox user | `s3cr3t` |

Refer to the [Proxmox API documentation](https://pve.proxmox.com/pve-docs/api-viewer/) for details on authentication and available realms.

### DNS flags

| Flag | Default | Description |
|---|---|---|
| `--bind` | `:53` | Address and port to listen on |
| `--suffix` | `.lab.lan` | Domain suffix to respond to |
| `--ipPrefix` | `192.168.1.` | Only return IPs starting with this prefix |
| `--ttl` | `3600` | DNS record TTL in seconds |
| `--insecure` | `false` | Allow self-signed TLS certificates on the Proxmox API |

## Installation (systemd)

1. Copy the binary to `/usr/local/bin/proxmox-dns`
2. Copy `proxmox-dns.service` to `/etc/systemd/system/`
3. Edit the unit to set the environment variables and adjust the flags to match your network:

```ini
[Service]
Environment="PM_API_URL=https://proxmox.example.com:8006/api2/json"
Environment="PM_USER=root@pam"
Environment="PM_PASS=s3cr3t"
ExecStart=/usr/local/bin/proxmox-dns --ipPrefix 192.168.1. --suffix .lab.lan
```

4. Enable and start:

```sh
systemctl daemon-reload
systemctl enable --now proxmox-dns
```

## Build

```sh
mise run build   # produces ./proxmox-dns (static binary)
mise run test    # run tests with race detector
```

The binary embeds the git revision and build timestamp, visible via:

```sh
./proxmox-dns --version
# version:  1.2
# revision: 3b0b62f...
# built:    2026-06-09 15:38:45 UTC / 2026-06-09 17:38:45 CEST
```

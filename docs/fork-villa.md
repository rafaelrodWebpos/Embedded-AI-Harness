# Fork rafaelrodWebpos/Embedded-AI-Harness

Fork of `SensorsIot/Embedded-AI-Harness` at `db6a093`. It adds bench
capabilities and changes nothing else. villa-1 added the first two; villa-2
(this change, not installed until the independent read-only review S6 passes)
adds four more, listed in the second table.

| Capability | API | What it does |
|---|---|---|
| `bench-ap-internet` | `GET`/`POST /api/wifi/internet` `{"enabled": bool}` | Internet egress for SoftAP clients through the uplink (`eth0`), **public addresses only** |
| `bench-sntp-block` | `POST /api/wifi/sntp_block` `{"blocked": bool}` | Drops UDP/123 from the AP network (an SNTP attempt times out) |

| Capability (villa-2) | API | What it does |
|---|---|---|
| `bench-dns-override` (CR-TB-05) | `GET`/`POST /api/wifi/dns_override` `{"enabled": bool, "host": "github.com"}` | The AP's dnsmasq answers that one name with 192.168.4.1; an HTTPS server with a self-signed certificate (generated on the Pi, never in git) listens on 192.168.4.1:443 and answers 404 to everything |
| `bench-mqtt-auth` (CR-TB-03) | `POST /api/mqtt/start` `{"user": …, "pass": …}` | Test broker with `allow_anonymous false` and a temporary password file (0600, hashed in place with `mosquitto_passwd -U`, deleted on stop) |
| `bench-traffic-capture` (CR-TB-04) | `POST /api/capture/start` `{"mac": …, "seconds": 1-600}`, `GET /api/capture/result`, `POST /api/capture/stop` | `tcpdump` on the AP interface only, frames from that MAC only; returns a summary per destination (proto, address, port, unicast/broadcast/multicast, packets), never payloads; nothing written to disk |
| `bench-serial-write` | `POST /api/serial/write` (FR-030, already in the original) | Only reported in `capabilities` now |

All are reported by `GET /api/info` (`capabilities`, plus `build` = installed git
sha) and by `GET /api/wifi/internet` (`internet`, `sntp_blocked`, `lan_blocked`,
`rules_ok`, `rules`). `GET /api/wifi/ap_status` also carries `internet` and
`sntp_blocked`.

## Safety

* **Off by default**: at portal start-up and on every `ap_stop`.
* Rules live in dedicated chains (`HARNESS_AP_FWD`, `HARNESS_AP_NAT`,
  `HARNESS_AP_FWD6`) hooked at **position 1** of `FORWARD`/`POSTROUTING`, ahead
  of anything older. Rewritten atomically (`iptables-restore --noflush`).
* With egress on, every private, link-local, CGNAT, loopback, multicast and
  reserved destination is dropped before the uplink `ACCEPT`; only the AP's own
  subnet is allowed. Nothing new enters the AP from outside. IPv6 forwarding to
  or from the AP is always dropped.
* AP clients resolve names through dnsmasq on the Pi, with public resolvers
  (`1.1.1.1`, `8.8.8.8`) while on and no upstream while off — never the LAN's.
* The old `internet: true` of `ap_start` / `enter-portal` and the sniffer use
  the same chains: no path NATs the AP into the LAN any more.

`pi/ap_egress.py` holds the rule sets as pure functions; `pytest/host/test_ap_egress.py`
checks them (exact order, every private range dropped, SNTP block, idempotence,
ip_forward restored, closed state on failure).

### villa-2 safety

* `bench-dns-override` and the capture are **off by default**: at portal start-up
  and on every `ap_stop`. The DNS override only changes what the AP's own
  dnsmasq answers (an `addn-hosts` file that is empty while off); the HTTPS
  server binds to the AP address only, never `0.0.0.0`, and serves nothing.
* The capture listens on `wlan0` only, never the uplink, and only to frames
  whose source MAC is the DUT's.
* The test broker's password file exists only while a broker started with
  credentials runs; the password never appears on a command line.
* The egress chains of villa-1 are not touched: the LAN stays blocked.
* New package on the Pi: `tcpdump` (owner's decision D6, H-86).

## Install on the Pi

0. **Snapshot** (needed by the way back), as root on the Pi:

   ```bash
   sudo mkdir -p /var/backups/harness
   sudo sh -c 'iptables-save > /var/backups/harness/iptables-antes.rules; ip6tables-save > /var/backups/harness/ip6tables-antes.rules'
   sysctl -n net.ipv4.ip_forward | sudo tee /var/backups/harness/ip_forward-antes
   # every file install.sh --update writes
   sudo tar czf /var/backups/harness/archivos-antes.tgz --ignore-failed-read -C / \
     usr/local/bin/rfc2217-portal usr/local/bin/plain_rfc2217_server.py usr/local/bin/wifi_controller.py \
     usr/local/bin/ble_controller.py usr/local/bin/bcm_gpio.py usr/local/bin/gpclk.py usr/local/bin/morse.py \
     usr/local/bin/si5351.py usr/local/bin/pe4302.py usr/local/bin/signal_generator.py usr/local/bin/sdr_controller.py \
     usr/local/bin/debug_controller.py usr/local/bin/mqtt_controller.py usr/local/bin/netscan_controller.py \
     usr/local/bin/tls_mirror_controller.py usr/local/bin/sniffer.py usr/local/bin/rfc2217-learn-slots \
     usr/local/bin/rfc2217-udev-notify.sh usr/local/bin/wifi-lease-notify.sh usr/local/bin/espota.py \
     etc/rtl_433/rtl_433.conf etc/systemd/system/rfc2217-portal.service etc/udev/rules.d/99-rfc2217-hotplug.rules \
     etc/udev/rules.d/60-openocd.rules etc/dhcpcd.conf etc/hostname etc/hosts
   ```

1. `git clone https://github.com/rafaelrodWebpos/Embedded-AI-Harness.git` and check
   out the tag to install.
2. `sudo bash pi/install.sh --update`
3. Check over HTTP: `GET /api/info` lists the two capabilities and a `build`;
   `GET /api/wifi/internet` says `internet: false`, `rules_ok: true`.

### Installing villa-2 over villa-1

Only after the S6 review. The snapshot of step 0 must be the one taken before
villa-1 (it already exists in `/var/backups/harness`; do not overwrite it), so
the way back still returns to the original bench.

1. `sudo apt-get install -y tcpdump`
2. In the clone: `git fetch && git checkout villa-2`, then
   `sudo bash pi/install.sh --update`
3. Check: `GET /api/info` lists `bench-ap-internet`, `bench-sntp-block`,
   `bench-dns-override`, `bench-mqtt-auth`, `bench-traffic-capture` and
   `bench-serial-write`; `GET /api/wifi/dns_override` says `enabled: false`;
   `GET /api/wifi/internet` says `internet: false`, `rules_ok: true`.

## Way back (one command)

```bash
sudo harness-volver-original
```

Stops the portal, removes the `HARNESS_*` chains and their jumps, restores
`net.ipv4.ip_forward` and the snapshot's files, deletes `ap_egress.py`,
`dns_override.py`, `capture_controller.py`, the DNS-override certificate, the
broker's temporary password file and the build marker, stops a running capture, restarts the portal and checks that no `HARNESS` rule is left and
`/api/info` no longer lists the capabilities. It lives in `/usr/local/sbin`, so it
works even if the fork's clone is deleted.

## Pushing to this fork

`tools/git-hooks/pre-push` blocks a push whose commits carry a secret
(gitleaks), any value of the owner's local environment file (and the /24 of
any IPv4 in it), or a MAC address. It fails closed without
`git config harness.envfile <path>`. Enable with
`git config core.hooksPath tools/git-hooks`.

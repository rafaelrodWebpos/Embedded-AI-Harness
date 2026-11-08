# Fork rafaelrodWebpos/Embedded-AI-Harness

Fork of `SensorsIot/Embedded-AI-Harness` at `db6a093`. It adds two bench
capabilities and changes nothing else:

| Capability | API | What it does |
|---|---|---|
| `bench-ap-internet` | `GET`/`POST /api/wifi/internet` `{"enabled": bool}` | Internet egress for SoftAP clients through the uplink (`eth0`), **public addresses only** |
| `bench-sntp-block` | `POST /api/wifi/sntp_block` `{"blocked": bool}` | Drops UDP/123 from the AP network (an SNTP attempt times out) |

Both are reported by `GET /api/info` (`capabilities`, plus `build` = installed git
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

## Way back (one command)

```bash
sudo harness-volver-original
```

Stops the portal, removes the `HARNESS_*` chains and their jumps, restores
`net.ipv4.ip_forward` and the snapshot's files, deletes `ap_egress.py` and the
build marker, restarts the portal and checks that no `HARNESS` rule is left and
`/api/info` no longer lists the capabilities. It lives in `/usr/local/sbin`, so it
works even if the fork's clone is deleted.

## Pushing to this fork

`tools/git-hooks/pre-push` blocks a push whose commits carry a secret
(gitleaks), any value of the owner's local environment file (and the /24 of
any IPv4 in it), or a MAC address. It fails closed without
`git config harness.envfile <path>`. Enable with
`git config core.hooksPath tools/git-hooks`.

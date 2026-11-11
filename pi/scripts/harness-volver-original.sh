#!/bin/bash
# Vuelta atrás del fork: deja el banco como estaba antes de instalarlo.
#
#   sudo harness-volver-original
#
# Restaura la instantánea tomada antes de la instalación (docs/fork-villa.md,
# paso 0) en /var/backups/harness: los archivos que instala install.sh y el valor
# de net.ipv4.ip_forward. Quita además todo lo que el fork añade y el original no
# conoce: las cadenas HARNESS_* con sus saltos, ap_egress.py, dns_override.py,
# capture_controller.py, el certificado del DNS override, el fichero de
# contraseñas temporal del broker y la marca de build. tcpdump (villa-2) no se
# desinstala: es un paquete de Debian; quitarlo a mano si se quiere
# (apt-get remove tcpdump).
# Termina comprobando que no queda ninguna regla HARNESS y que el portal responde.
set -euo pipefail

SNAP=/var/backups/harness
WLAN_IF="${WIFI_WLAN_IF:-wlan0}"
UPLINK_IF="${WIFI_UPLINK_IF:-eth0}"
[ "$(id -u)" -eq 0 ] || { echo "ejecútalo con sudo"; exit 1; }
[ -f "$SNAP/archivos-antes.tgz" ] && [ -f "$SNAP/ip_forward-antes" ] \
    || { echo "no hay instantánea en $SNAP: no se toca nada"; exit 1; }

echo "1/5 parar el portal"
systemctl stop rfc2217-portal || true
pkill -f "tcpdump -i $WLAN_IF" 2>/dev/null || true      # villa-2: una captura en curso

echo "2/5 quitar las cadenas del fork"
quitar_salto() {   # binario tabla cadena args...: borra todas las copias del salto
    local bin=$1 tabla=$2 cadena=$3; shift 3
    while "$bin" -w -t "$tabla" -C "$cadena" "$@" 2>/dev/null; do
        "$bin" -w -t "$tabla" -D "$cadena" "$@"
    done
}
quitar_salto iptables  filter INPUT       -i "$UPLINK_IF" -j HARNESS_AP_IN   # villa-2, S6-04
quitar_salto iptables  filter FORWARD     -i "$WLAN_IF" -j HARNESS_AP_FWD
quitar_salto iptables  filter FORWARD     -o "$WLAN_IF" -j HARNESS_AP_FWD
quitar_salto iptables  nat    POSTROUTING -j HARNESS_AP_NAT
quitar_salto ip6tables filter FORWARD     -i "$WLAN_IF" -j HARNESS_AP_FWD6
quitar_salto ip6tables filter FORWARD     -o "$WLAN_IF" -j HARNESS_AP_FWD6
for c in "iptables filter HARNESS_AP_FWD" "iptables filter HARNESS_AP_IN" "iptables nat HARNESS_AP_NAT" "ip6tables filter HARNESS_AP_FWD6"; do
    set -- $c
    "$1" -w -t "$2" -F "$3" 2>/dev/null || true
    "$1" -w -t "$2" -X "$3" 2>/dev/null || true
done

echo "3/5 restaurar ip_forward"
sysctl -w "net.ipv4.ip_forward=$(cat "$SNAP/ip_forward-antes")"

echo "4/5 restaurar los archivos del banco original"
tar xzf "$SNAP/archivos-antes.tgz" -C /
rm -f /usr/local/bin/ap_egress.py /usr/local/bin/dns_override.py /usr/local/bin/capture_controller.py \
      /usr/local/bin/api_auth.py /usr/local/bin/run_dir.py \
      /usr/local/share/harness/build /tmp/mqtt-tester/passwd /tmp/wifi-tester/dns-override-hosts \
      /etc/rfc2217/api-token
rm -rf /var/lib/rfc2217/dns-override-tls /run/harness
systemctl daemon-reload
udevadm control --reload-rules || true
systemctl restart rfc2217-portal

echo "5/5 comprobar"
sleep 5
quedan=$( { iptables-save; ip6tables-save; } | grep -c HARNESS || true)
info=$(curl -s -m 5 http://127.0.0.1:8080/api/info || true)
echo "reglas HARNESS que quedan: $quedan"
echo "/api/info: $info"
restos=""
[ -e /etc/rfc2217/api-token ] && restos="$restos /etc/rfc2217/api-token"
[ -e /run/harness ] && restos="$restos /run/harness"
echo "ficheros del fork que quedan:${restos:- ninguno}"
if [ "$quedan" -ne 0 ] || [ -n "$restos" ] || [ -z "$info" ] || echo "$info" | grep -qE 'bench-ap-internet|bench-dns-override|bench-traffic-capture|bench-mqtt-auth'; then
    echo "VUELTA ATRÁS INCOMPLETA: revisar a mano"; exit 1
fi
echo "Banco original restaurado. (Este comando se queda en /usr/local/sbin; se puede borrar.)"

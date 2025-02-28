#!/bin/bash

# WireGuard Quick Install Script with IPv4/IPv6 Support
# Fast setup for WireGuard VPN servers with encryption and dual-stack support
# Source: https://github.com/almajnoun/wg-quick-install2
# By Almajnoun
# MIT License - 2025

abort() { echo "Error: $1" >&2; exit 1; }
abort_apt() { abort "'apt-get install' failed."; }
abort_yum() { abort "'yum install' failed."; }
abort_zypper() { abort "'zypper install' failed."; }

valid_ip() {
    # IPv4 regex
    local ip4_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    # IPv6 regex (simplified, covers most cases)
    local ip6_regex='^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,7}:$|^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$ip4_regex|$ip6_regex"
}

is_private_ip() {
    local priv4_regex='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    local priv6_regex='^(fc|fd|fe80)'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$priv4_regex|$priv6_regex"
}

is_fqdn() {
    local fqdn_regex='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$fqdn_regex"
}

root_check() { [ "$(id -u)" -ne 0 ] && abort "Run as root with 'sudo bash $0'."; }
bash_check() { readlink /proc/$$/exe | grep -q "dash" && abort "Use 'bash', not 'sh'."; }
kernel_check() { [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && abort "Old kernel not supported."; }
os_detect() { ... } # بدون تغيير
os_ver_check() { ... } # بدون تغيير
container_check() { ... } # بدون تغيير
clean_name() { ... } # بدون تغيير
parse_args() { ... } # بدون تغيير

validate_args() {
    [ "$QUICK" = 1 ] && [ -e "$WG_CONFIG" ] && usage "Cannot use '--quick' with existing setup."
    [ "$(($NEW_PEER + $LIST_PEERS + $RM_PEER + $QR_PEER))" -gt 1 ] && usage "Only one action allowed."
    [ "$UNINSTALL" = 1 ] && [ "$(($NEW_PEER + $LIST_PEERS + $RM_PEER + $QR_PEER + $QUICK))" -gt 0 ] && usage "'--uninstall' cannot combine with other actions."
    if [ ! -e "$WG_CONFIG" ]; then
        local msg="Setup WireGuard first to"
        [ "$NEW_PEER" = 1 ] && abort "$msg add a peer."
        [ "$LIST_PEERS" = 1 ] && abort "$msg list peers."
        [ "$RM_PEER" = 1 ] && abort "$msg remove a peer."
        [ "$QR_PEER" = 1 ] && abort "$msg show QR code."
        [ "$UNINSTALL" = 1 ] && abort "No WireGuard to uninstall."
    fi
    [ "$NEW_PEER" = 1 ] && clean_name && [ -z "$peer" ] && abort "Peer name must be alphanumeric with '-' or '_'."
    [ "$RM_PEER" = 1 ] || [ "$QR_PEER" = 1 ] && clean_name && { [ -z "$peer" ] || ! grep -q "^# BEGIN $peer$" "$WG_CONFIG"; } && abort "Invalid or missing peer."
    [ -n "$SERVER_ADDR" ] && ! { is_fqdn "$SERVER_ADDR" || valid_ip "$SERVER_ADDR"; } && abort "Address must be FQDN, IPv4, or IPv6."
    [ -n "$PORT" ] && { [[ ! "$PORT" =~ ^[0-9]+$ || "$PORT" -gt 65535 ]]; } && abort "Port must be 1-65535."
    [ -n "$DNS1" ] && ! valid_ip "$DNS1" && abort "DNS1 must be valid IP (IPv4 or IPv6)."
    [ -n "$DNS2" ] && ! valid_ip "$DNS2" && abort "DNS2 must be valid IP (IPv4 or IPv6)."
    [ -z "$DNS1" ] && [ -n "$DNS2" ] && abort "DNS1 required with DNS2."
    DNS="8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844" # DNS افتراضي مزدوج
    [ -n "$DNS1" ] && [ -n "$DNS2" ] && DNS="$DNS1, $DNS2"
    [ -n "$DNS1" ] && [ -z "$DNS2" ] && DNS="$DNS1"
}

banner() { ... } # بدون تغيير
intro() { ... } # بدون تغيير
credits() { ... } # بدون تغيير
usage() { ... } # بدون تغيير
welcome() { ... } # بدون تغيير
dns_notice() { ... } # بدون تغيير

choose_addr() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nChoose server address type:"
        echo "  1) Domain (e.g., vpn.example.com)"
        echo "  2) IPv4 (auto-detect if available)"
        echo "  3) IPv6 (auto-detect if available)"
        read -rp "Type [2]: " addr_type
        until [[ -z "$addr_type" || "$addr_type" =~ ^[1-3]$ ]]; do
            echo "Invalid choice."
            read -rp "Type [2]: " addr_type
        done
        case "${addr_type:-2}" in
            1) 
                echo -e "\nEnter server domain:"
                read -r addr
                until is_fqdn "$addr"; do
                    echo "Invalid domain."
                    read -r addr
                done
                IP="$addr"
                dns_notice "$IP"
                ;;
            2) detect_ip 4 ;;
            3) detect_ip 6 ;;
        esac
    else
        [ -n "$SERVER_ADDR" ] && IP="$SERVER_ADDR" || detect_ip 6 # تفضيل IPv6 في الوضع السريع
    fi
    [ -z "$IP" ] && abort "Failed to set server address."
}

detect_ip() {
    local version="${1:-4}" # افتراضي IPv4 إذا لم يحدد
    if [ "$version" = "6" ] && ip -6 addr | grep -q 'inet6 [23]'; then
        IP=$(ip -6 addr | grep 'inet6 [23]' | grep -v 'fe80' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
        if [ -z "$IP" ] || is_private_ip "$IP"; then
            IP=$(curl -s http://ip6.icanhazip.com || curl -s http://ipv6.dynupdate6.no-ip.com)
        fi
    else
        IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -1)
        if [ -z "$IP" ] || is_private_ip "$IP"; then
            IP=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
        fi
    fi
    if ! valid_ip "$IP"; then
        [ "$QUICK" = 0 ] && pick_ip || abort "Cannot detect server IP."
    fi
    is_private_ip "$IP" && PUBLIC_IP=$(curl -s "http://ip${version}.icanhazip.com" || abort "Failed to detect public IP.")
    echo "Server IP: $IP"
    [ -n "$PUBLIC_IP" ] && echo "Public IP (NAT): $PUBLIC_IP"
}

pick_ip() {
    echo -e "\nMultiple IPs detected. Select one:"
    ip addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}|fe80' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
    read -rp "IP [1]: " ip_num
    local total=$(ip addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}|fe80' | wc -l)
    until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$total" ]]; do
        echo "Invalid choice."
        read -rp "IP [1]: " ip_num
    done
    [ -z "$ip_num" ] && ip_num=1
    IP=$(ip addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}|fe80' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "${ip_num}p")
}

set_port() { ... } # بدون تغيير

check_ipv6() {
    IP6=""
    if ip -6 addr | grep -q 'inet6 [23]'; then
        IP6=$(ip -6 addr | grep 'inet6 [23]' | grep -v 'fe80' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
    fi
    [ -n "$IP6" ] && echo "IPv6 detected: $IP6"
}

name_first_peer() { ... } # بدون تغيير

pick_dns() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nSelect DNS for the peer (supports IPv4/IPv6):"
        echo "  1) System resolvers"
        echo "  2) Google DNS (IPv4/IPv6, default)"
        echo "  3) Cloudflare DNS (IPv4/IPv6)"
        echo "  4) OpenDNS (IPv4)"
        echo "  5) Quad9 (IPv4/IPv6)"
        echo "  6) AdGuard DNS (IPv4/IPv6)"
        echo "  7) Custom"
        read -rp "DNS [2]: " dns_choice
        until [[ -z "$dns_choice" || "$dns_choice" =~ ^[1-7]$ ]]; do
            echo "Invalid choice."
            read -rp "DNS [2]: " dns_choice
        done
    else
        dns_choice=2
    fi
    case "$dns_choice" in
        1)
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
                resolv="/etc/resolv.conf"
            else
                resolv="/run/systemd/resolve/resolv.conf"
            fi
            DNS=$(grep -v '^#\|^;' "$resolv" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | xargs | sed 's/ /, /g')
            ;;
        2|"") DNS="8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844" ;;
        3) DNS="1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001" ;;
        4) DNS="208.67.222.222, 208.67.220.220" ;;
        5) DNS="9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9" ;;
        6) DNS="94.140.14.14, 94.140.15.15, 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff" ;;
        7)
            echo "Primary DNS (IPv4 or IPv6):"
            read -r dns1
            until valid_ip "$dns1"; do
                echo "Invalid DNS."
                read -r dns1
            done
            echo "Secondary DNS (optional, IPv4 or IPv6):"
            read -r dns2
            [ -n "$dns2" ] && until valid_ip "$dns2"; do
                echo "Invalid DNS."
                read -r dns2
            done
            DNS="$dns1"
            [ -n "$dns2" ] && DNS="$dns1, $dns2"
            ;;
    esac
    echo "DNS: $DNS"
}

prep_install() { ... } # بدون تغيير
install_deps() { ... } # بدون تغيير

gen_server_config() {
    local priv=$(wg genkey)
    echo "$priv" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    echo "$priv" > /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    local addr4="10.7.0.1/24"
    local addr6=""
    [ -n "$IP6" ] && [[ "$IP" =~ : ]] && addr6=", fddd:2c4:2c4:2c4::1/64"
    cat > "$WG_CONFIG" << EOF
# ENDPOINT $([ -n "$PUBLIC_IP" ] && echo "$PUBLIC_IP" || echo "$IP")
[Interface]
Address = $addr4$addr6
PrivateKey = $priv
ListenPort = $PORT
EOF
    chmod 600 "$WG_CONFIG"
}

setup_firewall() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if ! iptables -t nat -C POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE 2>/dev/null; then
        if systemctl is-active --quiet firewalld.service; then
            firewall-cmd --add-port="$PORT"/udp --permanent
            firewall-cmd --zone=trusted --add-source="10.7.0.0/24" --permanent
            firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE --permanent
            [ -n "$IP6" ] && firewall-cmd --zone=trusted --add-source="fddd:2c4:2c4:2c4::/64" --permanent
            firewall-cmd --reload
        else
            iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
            iptables -A FORWARD -s 10.7.0.0/24 -j ACCEPT
            iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
            iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE
            [ -n "$IP6" ] && ip6tables -t nat -A POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -o "$net_if" -j MASQUERADE
        fi
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wg.conf
    [ -n "$IP6" ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wg.conf
    sysctl -p /etc/sysctl.d/99-wg.conf
}

new_peer() {
    local peer_name="$1"
    local octet=2
    while grep -q "AllowedIPs = 10.7.0.$octet/32" "$WG_CONFIG"; do
        ((octet++))
    done
    [ "$octet" -eq 255 ] && abort "Subnet full. Max 253 peers."
    local key=$(wg genkey)
    local psk=$(wg genpsk)
    local pub=$(echo "$key" | wg pubkey)
    local allowed_ips="10.7.0.$octet/32"
    [ -n "$IP6" ] && [[ "$IP" =~ : ]] && allowed_ips="$allowed_ips, fddd:2c4:2c4:2c4::$octet/128"
    cat >> "$WG_CONFIG" << EOF

# BEGIN $peer_name
[Peer]
PublicKey = $pub
PresharedKey = $psk
AllowedIPs = $allowed_ips
# END $peer_name
EOF
    local server_pub=$(cat /etc/wireguard/server.pub)
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    local endpoint_ip=$(grep '^# ENDPOINT' "$WG_CONFIG" | cut -d ' ' -f 3)
    local endpoint_port=$(grep '^ListenPort' "$WG_CONFIG" | cut -d ' ' -f 3)
    [ -z "$endpoint_ip" ] && endpoint_ip="$IP"
    [ -z "$endpoint_port" ] && endpoint_port="$PORT"
    local temp_conf=$(mktemp)
    local client_addr="10.7.0.$octet/24"
    [ -n "$IP6" ] && [[ "$IP" =~ : ]] && client_addr="$client_addr, fddd:2c4:2c4:2c4::$octet/64"
    cat > "$temp_conf" << EOF
[Interface]
Address = $client_addr
DNS = $DNS
PrivateKey = $key

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint_ip:$endpoint_port
PersistentKeepalive = 25
EOF
    chmod 600 "$temp_conf"
    qrencode -t UTF8 < "$temp_conf"
    echo "Added '$peer_name'. Config at: $out_dir$peer_name.conf${ENCRYPT:+.gpg}"
    if [ "$ENCRYPT" = 1 ]; then
        cp "$temp_conf" "$out_dir$peer_name.conf"
        echo "Enter a passphrase to encrypt $peer_name.conf:"
        gpg -c "$out_dir$peer_name.conf"
        rm -f "$out_dir$peer_name.conf"
        echo "Encrypted config saved as $out_dir$peer_name.conf.gpg"
    else
        mv "$temp_conf" "$out_dir$peer_name.conf"
        [ -n "$SUDO_USER" ] && chown "$SUDO_USER:$SUDO_USER" "$out_dir$peer_name.conf"
    fi
    rm -f "$temp_conf"
    wg addconf wg0 <(sed -n "/^# BEGIN $peer_name$/,/^# END $peer_name$/p" "$WG_CONFIG")
}

start_service() { ... } # بدون تغيير
optimize_network() { ... } # بدون تغيير
finish() { ... } # بدون تغيير
list_peers() { ... } # بدون تغيير
remove_peer() { ... } # بدون تغيير
show_qr() { ... } # بدون تغيير
encrypt_peer() { ... } # بدون تغيير
decrypt_peer() { ... } # بدون تغيير
uninstall_wg() { ... } # بدون تغيير
set_new_peer() { ... } # بدون تغيير
setup_wg() { ... } # بدون تغيير

setup_wg "$@"
exit 0

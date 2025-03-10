#!/bin/bash

# WireGuard Quick Install Script
# Fast setup for WireGuard VPN servers
# Source: https://github.com/almajnoun/wg-quick-install
# By Almajnoun
# MIT License - 2025

abort() { echo "Error: $1" >&2; exit 1; }
abort_apt() { abort "'apt-get install' failed."; }
abort_yum() { abort "'yum install' failed."; }
abort_zypper() { abort "'zypper install' failed."; }

valid_ip() {
    local ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$ip_regex"
}

valid_ip6() {
    local ip6_regex='^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$|^([0-9a-fA-F]{0,4}:){1,7}:$|^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$ip6_regex"
}

is_private_ip() {
    local priv_regex='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$priv_regex"
}

is_fqdn() {
    local fqdn_regex='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$fqdn_regex"
}

root_check() {
    [ "$(id -u)" -ne 0 ] && abort "Run as root with 'sudo bash $0'."
}

bash_check() {
    readlink /proc/$$/exe | grep -q "dash" && abort "Use 'bash', not 'sh'."
}

kernel_check() {
    [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && abort "Old kernel not supported."
}

os_detect() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_ver=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [ -e /etc/debian_version ]; then
        os="debian"
        os_ver=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
        os="centos"
        os_ver=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [ -e /etc/fedora-release ]; then
        os="fedora"
        os_ver=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [ -e /etc/SUSE-brand ] && grep -q "openSUSE" /etc/SUSE-brand; then
        os="openSUSE"
        os_ver=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        abort "Unsupported OS. Use Ubuntu, Debian, CentOS, Fedora, or openSUSE."
    fi
}

os_ver_check() {
    [ "$os" = "ubuntu" ] && [ "$os_ver" -lt 2004 ] && abort "Ubuntu 20.04+ required."
    [ "$os" = "debian" ] && [ "$os_ver" -lt 11 ] && abort "Debian 11+ required."
    [ "$os" = "centos" ] && [ "$os_ver" -lt 8 ] && abort "CentOS 8+ required."
}

container_check() {
    systemd-detect-virt -cq 2>/dev/null && abort "Containers not supported."
}

clean_name() {
    peer=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "$raw_name" | cut -c-15)
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --quick) QUICK=1; shift ;;
            --new-peer) NEW_PEER=1; raw_name="$2"; shift 2 ;;
            --list-peers) LIST_PEERS=1; shift ;;
            --rm-peer) RM_PEER=1; raw_name="$2"; shift 2 ;;
            --qr-peer) QR_PEER=1; raw_name="$2"; shift 2 ;;
            --uninstall) UNINSTALL=1; shift ;;
            --addr) SERVER_ADDR="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --name) FIRST_PEER="$2"; shift 2 ;;
            --dns1) DNS1="$2"; shift 2 ;;
            --dns2) DNS2="$2"; shift 2 ;;
            -y|--yes) YES=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) usage "Unknown option: $1"; exit 1 ;;
        esac
    done
}

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
    [ -n "$SERVER_ADDR" ] && ! { is_fqdn "$SERVER_ADDR" || valid_ip "$SERVER_ADDR" || valid_ip6 "$SERVER_ADDR"; } && abort "Address must be FQDN, IPv4, or IPv6."
    [ -n "$PORT" ] && { [[ ! "$PORT" =~ ^[0-9]+$ || "$PORT" -gt 65535 ]]; } && abort "Port must be 1-65535."
    [ -n "$DNS1" ] && ! { valid_ip "$DNS1" || valid_ip6 "$DNS1"; } && abort "DNS1 must be valid IPv4 or IPv6."
    [ -n "$DNS2" ] && ! { valid_ip "$DNS2" || valid_ip6 "$DNS2"; } && abort "DNS2 must be valid IPv4 or IPv6."
    [ -z "$DNS1" ] && [ -n "$DNS2" ] && abort "DNS1 required with DNS2."
    DNS="8.8.8.8, 8.8.4.4"
    [ -n "$DNS1" ] && [ -n "$DNS2" ] && DNS="$DNS1, $DNS2"
    [ -n "$DNS1" ] && [ -z "$DNS2" ] && DNS="$DNS1"
}

banner() {
    cat <<'EOF'

WireGuard Quick Install Script
https://github.com/almajnoun/wg-quick-install
EOF
}

intro() {
    cat <<'EOF'

Welcome to WireGuard Quick Install!
https://github.com/almajnoun/wg-quick-install

EOF
}

credits() {
    cat <<'EOF'

By Almajnoun
MIT License - 2025
EOF
}

usage() {
    [ -n "$1" ] && echo "Error: $1" >&2
    banner
    credits
    cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:
  --new-peer [name]     Add a new VPN peer
  --dns1 [IP]           Primary DNS (IPv4/IPv6, default: 8.8.8.8)
  --dns2 [IP]           Secondary DNS (IPv4/IPv6, optional)
  --list-peers          List all peers
  --rm-peer [name]      Remove a peer
  --qr-peer [name]      Show QR code for a peer
  --uninstall           Remove WireGuard and configs
  -y, --yes             Auto-confirm removals
  -h, --help            Show this help

Setup Options:
  --quick               Quick setup with defaults or customs
  --addr [DNS/IP]       VPN endpoint (FQDN, IPv4, or IPv6)
  --port [number]       WireGuard port (1-65535, default: 51820)
  --name [name]         First peer name (default: peer)
  --dns1 [IP]           First peer primary DNS (IPv4/IPv6)
  --dns2 [IP]           First peer secondary DNS (IPv4/IPv6)

Run without options for interactive mode.
EOF
    exit 1
}

welcome() {
    if [ "$QUICK" = 0 ]; then
        intro
        echo "I need some details to set up your VPN."
        echo "Press Enter for defaults."
    else
        banner
        local mode="default"
        [ -n "$SERVER_ADDR" ] || [ -n "$PORT" ] || [ -n "$FIRST_PEER" ] || [ -n "$DNS1" ] && mode="custom"
        echo -e "\nStarting setup with $mode options."
    fi
}

dns_notice() {
    cat <<EOF

Note: Ensure '$1' resolves to this server's IPv4 or IPv6 address.
EOF
}

choose_addr() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nChoose server endpoint type:"
        echo "  1) Domain (e.g., vpn.example.com)"
        echo "  2) IPv4"
        echo "  3) IPv6 (if available)"
        read -rp "Type [1]: " type_choice
        until [[ -z "$type_choice" || "$type_choice" =~ ^[1-3]$ ]]; do
            echo "Invalid choice."
            read -rp "Type [1]: " type_choice
        done
        case "${type_choice:-1}" in
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
            2) detect_ip; IP="${PUBLIC_IP:-$IP}" ;;
            3)
                detect_ip
                if [ -n "$IP6" ] || [ -n "$PUBLIC_IP6" ]; then
                    IP="${PUBLIC_IP6:-$IP6}"
                else
                    echo "No IPv6 detected. Falling back to IPv4."
                    IP="${PUBLIC_IP:-$IP}"
                fi
                ;;
        esac
    else
        [ -n "$SERVER_ADDR" ] && IP="$SERVER_ADDR" || { detect_ip; IP="${PUBLIC_IP:-$IP}"; }
    fi
    [ -z "$IP" ] && abort "Failed to set server address."
    echo "Endpoint set to: $IP"
}

detect_ip() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        IP=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! valid_ip "$IP"; then
            IP=$(timeout 5 curl -s http://ipv4.icanhazip.com || timeout 5 curl -s http://ip1.dynupdate.no-ip.com || timeout 5 curl -s https://api.ipify.org)
            if ! valid_ip "$IP"; then
                [ "$QUICK" = 0 ] && pick_ip || abort "Cannot detect server IPv4. Check network connectivity."
            fi
        fi
    fi
    is_private_ip "$IP" && PUBLIC_IP=$(timeout 5 curl -s http://ipv4.icanhazip.com || abort "Failed to detect public IPv4. Check internet connection.")

    IP6=""
    if ip -6 addr | grep -q 'inet6 [23]'; then
        IP6=$(ip -6 addr | grep 'inet6 [23]' | grep -v 'fe80::' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
    fi
    if [ -z "$IP6" ] && [ "$QUICK" = 0 ]; then
        PUBLIC_IP6=$(timeout 5 curl -s http://ipv6.icanhazip.com || timeout 5 curl -s https://api64.ipify.org)
        [ -n "$PUBLIC_IP6" ] && valid_ip6 "$PUBLIC_IP6" && IP6="$PUBLIC_IP6"
    fi

    echo "Server IPv4: $IP"
    [ -n "$PUBLIC_IP" ] && echo "Public IPv4 (NAT): $PUBLIC_IP"
    [ -n "$IP6" ] && echo "Server IPv6: $IP6"
    [ -n "$PUBLIC_IP6" ] && echo "Public IPv6 (NAT): $PUBLIC_IP6"
}

pick_ip() {
    echo -e "\nMultiple IPs detected. Select one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "IP [1]: " ip_num
    local total=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$total" ]]; do
        echo "Invalid choice."
        read -rp "IP [1]: " ip_num
    done
    [ -z "$ip_num" ] && ip_num=1
    IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_num}p")
}

set_port() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nChoose WireGuard port [51820]:"
        read -r p
        PORT="${p:-51820}"
        until [[ "$PORT" =~ ^[0-9]+$ && "$PORT" -le 65535 ]]; do
            echo "Invalid port."
            read -r p
            PORT="${p:-51820}"
        done
    else
        PORT="${PORT:-51820}"
    fi
    echo "Port: $PORT"
}

check_ipv6() {
    IP6=""
    if ip -6 addr | grep -q 'inet6 [23]'; then
        IP6=$(ip -6 addr | grep 'inet6 [23]' | grep -v 'fe80::' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
    fi
    if [ -z "$IP6" ]; then
        echo "No global IPv6 detected. Using IPv4 only."
    else
        echo "IPv6 detected: $IP6"
    fi
}

name_first_peer() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nName the first peer [peer]:"
        read -r raw
        FIRST_PEER="${raw:-peer}"
        raw_name="$FIRST_PEER"
        clean_name
        FIRST_PEER="$peer"
    else
        FIRST_PEER="${FIRST_PEER:-peer}"
        raw_name="$FIRST_PEER"
        clean_name
        FIRST_PEER="$peer"
    fi
    echo "First Peer: $FIRST_PEER"
}

pick_dns() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nSelect DNS for the peer (IPv4/IPv6 support):"
        echo "  1) System resolvers"
        echo "  2) Google DNS (IPv4: 8.8.8.8, 8.8.4.4; IPv6: 2001:4860:4860::8888, 2001:4860:4860::8844)"
        echo "  3) Cloudflare DNS (IPv4: 1.1.1.1, 1.0.0.1; IPv6: 2606:4700:4700::1111, 2606:4700:4700::1001)"
        echo "  4) OpenDNS (IPv4 only: 208.67.222.222, 208.67.220.220)"
        echo "  5) Quad9 (IPv4: 9.9.9.9, 149.112.112.112; IPv6: 2620:fe::fe, 2620:fe::9)"
        echo "  6) AdGuard DNS (IPv4: 94.140.14.14, 94.140.15.15; IPv6: 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff)"
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
        2|"")
            DNS="8.8.8.8, 8.8.4.4"
            [ -n "$IP6" ] && DNS="$DNS, 2001:4860:4860::8888, 2001:4860:4860::8844"
            ;;
        3)
            DNS="1.1.1.1, 1.0.0.1"
            [ -n "$IP6" ] && DNS="$DNS, 2606:4700:4700::1111, 2606:4700:4700::1001"
            ;;
        4)
            DNS="208.67.222.222, 208.67.220.220"
            ;;
        5)
            DNS="9.9.9.9, 149.112.112.112"
            [ -n "$IP6" ] && DNS="$DNS, 2620:fe::fe, 2620:fe::9"
            ;;
        6)
            DNS="94.140.14.14, 94.140.15.15"
            [ -n "$IP6" ] && DNS="$DNS, 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff"
            ;;
        7)
            echo "Primary DNS (IPv4 or IPv6):"
            read -r dns1
            until valid_ip "$dns1" || valid_ip6 "$dns1"; do
                echo "Invalid DNS."
                read -r dns1
            done
            echo "Secondary DNS (optional, IPv4 or IPv6):"
            read -r dns2
            [ -n "$dns2" ] && until valid_ip "$dns2" || valid_ip6 "$dns2"; do
                echo "Invalid DNS."
                read -r dns2
            done
            DNS="$dns1"
            [ -n "$dns2" ] && DNS="$dns1, $dns2"
            ;;
    esac
    echo "DNS: $DNS"
}

check_connectivity() {
    if ! ping -c 3 8.8.8.8 >/dev/null 2>&1 && ! ping6 -c 3 2001:4860:4860::8888 >/dev/null 2>&1; then
        abort "No internet connection detected (IPv4/IPv6). Please check your network."
    fi
}

prep_install() {
    echo -e "\nChecking connectivity before installation..."
    check_connectivity
    echo -e "Installing WireGuard..."
}

install_deps() {
    case "$os" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables iproute2 || abort_apt
            ;;
        "centos")
            [ "$os_ver" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables iproute || abort_yum
            [ "$os_ver" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables iproute || abort_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables iproute || abort "dnf failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables iproute2 || abort_zypper
            ;;
    esac
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
}

gen_server_config() {
    local priv=$(wg genkey)
    echo "$priv" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    echo "$priv" > /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    cat > "$WG_CONFIG" << EOF
# ENDPOINT $([ -n "$PUBLIC_IP" ] && echo "$PUBLIC_IP" || echo "$IP")$( [ -n "$IP6" ] && echo " or [$IP6]" )
[Interface]
Address = 10.7.0.1/24$( [ -n "$IP6" ] && echo ", fddd:2c4:2c4:2c4::1/64" )
PrivateKey = $priv
ListenPort = $PORT
EOF
    chmod 600 "$WG_CONFIG"
}

setup_firewall() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$net_if" ] && abort "Cannot detect default network interface."
    
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$PORT"/udp --permanent || abort "Failed to configure firewalld port"
        firewall-cmd --zone=trusted --add-source="10.7.0.0/24" --permanent
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE --permanent
        [ -n "$IP6" ] && firewall-cmd --zone=trusted --add-source="fddd:2c4:2c4:2c4::/64" --permanent
        [ -n "$IP6" ] && firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE --permanent
        firewall-cmd --reload || abort "Failed to reload firewalld"
    else
        iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || abort "Failed to set iptables INPUT rule"
        iptables -A FORWARD -s 10.7.0.0/24 -j ACCEPT 2>/dev/null
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
        iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE 2>/dev/null || abort "Failed to set NAT masquerading"
        if [ -n "$IP6" ]; then
            ip6tables -A INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || abort "Failed to set ip6tables INPUT rule"
            ip6tables -A FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT 2>/dev/null
            ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
            ip6tables -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 -o "$net_if" -j MASQUERADE 2>/dev/null || abort "Failed to set IPv6 NAT masquerading"
        fi
    fi
    
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || abort "Failed to enable IP forwarding"
    [ -n "$IP6" ] && sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
    
    cat > /etc/sysctl.d/99-wg.conf << EOF
net.ipv4.ip_forward=1
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.ipv4.tcp_rmem=4096 131072 26214400
net.ipv4.tcp_wmem=4096 131072 26214400
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=2500
EOF
    [ -n "$IP6" ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wg.conf
    sysctl -p /etc/sysctl.d/99-wg.conf >/dev/null 2>&1 || abort "Failed to apply sysctl settings"
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
    cat >> "$WG_CONFIG" << EOF

# BEGIN $peer_name
[Peer]
PublicKey = $pub
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$( [ -n "$IP6" ] && echo ", fddd:2c4:2c4:2c4::$octet/128" )
# END $peer_name
EOF
    local server_pub=$(cat /etc/wireguard/server.pub)
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    local endpoint_ip=$(grep '^# ENDPOINT' "$WG_CONFIG" | cut -d ' ' -f 3)
    local endpoint_port=$(grep '^ListenPort' "$WG_CONFIG" | cut -d ' ' -f 3)
    [ -z "$endpoint_ip" ] && endpoint_ip="$IP"
    [ -z "$endpoint_port" ] && endpoint_port="$PORT"

    local allowed_ips="0.0.0.0/0"
    [ -n "$IP6" ] && allowed_ips="0.0.0.0/0, ::/0"

    local endpoint_display="$endpoint_ip:$endpoint_port"
    if valid_ip6 "$endpoint_ip"; then
        endpoint_display="[$endpoint_ip]:$endpoint_port"
    fi

    cat > "$out_dir$peer_name.conf" << EOF
[Interface]
Address = 10.7.0.$octet/24$( [ -n "$IP6" ] && echo ", fddd:2c4:2c4:2c4::$octet/64" )
DNS = $DNS
PrivateKey = $key

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
AllowedIPs = $allowed_ips
Endpoint = $endpoint_display
PersistentKeepalive = 25
EOF
    chmod 600 "$out_dir$peer_name.conf"
    [ -n "$SUDO_USER" ] && chown "$SUDO_USER:$SUDO_USER" "$out_dir$peer_name.conf"
    wg addconf wg0 <(sed -n "/^# BEGIN $peer_name$/,/^# END $peer_name$/p" "$WG_CONFIG")
    echo "Added '$peer_name'. Config at: $out_dir$peer_name.conf"
    qrencode -t UTF8 < "$out_dir$peer_name.conf"
}

start_service() {
    systemctl enable wg-quick@wg0.service >/dev/null 2>&1 || abort "Failed to enable WireGuard service"
    systemctl start wg-quick@wg0.service >/dev/null 2>&1 || { systemctl status wg-quick@wg0.service; abort "Service failed to start."; }
    if ! wg show wg0 >/dev/null 2>&1; then
        abort "WireGuard interface wg0 not active. Check configuration."
    fi
}

finish() {
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    echo -e "\nDone! Peer config at: $out_dir$FIRST_PEER.conf"
}

list_peers() {
    grep '^# BEGIN' "$WG_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    local count=$(grep -c '^# BEGIN' "$WG_CONFIG")
    echo -e "\nTotal: $count peers"
}

remove_peer() {
    echo "Select peer to remove:"
    list_peers
    read -rp "Number: " num
    local total=$(grep -c '^# BEGIN' "$WG_CONFIG")
    until [[ "$num" =~ ^[0-9]+$ && "$num" -le "$total" ]]; do
        echo "Invalid."
        read -rp "Number: " num
    done
    local peer=$(grep '^# BEGIN' "$WG_CONFIG" | cut -d ' ' -f 3 | sed -n "${num}p")
    wg set wg0 peer "$(sed -n "/^# BEGIN $peer$/,\$p" "$WG_CONFIG" | grep -m 1 PublicKey | cut -d ' ' -f 3)" remove
    sed -i "/^# BEGIN $peer$/,/^# END $peer$/d" "$WG_CONFIG"
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    rm -f "$out_dir$peer.conf"
    echo "Removed '$peer'."
}

show_qr() {
    echo "Select peer for QR:"
    list_peers
    read -rp "Number: " num
    local total=$(grep -c '^# BEGIN' "$WG_CONFIG")
    until [[ "$num" =~ ^[0-9]+$ && "$num" -le "$total" ]]; do
        echo "Invalid."
        read -rp "Number: " num
    done
    local peer=$(grep '^# BEGIN' "$WG_CONFIG" | cut -d ' ' -f 3 | sed -n "${num}p")
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    [ -f "$out_dir$peer.conf" ] || abort "Config for '$peer' not found."
    qrencode -t UTF8 < "$out_dir$peer.conf"
    echo "QR for '$peer' shown."
}

uninstall_wg() {
    systemctl disable wg-quick@wg0.service >/dev/null 2>&1
    systemctl stop wg-quick@wg0.service >/dev/null 2>&1

    rm -rf /etc/wireguard
    rm -f /etc/sysctl.d/99-wg.conf
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
    [ -n "$IP6" ] && sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1

    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$net_if" ]; then
        iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -s 10.7.0.0/24 -j ACCEPT 2>/dev/null
        iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
        iptables -t nat -D POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE 2>/dev/null
        if [ -n "$IP6" ]; then
            ip6tables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null
            ip6tables -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT 2>/dev/null
            ip6tables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
            ip6tables -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 -o "$net_if" -j MASQUERADE 2>/dev/null
        fi
    fi

    case "$os" in
        "ubuntu"|"debian") apt-get remove --purge -y wireguard wireguard-tools 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools 2>/dev/null ;;
    esac

    echo "WireGuard configuration and service removed safely."
}

set_new_peer() {
    echo -e "\nEnter name for the new peer:"
    read -rp "Name: " raw_name
    [ -z "$raw_name" ] && abort "Name cannot be empty."
    clean_name
    while [ -z "$peer" ] || grep -q "^# BEGIN $peer$" "$WG_CONFIG"; do
        if [ -z "$peer" ]; then
            echo "Invalid name. Use alphanumeric, '-' or '_' only."
        else
            echo "'$peer' already exists."
        fi
        read -rp "Name: " raw_name
        [ -z "$raw_name" ] && abort "Name cannot be empty."
        clean_name
    done
    echo "New Peer: $peer"
}

setup_wg() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    command -v ip >/dev/null 2>&1 || abort "Required command 'ip' not found."
    command -v wg >/dev/null 2>&1 && [ -e "$WG_CONFIG" ] || command -v curl >/dev/null 2>&1 || abort "Required command 'curl' not found."
    
    root_check
    bash_check
    kernel_check
    os_detect
    os_ver_check
    container_check

    WG_CONFIG="/etc/wireguard/wg0.conf"

    QUICK=0
    YES=0
    NEW_PEER=0
    LIST_PEERS=0
    RM_PEER=0
    QR_PEER=0
    UNINSTALL=0
    PUBLIC_IP=""
    PUBLIC_IP6=""
    SERVER_ADDR=""
    PORT=""
    FIRST_PEER=""
    raw_name=""
    peer=""
    DNS=""
    DNS1=""
    DNS2=""

    parse_args "$@"
    validate_args

    if [ "$NEW_PEER" = 1 ]; then
        banner
        clean_name
        [ -z "$peer" ] && set_new_peer
        pick_dns
        new_peer "$peer"
        echo -e "\nQR code displayed."
        echo "Peer '$peer' added."
        exit 0
    fi

    if [ "$LIST_PEERS" = 1 ]; then
        banner
        echo -e "\nListing peers..."
        list_peers
        exit 0
    fi

    if [ "$RM_PEER" = 1 ]; then
        banner
        clean_name
        remove_peer
        exit 0
    fi

    if [ "$QR_PEER" = 1 ]; then
        banner
        clean_name
        show_qr
        exit 0
    fi

    if [ "$UNINSTALL" = 1 ]; then
        banner
        uninstall_wg
        exit 0
    fi

    if [ ! -e "$WG_CONFIG" ]; then
        welcome
        choose_addr
        set_port
        check_ipv6
        name_first_peer
        pick_dns
        prep_install
        install_deps
        gen_server_config
        setup_firewall
        new_peer "$FIRST_PEER"
        start_service
        echo -e "\nQR code displayed."
        finish
    else
        banner
        echo -e "\nWireGuard is running. Choose an option:"
        echo "  1) Add peer"
        echo "  2) List peers"
        echo "  3) Remove peer"
        echo "  4) Show QR"
        echo "  5) Uninstall"
        echo "  6) Exit"
        read -rp "Option: " opt
        until [[ "$opt" =~ ^[1-6]$ ]]; do
            echo "Invalid choice."
            read -rp "Option: " opt
        done
        case "$opt" in
            1) set_new_peer; pick_dns; new_peer "$peer"; echo -e "\nQR code displayed."; echo "Peer added." ;;
            2) list_peers ;;
            3) remove_peer ;;
            4) show_qr ;;
            5) uninstall_wg ;;
            6) exit 0 ;;
        esac
    fi
}

setup_wg "$@"
exit 0

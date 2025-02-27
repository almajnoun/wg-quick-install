#!/bin/bash

# WireGuard Quick Install Script
# Fast setup for WireGuard VPN servers
# Source: https://github.com/almajnoun/wireguard-installer-auto
# By Almajnoun, optimized with Grok 3 (xAI)
# MIT License - 2025

abort() { echo "Error: $1" >&2; exit 1; }
abort_apt() { abort "'apt-get install' failed."; }
abort_yum() { abort "'yum install' failed."; }
abort_zypper() { abort "'zypper install' failed."; }

valid_ip() {
    local ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$ip_regex"
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
            --encrypt) ENCRYPT=1; shift ;;
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
    [ -n "$SERVER_ADDR" ] && ! { is_fqdn "$SERVER_ADDR" || valid_ip "$SERVER_ADDR"; } && abort "Address must be FQDN or IPv4."
    [ -n "$PORT" ] && { [[ ! "$PORT" =~ ^[0-9]+$ || "$PORT" -gt 65535 ]]; } && abort "Port must be 1-65535."
    [ -n "$DNS1" ] && ! valid_ip "$DNS1" && abort "DNS1 must be valid IP."
    [ -n "$DNS2" ] && ! valid_ip "$DNS2" && abort "DNS2 must be valid IP."
    [ -z "$DNS1" ] && [ -n "$DNS2" ] && abort "DNS1 required with DNS2."
    DNS="8.8.8.8, 8.8.4.4"
    [ -n "$DNS1" ] && [ -n "$DNS2" ] && DNS="$DNS1, $DNS2"
    [ -n "$DNS1" ] && [ -z "$DNS2" ] && DNS="$DNS1"
}

banner() {
    cat <<'EOF'

WireGuard Quick Install Script
https://github.com/almajnoun/wireguard-installer-auto
EOF
}

intro() {
    cat <<'EOF'

Welcome to WireGuard Quick Install!
https://github.com/almajnoun/wireguard-installer-auto

EOF
}

credits() {
    cat <<'EOF'

By Almajnoun, optimized with Grok 3 (xAI)
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
  --dns1 [IP]           Primary DNS (default: 8.8.8.8)
  --dns2 [IP]           Secondary DNS (optional)
  --list-peers          List all peers
  --rm-peer [name]      Remove a peer
  --qr-peer [name]      Show QR code for a peer
  --uninstall           Remove WireGuard and configs
  --encrypt             Encrypt peer config files
  -y, --yes             Auto-confirm removals
  -h, --help            Show this help

Setup Options:
  --quick               Quick setup with defaults or customs
  --addr [DNS/IP]       VPN endpoint (FQDN or IPv4)
  --port [number]       WireGuard port (1-65535, default: 51820)
  --name [name]         First peer name (default: peer)
  --dns1 [IP]           First peer primary DNS
  --dns2 [IP]           First peer secondary DNS

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

Note: Ensure '$1' resolves to this server's IPv4.
EOF
}

choose_addr() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nUse domain (e.g., vpn.example.com) instead of IP? [y/N]:"
        read -r resp
        case "$resp" in
            [yY]*) 
                echo -e "\nEnter server domain:"
                read -r addr
                until is_fqdn "$addr"; do
                    echo "Invalid domain."
                    read -r addr
                done
                IP="$addr"
                dns_notice "$IP"
                ;;
            *) detect_ip ;;
        esac
    else
        [ -n "$SERVER_ADDR" ] && IP="$SERVER_ADDR" || detect_ip
    fi
    [ -z "$IP" ] && abort "Failed to set server address."
}

detect_ip() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        IP=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! valid_ip "$IP"; then
            IP=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! valid_ip "$IP"; then
                [ "$QUICK" = 0 ] && pick_ip || abort "Cannot detect server IP."
            fi
        fi
    fi
    is_private_ip "$IP" && PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com || abort "Failed to detect public IP.")
    echo "Server IP: $IP"
    [ -n "$PUBLIC_IP" ] && echo "Public IP (NAT): $PUBLIC_IP"
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
        IP6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
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
        echo -e "\nSelect DNS for the peer:"
        echo "  1) System resolvers"
        echo "  2) Google DNS (default)"
        echo "  3) Cloudflare DNS"
        echo "  4) OpenDNS"
        echo "  5) Quad9"
        echo "  6) AdGuard DNS"
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
            DNS=$(grep -v '^#\|^;' "$resolv" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed 's/ /, /g')
            ;;
        2|"") DNS="8.8.8.8, 8.8.4.4" ;;
        3) DNS="1.1.1.1, 1.0.0.1" ;;
        4) DNS="208.67.222.222, 208.67.220.220" ;;
        5) DNS="9.9.9.9, 149.112.112.112" ;;
        6) DNS="94.140.14.14, 94.140.15.15" ;;
        7)
            echo "Primary DNS:"
            read -r dns1
            until valid_ip "$dns1"; do
                echo "Invalid DNS."
                read -r dns1
            done
            echo "Secondary DNS (optional):"
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

prep_install() {
    echo -e "\nInstalling WireGuard..."
}

install_deps() {
    case "$os" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables gnupg || abort_apt
            ;;
        "centos")
            [ "$os_ver" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables gnupg || abort_yum
            [ "$os_ver" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables gnupg || abort_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables gnupg || abort "dnf failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables gnupg || abort_zypper
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
# ENDPOINT $([ -n "$PUBLIC_IP" ] && echo "$PUBLIC_IP" || echo "$IP")
[Interface]
Address = 10.7.0.1/24$( [ -n "$IP6" ] && echo ", fddd:2c4:2c4:2c4::1/64" )
PrivateKey = $priv
ListenPort = $PORT
EOF
    chmod 600 "$WG_CONFIG"
}

setup_firewall() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if iptables -t nat -C POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE 2>/dev/null; then
        echo "NAT rule already exists for 10.7.0.0/24. Skipping..."
    else
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
    local temp_conf=$(mktemp)  # ملف مؤقت للتكوين غير المشفر
    cat > "$temp_conf" << EOF
[Interface]
Address = 10.7.0.$octet/24$( [ -n "$IP6" ] && echo ", fddd:2c4:2c4:2c4::$octet/64" )
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
    wg addconf wg0 <(sed -n "/^# BEGIN $peer_name$/,/^# END $peer_name$/p" "$WG_CONFIG")
    echo "Added '$peer_name'. Config at: $out_dir$peer_name.conf${ENCRYPT:+.gpg}"
    qrencode -t UTF8 < "$temp_conf"  # عرض QR من الملف المؤقت غير المشفر
    rm -f "$temp_conf"  # حذف الملف المؤقت بعد العرض
}

start_service() {
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service || { systemctl status wg-quick@wg0.service; abort "Service failed."; }
}

optimize_network() {
    if modprobe -q tcp_bbr && [ "$(uname -r | cut -d '.' -f 1-2)" \> "4.19" ]; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-wg.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-wg.conf
        sysctl -p /etc/sysctl.d/99-wg.conf
        echo "TCP BBR enabled for better performance and security."
    fi
}

finish() {
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    echo -e "\nDone! Peer config at: $out_dir$FIRST_PEER.conf${ENCRYPT:+.gpg}"
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
    rm -f "$out_dir$peer.conf" "$out_dir$peer.conf.gpg"
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
    if [ -f "$out_dir$peer.conf.gpg" ]; then
        echo "Config is encrypted. Decrypt it first with 'gpg -d $out_dir$peer.conf.gpg'"
    elif [ -f "$out_dir$peer.conf" ]; then
        qrencode -t UTF8 < "$out_dir$peer.conf"
        echo "QR for '$peer' shown."
    else
        abort "Config for '$peer' not found."
    fi
}

uninstall_wg() {
    systemctl disable wg-quick@wg0.service
    systemctl stop wg-quick@wg0.service
    rm -rf /etc/wireguard /etc/sysctl.d/99-wg.conf
    iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s "10.7.0.0/24" -j MASQUERADE 2>/dev/null
    [ -n "$IP6" ] && ip6tables -t nat -D POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -j MASQUERADE 2>/dev/null
    case "$os" in
        "ubuntu"|"debian") apt-get remove --purge -y wireguard qrencode iptables gnupg 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools qrencode iptables gnupg 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables gnupg 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables gnupg 2>/dev/null ;;
    esac
    echo "WireGuard removed."
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

# Main Execution
setup_wg() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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
    ENCRYPT=0
    PUBLIC_IP=""
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
        optimize_network
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

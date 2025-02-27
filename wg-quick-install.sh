#!/bin/bash

# WireGuard Quick Install Script
# Fast setup for WireGuard VPN servers
# Source: https://github.com/almajnoun/wireguard-installer-auto
# By Almajnoun, optimized with Grok 3 (xAI)
# MIT License - 2025

# Error Handlers
abort() { echo "Error: $1" >&2; exit 1; }
abort_apt() { abort "Failed to install via apt-get."; }
abort_yum() { abort "Failed to install via yum."; }
abort_zypper() { abort "Failed to install via zypper."; }

# Validators
valid_ip() {
    local ip_pat='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    echo "$1" | grep -Eq "$ip_pat"
}

is_private_ip() {
    local priv_pat='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    echo "$1" | grep -Eq "$priv_pat"
}

is_fqdn() {
    local fqdn_pat='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    echo "$1" | grep -Eq "$fqdn_pat"
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
        SYS="ubuntu"
        SYS_VER=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [ -e /etc/debian_version ]; then
        SYS="debian"
        SYS_VER=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
        SYS="centos"
        SYS_VER=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [ -e /etc/fedora-release ]; then
        SYS="fedora"
        SYS_VER=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [ -e /etc/SUSE-brand ] && grep -q "openSUSE" /etc/SUSE-brand; then
        SYS="openSUSE"
        SYS_VER=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        abort "Unsupported OS. Use Ubuntu, Debian, CentOS, Fedora, or openSUSE."
    fi
}

os_version_check() {
    [ "$SYS" = "ubuntu" ] && [ "$SYS_VER" -lt 2004 ] && abort "Ubuntu 20.04+ required."
    [ "$SYS" = "debian" ] && [ "$SYS_VER" -lt 11 ] && abort "Debian 11+ required."
    [ "$SYS" = "centos" ] && [ "$SYS_VER" -lt 8 ] && abort "CentOS 8+ required."
}

container_check() {
    systemd-detect-virt -cq 2>/dev/null && abort "Containers not supported."
}

sanitize_name() {
    PEER=$(echo "$RAW_NAME" | sed 's/[^0-9a-zA-Z_-]/_/g' | cut -c-15)
}

# Argument Parsing
parse_flags() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --quick) QUICK=1; shift ;;
            --new-peer) NEW_PEER=1; RAW_NAME="$2"; shift 2 ;;
            --list-peers) LIST_PEERS=1; shift ;;
            --rm-peer) RM_PEER=1; RAW_NAME="$2"; shift 2 ;;
            --qr-peer) QR_PEER=1; RAW_NAME="$2"; shift 2 ;;
            --uninstall) UNINSTALL=1; shift ;;
            --addr) SERVER_ADDR="$2"; shift 2 ;;
            --port) SERVER_PORT="$2"; shift 2 ;;
            --name) FIRST_PEER="$2"; shift 2 ;;
            --dns1) DNS1="$2"; shift 2 ;;
            --dns2) DNS2="$2"; shift 2 ;;
            -y|--yes) YES=1; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) show_usage "Invalid flag: $1"; exit 1 ;;
        esac
    done
}

validate_flags() {
    [ "$QUICK" = 1 ] && [ -e "$WG_CONFIG" ] && show_usage "Cannot use '--quick' with existing setup."
    [ "$(($NEW_PEER + $LIST_PEERS + $RM_PEER + $QR_PEER))" -gt 1 ] && show_usage "Only one action allowed."
    [ "$UNINSTALL" = 1 ] && [ "$(($NEW_PEER + $LIST_PEERS + $RM_PEER + $QR_PEER + $QUICK))" -gt 0 ] && show_usage "'--uninstall' cannot combine with other actions."
    if [ ! -e "$WG_CONFIG" ]; then
        local msg="Setup WireGuard first to"
        [ "$NEW_PEER" = 1 ] && abort "$msg add a peer."
        [ "$LIST_PEERS" = 1 ] && abort "$msg list peers."
        [ "$RM_PEER" = 1 ] && abort "$msg remove a peer."
        [ "$QR_PEER" = 1 ] && abort "$msg show QR code."
        [ "$UNINSTALL" = 1 ] && abort "No WireGuard to uninstall."
    fi
    [ "$NEW_PEER" = 1 ] && sanitize_name && [ -z "$PEER" ] && abort "Peer name must be alphanumeric with '-' or '_'."
    [ "$RM_PEER" = 1 ] || [ "$QR_PEER" = 1 ] && sanitize_name && { [ -z "$PEER" ] || ! grep -q "^# BEGIN $PEER$" "$WG_CONFIG"; } && abort "Invalid or missing peer."
    [ -n "$SERVER_ADDR" ] && ! { is_fqdn "$SERVER_ADDR" || valid_ip "$SERVER_ADDR"; } && abort "Address must be FQDN or IPv4."
    [ -n "$SERVER_PORT" ] && { [[ ! "$SERVER_PORT" =~ ^[0-9]+$ || "$SERVER_PORT" -gt 65535 ]]; } && abort "Port must be 1-65535."
    [ -n "$DNS1" ] && ! valid_ip "$DNS1" && abort "DNS1 must be valid IP."
    [ -n "$DNS2" ] && ! valid_ip "$DNS2" && abort "DNS2 must be valid IP."
    [ -z "$DNS1" ] && [ -n "$DNS2" ] && abort "DNS1 required with DNS2."
    DNS="$DNS_DEFAULT"
    [ -n "$DNS1" ] && [ -n "$DNS2" ] && DNS="$DNS1, $DNS2"
    [ -n "$DNS1" ] && [ -z "$DNS2" ] && DNS="$DNS1"
}

# Display Functions
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

show_usage() {
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
  -y, --yes             Auto-confirm removals
  -h, --help            Display this help

Setup Options (optional):
  --quick               Quick setup with defaults or customs
  --addr [DNS/IP]       VPN endpoint (FQDN or IPv4)
  --port [number]       WireGuard port (1-65535, default: 51820)
  --name [name]         First peer name (default: peer)
  --dns1 [IP]           First peer primary DNS
  --dns2 [IP]           First peer secondary DNS

Run without options for interactive setup.
EOF
    exit 1
}

greet() {
    if [ "$QUICK" = 0 ]; then
        intro
        echo "I'll need some info to configure your VPN."
        echo "Hit Enter for defaults."
    else
        banner
        local type="default"
        [ -n "$SERVER_ADDR" ] || [ -n "$SERVER_PORT" ] || [ -n "$FIRST_PEER" ] || [ -n "$DNS1" ] && type="custom"
        echo -e "\nDeploying WireGuard with $type settings."
    fi
}

dns_note() {
    cat <<EOF

Note: Ensure '$1' points to this server's IPv4.
EOF
}

# Setup Functions
pick_address() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nUse a domain (e.g., vpn.example.com) instead of IP? [y/N]:"
        read -r ans
        case "$ans" in
            [yY]*) 
                echo -e "\nEnter VPN server domain:"
                read -r addr
                until is_fqdn "$addr"; do
                    echo "Invalid domain. Use a valid FQDN."
                    read -r addr
                done
                ADDR="$addr"
                dns_note "$ADDR"
                ;;
            *) find_server_ip ;;
        esac
    else
        [ -n "$SERVER_ADDR" ] && ADDR="$SERVER_ADDR" || find_server_ip
    fi
    [ -z "$ADDR" ] && abort "Failed to determine server address."
}

find_server_ip() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        ADDR=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        ADDR=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! valid_ip "$ADDR"; then
            ADDR=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! valid_ip "$ADDR"; then
                [ "$QUICK" = 0 ] && select_ip || abort "Unable to detect IP."
            fi
        fi
    fi
    is_private_ip "$ADDR" && PUBLIC_ADDR=$(curl -s http://ipv4.icanhazip.com || abort "Failed to get public IP.")
    echo "Server IP: $ADDR"
    [ -n "$PUBLIC_ADDR" ] && echo "Public IP (NAT): $PUBLIC_ADDR"
}

select_ip() {
    echo -e "\nMultiple IPs found. Pick one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "IP [1]: " num
    local total=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$num" || "$num" =~ ^[0-9]+$ && "$num" -le "$total" ]]; do
        echo "Invalid choice."
        read -rp "IP [1]: " num
    done
    [ -z "$num" ] && num=1
    ADDR=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${num}p")
}

choose_port() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nSet WireGuard port [51820]:"
        read -r p
        PORT="${p:-51820}"
        until [[ "$PORT" =~ ^[0-9]+$ && "$PORT" -le 65535 ]]; do
            echo "Invalid port."
            read -r p
            PORT="${p:-51820}"
        done
    else
        PORT="${SERVER_PORT:-51820}"
    fi
    echo "Port: $PORT"
}

check_ipv6() {
    IPV6_ADDR=""
    if ip -6 addr | grep -q 'inet6 [23]'; then
        IPV6_ADDR=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
    fi
}

set_first_peer() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nName the first peer [peer]:"
        read -r raw
        FIRST_PEER="${raw:-peer}"
        RAW_NAME="$FIRST_PEER"
        sanitize_name
        FIRST_PEER="$PEER"
    fi
    [ -z "$FIRST_PEER" ] && FIRST_PEER="peer"
    echo "First Peer: $FIRST_PEER"
}

set_new_peer_name() {
    echo -e "\nEnter a name for the new peer:"
    read -rp "Name: " RAW_NAME
    [ -z "$RAW_NAME" ] && abort "Peer name cannot be empty."
    sanitize_name
    while [ -z "$PEER" ] || grep -q "^# BEGIN $PEER$" "$WG_CONFIG"; do
        if [ -z "$PEER" ]; then
            echo "Invalid name. Use alphanumeric, '-' or '_' only."
        else
            echo "'$PEER' already exists."
        fi
        read -rp "Name: " RAW_NAME
        [ -z "$RAW_NAME" ] && abort "Peer name cannot be empty."
        sanitize_name
    done
    echo "New Peer: $PEER"
}

pick_dns_servers() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nChoose DNS server for the peer:"
        echo "  1) System resolvers"
        echo "  2) Google DNS (default)"
        echo "  3) Cloudflare DNS"
        echo "  4) OpenDNS"
        echo "  5) Quad9"
        echo "  6) AdGuard DNS"
        echo "  7) Custom"
        read -rp "DNS [2]: " dns_opt
        until [[ -z "$dns_opt" || "$dns_opt" =~ ^[1-7]$ ]]; do
            echo "Invalid selection."
            read -rp "DNS [2]: " dns_opt
        done
    else
        dns_opt=2
    fi
    case "$dns_opt" in
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
            echo "Enter primary DNS:"
            read -r dns1
            until valid_ip "$dns1"; do
                echo "Invalid DNS."
                read -r dns1
            done
            echo "Enter secondary DNS (optional):"
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

prep_setup() {
    echo -e "\nInstalling WireGuard..."
}

install_deps() {
    case "$SYS" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables || abort_apt
            ;;
        "centos")
            [ "$SYS_VER" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables || abort_yum
            [ "$SYS_VER" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables || abort_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables || abort "dnf failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables || abort_zypper
            ;;
    esac
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
}

gen_server_conf() {
    local key=$(wg genkey)
    echo "$key" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    echo "$key" > /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    cat > "$WG_CONFIG" << EOF
# ENDPOINT $([ -n "$PUBLIC_ADDR" ] && echo "$PUBLIC_ADDR" || echo "$ADDR")
[Interface]
Address = 10.7.0.1/24$( [ -n "$IPV6_ADDR" ] && echo ", fddd:2c4:2c4:2c4::1/64" )
PrivateKey = $key
ListenPort = $PORT
EOF
    chmod 600 "$WG_CONFIG"
}

config_firewall() {
    local if=$(ip route | grep default | awk '{print $5}' | head -1)
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$PORT"/udp --permanent
        firewall-cmd --zone=trusted --add-source="10.7.0.0/24" --permanent
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE --permanent
        [ -n "$IPV6_ADDR" ] && firewall-cmd --zone=trusted --add-source="fddd:2c4:2c4:2c4::/64" --permanent
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
        iptables -A FORWARD -s 10.7.0.0/24 -j ACCEPT
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o "$if" -j MASQUERADE
        [ -n "$IPV6_ADDR" ] && ip6tables -t nat -A POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -o "$if" -j MASQUERADE
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wg.conf
    [ -n "$IPV6_ADDR" ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wg.conf
    sysctl -p /etc/sysctl.d/99-wg.conf
}

add_new_peer() {
    local peer_name="${1:-$FIRST_PEER}"
    local ip_num=2
    while grep -q "AllowedIPs = 10.7.0.$ip_num/32" "$WG_CONFIG"; do
        ((ip_num++))
    done
    [ "$ip_num" -eq 255 ] && abort "Subnet full. Max 253 peers."
    local priv=$(wg genkey)
    local psk=$(wg genpsk)
    local pub=$(echo "$priv" | wg pubkey)
    cat >> "$WG_CONFIG" << EOF

# BEGIN $peer_name
[Peer]
PublicKey = $pub
PresharedKey = $psk
AllowedIPs = 10.7.0.$ip_num/32$( [ -n "$IPV6_ADDR" ] && echo ", fddd:2c4:2c4:2c4::$ip_num/128" )
# END $peer_name
EOF
    local server_pub=$(cat /etc/wireguard/server.pub)
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    cat > "$out_dir$peer_name.conf" << EOF
[Interface]
Address = 10.7.0.$ip_num/24$( [ -n "$IPV6_ADDR" ] && echo ", fddd:2c4:2c4:2c4::$ip_num/64" )
DNS = $DNS
PrivateKey = $priv

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $([ -n "$PUBLIC_ADDR" ] && echo "$PUBLIC_ADDR" || echo "$ADDR"):$PORT
PersistentKeepalive = 25
EOF
    chmod 600 "$out_dir$peer_name.conf"
    [ -n "$SUDO_USER" ] && chown "$SUDO_USER:$SUDO_USER" "$out_dir$peer_name.conf"
    wg addconf wg0 <(sed -n "/^# BEGIN $peer_name$/,/^# END $peer_name$/p" "$WG_CONFIG")
    echo "Added '$peer_name'. Config at: $out_dir$peer_name.conf"
    qrencode -t UTF8 < "$out_dir$peer_name.conf"
}

activate_service() {
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service || { systemctl status wg-quick@wg0.service; abort "Service failed to start."; }
}

finalize() {
    local out_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && out_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    echo -e "\nFinished! Peer config at: $out_dir$FIRST_PEER.conf"
}

list_all_peers() {
    grep '^# BEGIN' "$WG_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    local count=$(grep -c '^# BEGIN' "$WG_CONFIG")
    echo -e "\nTotal: $count peers"
}

del_peer() {
    echo "Select peer to delete:"
    list_all_peers
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

show_peer_qr() {
    echo "Select peer for QR:"
    list_all_peers
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
    echo "QR for '$peer' displayed."
}

remove_wg() {
    systemctl disable wg-quick@wg0.service
    systemctl stop wg-quick@wg0.service
    rm -rf /etc/wireguard /etc/sysctl.d/99-wg.conf
    iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s "10.7.0.0/24" -j MASQUERADE 2>/dev/null
    [ -n "$IPV6_ADDR" ] && ip6tables -t nat -D POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -j MASQUERADE 2>/dev/null
    case "$SYS" in
        "ubuntu"|"debian") apt-get remove --purge -y wireguard qrencode iptables 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
    esac
    echo "WireGuard uninstalled."
}

# Main Flow
install_wg() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    root_check
    bash_check
    kernel_check
    os_detect
    os_version_check
    container_check

    WG_CONFIG="/etc/wireguard/wg0.conf"
    DNS_DEFAULT="8.8.8.8, 8.8.4.4"

    QUICK=0
    YES=0
    NEW_PEER=0
    LIST_PEERS=0
    RM_PEER=0
    QR_PEER=0
    UNINSTALL=0
    PUBLIC_ADDR=""
    SERVER_ADDR=""
    SERVER_PORT=""
    FIRST_PEER=""
    RAW_NAME=""
    PEER=""
    DNS=""
    DNS1=""
    DNS2=""

    parse_flags "$@"
    validate_flags

    if [ "$NEW_PEER" = 1 ]; then
        banner
        sanitize_name
        if [ "$QUICK" = 0 ]; then
            set_new_peer_name
        else
            [ -z "$PEER" ] && PEER="peer"
        fi
        pick_dns_servers
        add_new_peer "$PEER"
        echo -e "\nQR code above."
        echo "Peer '$PEER' added."
        exit 0
    fi

    if [ "$LIST_PEERS" = 1 ]; then
        banner
        echo -e "\nListing peers..."
        list_all_peers
        exit 0
    fi

    if [ "$RM_PEER" = 1 ]; then
        banner
        sanitize_name
        del_peer
        exit 0
    fi

    if [ "$QR_PEER" = 1 ]; then
        banner
        sanitize_name
        show_peer_qr
        exit 0
    fi

    if [ "$UNINSTALL" = 1 ]; then
        banner
        remove_wg
        exit 0
    fi

    if [ ! -e "$WG_CONFIG" ]; then
        greet
        pick_address
        choose_port
        check_ipv6
        set_first_peer
        pick_dns_servers
        prep_setup
        install_deps
        gen_server_conf
        config_firewall
        add_new_peer "$FIRST_PEER"
        activate_service
        echo -e "\nQR code above."
        finalize
    else
        banner
        echo -e "\nWireGuard is active. Select action:"
        echo "  1) Add peer"
        echo "  2) List peers"
        echo "  3) Remove peer"
        echo "  4) Show QR"
        echo "  5) Uninstall"
        echo "  6) Exit"
        read -rp "Choice: " act
        until [[ "$act" =~ ^[1-6]$ ]]; do
            echo "Invalid."
            read -rp "Choice: " act
        done
        case "$act" in
            1) set_new_peer_name; pick_dns_servers; add_new_peer "$PEER"; echo -e "\nQR code above."; echo "Peer added." ;;
            2) list_all_peers ;;
            3) del_peer ;;
            4) show_peer_qr ;;
            5) remove_wg ;;
            6) exit 0 ;;
        esac
    fi
}

install_wg "$@"
exit 0

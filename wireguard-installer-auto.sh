#!/bin/bash

# WireGuard Quick Setup Tool
# Simplified deployment of WireGuard VPN servers
# Repository: https://github.com/almajnoun/wireguard-installer-auto
# Authored by Almajnoun, refined with Grok 3 (xAI)
# MIT License - 2025

# Error Handling
halt() { echo "Error: $1" >&2; exit 1; }
halt_apt() { halt "Package installation via apt-get failed."; }
halt_yum() { halt "Package installation via yum failed."; }
halt_zypper() { halt "Package installation via zypper failed."; }

# Validation Functions
is_valid_ip() {
    local ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    echo "$1" | grep -Eq "$ip_regex"
}

is_private() {
    local priv_regex='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    echo "$1" | grep -Eq "$priv_regex"
}

is_domain() {
    local fqdn_regex='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    echo "$1" | grep -Eq "$fqdn_regex"
}

require_root() {
    [ "$(id -u)" -ne 0 ] && halt "This script requires root privileges. Use 'sudo bash $0'."
}

check_bash() {
    readlink /proc/$$/exe | grep -q "dash" && halt "Run with 'bash', not 'sh'."
}

verify_kernel() {
    [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && halt "Old kernel detected, incompatible with WireGuard."
}

detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        OS="ubuntu"
        OS_VER=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [ -e /etc/debian_version ]; then
        OS="debian"
        OS_VER=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
        OS="centos"
        OS_VER=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [ -e /etc/fedora-release ]; then
        OS="fedora"
        OS_VER=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [ -e /etc/SUSE-brand ] && grep -q "openSUSE" /etc/SUSE-brand; then
        OS="openSUSE"
        OS_VER=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        halt "Unsupported distribution. Supports Ubuntu, Debian, CentOS, Fedora, and openSUSE."
    fi
}

check_os_version() {
    [ "$OS" = "ubuntu" ] && [ "$OS_VER" -lt 2004 ] && halt "Requires Ubuntu 20.04 or higher."
    [ "$OS" = "debian" ] && [ "$OS_VER" -lt 11 ] && halt "Requires Debian 11 or higher."
    [ "$OS" = "centos" ] && [ "$OS_VER" -lt 8 ] && halt "Requires CentOS 8 or higher."
}

check_container() {
    systemd-detect-virt -cq 2>/dev/null && halt "Containers are not supported."
}

clean_name() {
    NAME_SAFE=$(echo "$NAME_RAW" | sed 's/[^0-9a-zA-Z_-]/_/g' | cut -c-15)
}

# Command-Line Parsing
parse_options() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --quick) QUICK=1; shift ;;
            --add-peer) ADD_PEER=1; NAME_RAW="$2"; shift 2 ;;
            --show-peers) SHOW_PEERS=1; shift ;;
            --delete-peer) DEL_PEER=1; NAME_RAW="$2"; shift 2 ;;
            --get-qr) GET_QR=1; NAME_RAW="$2"; shift 2 ;;
            --remove) REMOVE=1; shift ;;
            --endpoint) ENDPOINT_NAME="$2"; shift 2 ;;
            --port) WG_PORT="$2"; shift 2 ;;
            --peer-name) INITIAL_PEER="$2"; shift 2 ;;
            --dns1) DNS1="$2"; shift 2 ;;
            --dns2) DNS2="$2"; shift 2 ;;
            -y|--yes) YES=1; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) show_help "Unknown option: $1"; exit 1 ;;
        esac
    done
}

validate_options() {
    [ "$QUICK" = 1 ] && [ -e "$CONFIG_FILE" ] && show_help "Cannot use '--quick' with an existing WireGuard setup."
    [ "$(($ADD_PEER + $SHOW_PEERS + $DEL_PEER + $GET_QR))" -gt 1 ] && show_help "Only one action allowed: '--add-peer', '--show-peers', '--delete-peer', or '--get-qr'."
    [ "$REMOVE" = 1 ] && [ "$(($ADD_PEER + $SHOW_PEERS + $DEL_PEER + $GET_QR + $QUICK))" -gt 0 ] && show_help "'--remove' cannot be used with other actions."
    if [ ! -e "$CONFIG_FILE" ]; then
        local pre="WireGuard setup required before you can"
        [ "$ADD_PEER" = 1 ] && halt "$pre add a peer."
        [ "$SHOW_PEERS" = 1 ] && halt "$pre list peers."
        [ "$DEL_PEER" = 1 ] && halt "$pre delete a peer."
        [ "$GET_QR" = 1 ] && halt "$pre show a QR code."
        [ "$REMOVE" = 1 ] && halt "No WireGuard setup to remove."
    fi
    [ "$ADD_PEER" = 1 ] && clean_name && [ -z "$NAME_SAFE" ] && halt "Peer name must use letters, numbers, '-', or '_' only."
    [ "$DEL_PEER" = 1 ] || [ "$GET_QR" = 1 ] && clean_name && { [ -z "$NAME_SAFE" ] || ! grep -q "^# PEER $NAME_SAFE$" "$CONFIG_FILE"; } && halt "Invalid or non-existent peer name."
    [ -n "$ENDPOINT_NAME" ] && ! { is_domain "$ENDPOINT_NAME" || is_valid_ip "$ENDPOINT_NAME"; } && halt "Endpoint must be a valid domain or IPv4."
    [ -n "$WG_PORT" ] && { [[ ! "$WG_PORT" =~ ^[0-9]+$ || "$WG_PORT" -gt 65535 ]]; } && halt "Port must be 1-65535."
    [ -n "$DNS1" ] && ! is_valid_ip "$DNS1" && halt "DNS1 must be a valid IP."
    [ -n "$DNS2" ] && ! is_valid_ip "$DNS2" && halt "DNS2 must be a valid IP."
    [ -z "$DNS1" ] && [ -n "$DNS2" ] && halt "Specify --dns1 with --dns2."
    DNS="$DNS_DEFAULT"
    [ -n "$DNS1" ] && [ -n "$DNS2" ] && DNS="$DNS1, $DNS2"
    [ -n "$DNS1" ] && [ -z "$DNS2" ] && DNS="$DNS1"
}

# Display Functions
print_banner() {
    cat <<'EOF'

WireGuard Quick Setup Tool
https://github.com/almajnoun/wireguard-installer-auto
EOF
}

print_intro() {
    cat <<'EOF'

Welcome to WireGuard Quick Setup!
https://github.com/almajnoun/wireguard-installer-auto

EOF
}

print_author() {
    cat <<'EOF'

Authored by Almajnoun, refined with Grok 3 (xAI)
MIT License - 2025
EOF
}

show_help() {
    [ -n "$1" ] && echo "Error: $1" >&2
    print_banner
    print_author
    cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:
  --add-peer [name]     Add a new VPN peer
  --dns1 [IP]           Primary DNS server (default: 8.8.8.8)
  --dns2 [IP]           Secondary DNS server (optional)
  --show-peers          List all VPN peers
  --delete-peer [name]  Remove a VPN peer
  --get-qr [name]       Display QR code for a peer
  --remove              Uninstall WireGuard and all configs
  -y, --yes             Auto-confirm removals
  -h, --help            Show this help

Setup Options (optional):
  --quick               Quick setup with defaults or custom options
  --endpoint [DNS/IP]   VPN endpoint (domain or IPv4)
  --port [number]       WireGuard port (1-65535, default: 51820)
  --peer-name [name]    Initial VPN peer name (default: peer)
  --dns1 [IP]           Primary DNS for initial peer
  --dns2 [IP]           Secondary DNS for initial peer

Run without options for interactive mode.
EOF
    exit 1
}

welcome_message() {
    if [ "$QUICK" = 0 ]; then
        print_intro
        echo "A few questions are needed to configure your VPN."
        echo "Press Enter for default values."
    else
        print_banner
        local setup_type="default"
        [ -n "$ENDPOINT_NAME" ] || [ -n "$WG_PORT" ] || [ -n "$INITIAL_PEER" ] || [ -n "$DNS1" ] && setup_type="custom"
        echo -e "\nStarting VPN setup with $setup_type options."
    fi
}

domain_notice() {
    cat <<EOF

Note: Ensure '$1' resolves to this server's IPv4 address.
EOF
}

# Core Functions
select_endpoint() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nUse a domain (e.g., vpn.example.com) instead of IP? [y/N]:"
        read -r resp
        case "$resp" in
            [yY]*) 
                echo -e "\nEnter the VPN server's domain:"
                read -r domain
                until is_domain "$domain"; do
                    echo "Invalid domain. Must be a valid FQDN."
                    read -r domain
                done
                ENDPOINT_IP="$domain"
                domain_notice "$ENDPOINT_IP"
                ;;
            *) find_ip ;;
        esac
    else
        [ -n "$ENDPOINT_NAME" ] && ENDPOINT_IP="$ENDPOINT_NAME" || find_ip
    fi
    [ -z "$ENDPOINT_IP" ] && halt "Failed to set endpoint address."
}

find_ip() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        ENDPOINT_IP=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! is_valid_ip "$ENDPOINT_IP"; then
            ENDPOINT_IP=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! is_valid_ip "$ENDPOINT_IP"; then
                [ "$QUICK" = 0 ] && choose_ip || halt "Could not detect server IP."
            fi
        fi
    fi
    is_private "$ENDPOINT_IP" && NAT_IP=$(curl -s http://ipv4.icanhazip.com || halt "Failed to detect public IP for NAT.")
    echo "Server IP: $ENDPOINT_IP"
    [ -n "$NAT_IP" ] && echo "Public IP (NAT): $NAT_IP"
}

choose_ip() {
    echo -e "\nMultiple IPs detected. Choose one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "IP [1]: " ip_choice
    local ip_total=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$ip_choice" || "$ip_choice" =~ ^[0-9]+$ && "$ip_choice" -le "$ip_total" ]]; do
        echo "Invalid choice."
        read -rp "IP [1]: " ip_choice
    done
    [ -z "$ip_choice" ] && ip_choice=1
    ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_choice}p")
}

set_port() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nSelect WireGuard port [51820]:"
        read -r port_val
        PORT="${port_val:-51820}"
        until [[ "$PORT" =~ ^[0-9]+$ && "$PORT" -le 65535 ]]; do
            echo "Invalid port."
            read -r port_val
            PORT="${port_val:-51820}"
        done
    else
        PORT="${WG_PORT:-51820}"
    fi
    echo "Port: $PORT"
}

detect_ipv6() {
    IPV6=""
    if ip -6 addr | grep -q 'inet6 [23]'; then
        IPV6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
    fi
}

name_initial_peer() {
    if [ "$QUICK" = 0 ]; then
        echo -e "\nEnter name for the first peer [peer]:"
        read -r peer_raw
        PEER_NAME="${peer_raw:-peer}"
        NAME_RAW="$PEER_NAME"
        clean_name
        PEER_NAME="$NAME_SAFE"
    fi
    [ -z "$PEER_NAME" ] && PEER_NAME="peer"
    echo "First Peer: $PEER_NAME"
}

prep_install() {
    [ "$QUICK" = 0 ] && echo -e "\nStarting WireGuard installation..."
}

install_tools() {
    echo "Installing required tools..."
    case "$OS" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables || halt_apt
            ;;
        "centos")
            [ "$OS_VER" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables || halt_yum
            [ "$OS_VER" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables || halt_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables || halt "dnf install failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables || halt_zypper
            ;;
    esac
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
}

build_server_config() {
    local priv_key=$(wg genkey)
    echo "$priv_key" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    echo "$priv_key" > /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    [ -z "$ENDPOINT_IP" ] && halt "Endpoint IP missing for server config."
    cat > "$CONFIG_FILE" << EOF
# ENDPOINT $ENDPOINT_IP
[Interface]
Address = 10.7.0.1/24$( [ -n "$IPV6" ] && echo ", fddd:2c4:2c4:2c4::1/64" )
PrivateKey = $priv_key
ListenPort = $PORT
EOF
    chmod 600 "$CONFIG_FILE"
}

setup_firewall() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$PORT"/udp --permanent
        firewall-cmd --zone=trusted --add-source="10.7.0.0/24" --permanent
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE --permanent
        [ -n "$IPV6" ] && firewall-cmd --zone=trusted --add-source="fddd:2c4:2c4:2c4::/64" --permanent
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
        iptables -A FORWARD -s 10.7.0.0/24 -j ACCEPT
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o "$net_if" -j MASQUERADE
        [ -n "$IPV6" ] && ip6tables -t nat -A POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -o "$net_if" -j MASQUERADE
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wg.conf
    [ -n "$IPV6" ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wg.conf
    sysctl -p /etc/sysctl.d/99-wg.conf
}

add_peer() {
    local peer_name="${1:-$PEER_NAME}"
    local octet=2
    while grep -q "AllowedIPs = 10.7.0.$octet/32" "$CONFIG_FILE"; do
        ((octet++))
    done
    [ "$octet" -eq 255 ] && halt "Subnet full. Max 253 peers."
    local peer_key=$(wg genkey)
    local peer_psk=$(wg genpsk)
    local peer_pub=$(echo "$peer_key" | wg pubkey)
    cat >> "$CONFIG_FILE" << EOF

# PEER $peer_name
[Peer]
PublicKey = $peer_pub
PresharedKey = $peer_psk
AllowedIPs = 10.7.0.$octet/32$( [ -n "$IPV6" ] && echo ", fddd:2c4:2c4:2c4::$octet/128" )
# END_PEER $peer_name
EOF
    local server_pub=$(cat /etc/wireguard/server.pub)
    local export_dir=~
    if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
        user_dir=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        [ -d "$user_dir" ] && [ "$user_dir" != "/" ] && export_dir="$user_dir/"
    fi
    cat > "$export_dir$peer_name.conf" << EOF
[Interface]
Address = 10.7.0.$octet/24$( [ -n "$IPV6" ] && echo ", fddd:2c4:2c4:2c4::$octet/64" )
DNS = $DNS
PrivateKey = $peer_key

[Peer]
PublicKey = $server_pub
PresharedKey = $peer_psk
AllowedIPs = 0.0.0.0/0$( [ -n "$IPV6" ] && echo ", ::/0" )
Endpoint = $ENDPOINT_IP:$PORT
PersistentKeepalive = 25
EOF
    chmod 600 "$export_dir$peer_name.conf"
    [ -n "$SUDO_USER" ] && chown "$SUDO_USER:$SUDO_USER" "$export_dir$peer_name.conf"
    wg addconf wg0 <(sed -n "/^# PEER $peer_name$/,/^# END_PEER $peer_name$/p" "$CONFIG_FILE")
    echo "Added peer '$peer_name'. Config at: $export_dir$peer_name.conf"
    qrencode -t UTF8 < "$export_dir$peer_name.conf"
}

start_service() {
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service || { systemctl status wg-quick@wg0.service; halt "Failed to start service."; }
}

complete_install() {
    local export_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && export_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    echo -e "\nSetup complete! Peer config saved to: $export_dir$PEER_NAME.conf"
}

list_peers() {
    grep '^# PEER' "$CONFIG_FILE" | cut -d ' ' -f 3 | nl -s ') '
    local peer_count=$(grep -c '^# PEER' "$CONFIG_FILE")
    echo -e "\nTotal peers: $peer_count"
}

remove_peer() {
    echo "Select peer to remove:"
    list_peers
    read -rp "Peer number: " peer_num
    local peer_total=$(grep -c '^# PEER' "$CONFIG_FILE")
    until [[ "$peer_num" =~ ^[0-9]+$ && "$peer_num" -le "$peer_total" ]]; do
        echo "Invalid selection."
        read -rp "Peer number: " peer_num
    done
    local peer=$(grep '^# PEER' "$CONFIG_FILE" | cut -d ' ' -f 3 | sed -n "${peer_num}p")
    wg set wg0 peer "$(sed -n "/^# PEER $peer$/,\$p" "$CONFIG_FILE" | grep -m 1 PublicKey | cut -d ' ' -f 3)" remove
    sed -i "/^# PEER $peer$/,/^# END_PEER $peer$/d" "$CONFIG_FILE"
    local export_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && export_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    rm -f "$export_dir$peer.conf"
    echo "Peer '$peer' removed."
}

show_qr() {
    echo "Select peer for QR code:"
    list_peers
    read -rp "Peer number: " peer_num
    local peer_total=$(grep -c '^# PEER' "$CONFIG_FILE")
    until [[ "$peer_num" =~ ^[0-9]+$ && "$peer_num" -le "$peer_total" ]]; do
        echo "Invalid selection."
        read -rp "Peer number: " peer_num
    done
    local peer=$(grep '^# PEER' "$CONFIG_FILE" | cut -d ' ' -f 3 | sed -n "${peer_num}p")
    local export_dir=~
    [ -n "$SUDO_USER" ] && [ -d "$(getent passwd "$SUDO_USER" | cut -d: -f6)" ] && export_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)/"
    [ -f "$export_dir$peer.conf" ] || halt "Config file for '$peer' missing."
    qrencode -t UTF8 < "$export_dir$peer.conf"
    echo "QR code for '$peer' displayed."
}

uninstall_wg() {
    systemctl disable wg-quick@wg0.service
    systemctl stop wg-quick@wg0.service
    rm -rf /etc/wireguard /etc/sysctl.d/99-wg.conf
    iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s "10.7.0.0/24" -j MASQUERADE 2>/dev/null
    [ -n "$IPV6" ] && ip6tables -t nat -D POSTROUTING -s "fddd:2c4:2c4:2c4::/64" -j MASQUERADE 2>/dev/null
    case "$OS" in
        "ubuntu"|"debian") apt-get remove --purge -y wireguard qrencode iptables 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
    esac
    echo "WireGuard removed."
}

# Main Execution
setup_wg() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    require_root
    check_bash
    verify_kernel
    detect_os
    check_os_version
    check_container

    CONFIG_FILE="/etc/wireguard/wg0.conf"
    DNS_DEFAULT="8.8.8.8, 8.8.4.4"

    QUICK=0
    YES=0
    ADD_PEER=0
    SHOW_PEERS=0
    DEL_PEER=0
    GET_QR=0
    REMOVE=0
    NAT_IP=""
    ENDPOINT_NAME=""
    WG_PORT=""
    INITIAL_PEER=""
    NAME_RAW=""
    NAME_SAFE=""
    DNS=""
    DNS1=""
    DNS2=""

    parse_options "$@"
    validate_options

    if [ "$ADD_PEER" = 1 ]; then
        print_banner
        clean_name
        select_endpoint
        set_port
        detect_ipv6
        name_initial_peer
        pick_dns_servers
        add_peer "$NAME_SAFE"
        echo -e "\nQR code shown above."
        echo "Peer '$NAME_SAFE' added. Config at: ~/$NAME_SAFE.conf"
        exit 0
    fi

    if [ "$SHOW_PEERS" = 1 ]; then
        print_banner
        echo -e "\nListing peers..."
        list_peers
        exit 0
    fi

    if [ "$DEL_PEER" = 1 ]; then
        print_banner
        clean_name
        remove_peer
        exit 0
    fi

    if [ "$GET_QR" = 1 ]; then
        print_banner
        clean_name
        show_qr
        exit 0
    fi

    if [ "$REMOVE" = 1 ]; then
        print_banner
        uninstall_wg
        exit 0
    fi

    if [ ! -e "$CONFIG_FILE" ]; then
        welcome_message
        select_endpoint
        set_port
        detect_ipv6
        name_initial_peer
        pick_dns_servers
        prep_install
        install_tools
        build_server_config
        setup_firewall
        add_peer "$PEER_NAME"
        start_service
        echo -e "\nQR code shown above."
        complete_install
    else
        print_banner
        echo -e "\nWireGuard is installed. Choose an option:"
        echo "  1) Add new peer"
        echo "  2) List peers"
        echo "  3) Delete peer"
        echo "  4) Show QR code"
        echo "  5) Remove WireGuard"
        echo "  6) Exit"
        read -rp "Option: " opt
        until [[ "$opt" =~ ^[1-6]$ ]]; do
            echo "Invalid selection."
            read -rp "Option: " opt
        done
        case "$opt" in
            1) pick_dns_servers; add_peer; echo -e "\nQR code shown above."; echo "Peer added. Config at: ~/$NAME_SAFE.conf" ;;
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

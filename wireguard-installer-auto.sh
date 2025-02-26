#!/bin/bash

# WireGuard Auto Deployer Script
# Enhanced VPN setup tool with secure configuration and DNS flexibility
# GitHub: https://github.com/almajnoun/wireguard-installer-auto
# Created by Almajnoun with contributions from Grok 3 (xAI)
# Licensed under MIT - 2025

# Set strict permissions
umask 077

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Error handling
fail() { echo -e "${RED}Error: $1${NC}" >&2; exit 1; }
fail_apt() { fail "Failed to install packages with apt-get."; }
fail_yum() { fail "Failed to install packages with yum."; }
fail_zypper() { fail "Failed to install packages with zypper."; }

# Utility functions
is_valid_ip() {
    local ip_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    echo "$1" | grep -Eq "$ip_regex"
}

is_private_ip() {
    local private_regex='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    echo "$1" | grep -Eq "$private_regex"
}

is_valid_domain() {
    local domain_regex='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    echo "$1" | grep -Eq "$domain_regex"
}

check_privileges() {
    [ "$(id -u)" -ne 0 ] && fail "Run this script as root using 'sudo'."
}

verify_shell() {
    readlink /proc/$$/exe | grep -q "dash" && fail "Use 'bash' to run this script, not 'sh'."
}

validate_kernel() {
    [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && fail "Old kernel detected. Update your system."
}

detect_system() {
    if grep -qs "ubuntu" /etc/os-release; then
        SYS_TYPE="ubuntu"
        SYS_VER=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [ -e /etc/debian_version ]; then
        SYS_TYPE="debian"
        SYS_VER=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
        SYS_TYPE="centos"
        SYS_VER=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [ -e /etc/fedora-release ]; then
        SYS_TYPE="fedora"
        SYS_VER=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [ -e /etc/SUSE-brand ] && grep -q "openSUSE" /etc/SUSE-brand; then
        SYS_TYPE="openSUSE"
        SYS_VER=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        fail "Unsupported system. Compatible with Ubuntu, Debian, CentOS, Fedora, and openSUSE."
    fi
}

verify_system_version() {
    [ "$SYS_TYPE" = "ubuntu" ] && [ "$SYS_VER" -lt 2004 ] && fail "Ubuntu 20.04+ required."
    [ "$SYS_TYPE" = "debian" ] && [ "$SYS_VER" -lt 11 ] && fail "Debian 11+ required."
    [ "$SYS_TYPE" = "centos" ] && [ "$SYS_VER" -lt 8 ] && fail "CentOS 8+ required."
}

check_container_env() {
    systemd-detect-virt -cq 2>/dev/null && fail "Running in a container is not supported."
}

sanitize_name() {
    SAFE_NAME=$(echo "$RAW_NAME" | sed 's/[^0-9a-zA-Z_-]/_/g' | cut -c-15)
}

# Configuration defaults
VPN_CONFIG="/etc/wireguard/wg0.conf"
USER_DIR="$HOME/wireguard-users"
VPN_IPV4="10.7.0"
VPN_IPV6="fddd:2c4:2c4:2c4::"
DNS_DEFAULT="8.8.8.8, 8.8.4.4"
KEEPALIVE_DEFAULT=25
ENDPOINT_IP=""
ENDPOINT_NAME=""
PORT_DEFAULT=51820
FIRST_USER="user"
ENABLE_IPV6=1

# Parse command-line arguments
parse_options() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --quick) AUTO_SETUP=1; shift ;;
            --new-user) ADD_USER=1; RAW_NAME="$2"; shift 2 ;;
            --show-users) LIST_USERS=1; shift ;;
            --delete-user) DEL_USER=1; RAW_NAME="$2"; shift 2 ;;
            --get-qr) SHOW_QR=1; RAW_NAME="$2"; shift 2 ;;
            --remove) UNINSTALL=1; shift ;;
            --endpoint) ENDPOINT_NAME="$2"; shift 2 ;;
            --port-num) PORT_NUM="$2"; shift 2 ;;
            --user) FIRST_USER="$2"; shift 2 ;;
            --dns-primary) DNS_PRI="$2"; shift 2 ;;
            --dns-secondary) DNS_SEC="$2"; shift 2 ;;
            -y|--confirm) CONFIRM_YES=1; shift ;;
            -h|--info) display_help; exit 0 ;;
            *) display_help "Invalid option: $1"; exit 1 ;;
        esac
    done
}

validate_options() {
    [ "$AUTO_SETUP" = 1 ] && [ -e "$VPN_CONFIG" ] && fail "Cannot use '--quick' when WireGuard is already installed."
    [ "$(($ADD_USER + $LIST_USERS + $DEL_USER + $SHOW_QR))" -gt 1 ] && fail "Use only one of '--new-user', '--show-users', '--delete-user', or '--get-qr'."
    [ "$UNINSTALL" = 1 ] && [ "$(($ADD_USER + $LIST_USERS + $DEL_USER + $SHOW_QR + $AUTO_SETUP))" -gt 0 ] && fail "'--remove' cannot be combined with other flags."
    if [ ! -e "$VPN_CONFIG" ]; then
        local msg="WireGuard must be installed first to"
        [ "$ADD_USER" = 1 ] && fail "$msg add a user."
        [ "$LIST_USERS" = 1 ] && fail "$msg list users."
        [ "$DEL_USER" = 1 ] && fail "$msg delete a user."
        [ "$SHOW_QR" = 1 ] && fail "$msg show a QR code."
        [ "$UNINSTALL" = 1 ] && fail "Nothing to uninstall. WireGuard is not set up."
    fi
    [ "$ADD_USER" = 1 ] && sanitize_name && [ -z "$SAFE_NAME" ] && fail "User name must be alphanumeric with '-' or '_' only."
    [ "$DEL_USER" = 1 ] || [ "$SHOW_QR" = 1 ] && sanitize_name && { [ -z "$SAFE_NAME" ] || ! grep -q "^# BEGIN_PEER $SAFE_NAME$" "$VPN_CONFIG"; } && fail "Invalid or non-existent user name."
    [ -n "$ENDPOINT_NAME" ] && ! { is_valid_domain "$ENDPOINT_NAME" || is_valid_ip "$ENDPOINT_NAME"; } && fail "Endpoint must be a valid domain or IPv4 address."
    [ -n "$PORT_NUM" ] && { [[ ! "$PORT_NUM" =~ ^[0-9]+$ || "$PORT_NUM" -gt 65535 ]]; } && fail "Port must be a number between 1 and 65535."
    [ -n "$DNS_PRI" ] && ! is_valid_ip "$DNS_PRI" && fail "Primary DNS must be a valid IP."
    [ -n "$DNS_SEC" ] && ! is_valid_ip "$DNS_SEC" && fail "Secondary DNS must be a valid IP."
    [ -z "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && fail "Specify --dns-primary with --dns-secondary."
    DNS_SET="$DNS_DEFAULT"
    [ -n "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && DNS_SET="$DNS_PRI, $DNS_SEC"
    [ -n "$DNS_PRI" ] && [ -z "$DNS_SEC" ] && DNS_SET="$DNS_PRI"
}

display_help() {
    [ -n "$1" ] && echo -e "${RED}Error: $1${NC}" >&2
    cat <<EOF
WireGuard Auto Deployer
https://github.com/almajnoun/wireguard-installer-auto

Usage: bash $0 [flags]

Flags:
  --new-user [name]         Add a new VPN user
  --dns-primary [IP]        Primary DNS server (default: 8.8.8.8)
  --dns-secondary [IP]      Secondary DNS server (optional)
  --show-users              List all VPN users
  --delete-user [name]      Remove a VPN user
  --get-qr [name]           Show QR code for a VPN user
  --remove                  Uninstall WireGuard and configurations
  -y, --confirm             Auto-confirm removal prompts
  -h, --info                Show this help

Setup Flags:
  --quick                   Quick setup with defaults or custom options
  --endpoint [DNS/IP]       VPN endpoint (domain or IPv4)
  --port-num [number]       WireGuard port (1-65535, default: 51820)
  --user [name]             Initial VPN user name (default: user)
  --dns-primary [IP]        Primary DNS for initial user
  --dns-secondary [IP]      Secondary DNS for initial user
EOF
    exit 1
}

welcome_message() {
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "${GREEN}Welcome to WireGuard Auto Deployer!${NC}"
        echo "Answer a few questions to begin setup."
        echo "Press Enter to accept defaults."
    else
        echo -e "${BLUE}Starting VPN deployment with $([ -n "$ENDPOINT_NAME" ] || [ -n "$PORT_NUM" ] || [ -n "$FIRST_USER" ] || [ -n "$DNS_PRI" ] && echo "custom" || echo "default") settings.${NC}"
    fi
}

fetch_endpoint() {
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nUse a domain name (e.g., vpn.example.com) instead of IP? [y/N]: "
        read -r choice
        case "$choice" in
            [yY]*) 
                echo -e "\nEnter the domain name for this VPN:"
                read -r domain
                until is_valid_domain "$domain"; do
                    echo "Invalid domain. Must be a valid FQDN."
                    read -r domain
                done
                ENDPOINT_IP="$domain"
                echo -e "${YELLOW}Ensure '$domain' resolves to this server's IP.${NC}"
                ;;
            *)
                detect_ip_address
                ;;
        esac
    else
        [ -n "$ENDPOINT_NAME" ] && ENDPOINT_IP="$ENDPOINT_NAME" || detect_ip_address
    fi
}

detect_ip_address() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        ENDPOINT_IP=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! is_valid_ip "$ENDPOINT_IP"; then
            ENDPOINT_IP=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! is_valid_ip "$ENDPOINT_IP"; then
                [ "$AUTO_SETUP" = 0 ] && select_ip_manually || fail "Could not detect public IP in auto mode."
            fi
        fi
    fi
    is_private_ip "$ENDPOINT_IP" && PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com || fail "Cannot detect public IP for NAT.")
}

select_ip_manually() {
    echo -e "\nMultiple IPs detected. Choose one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "Select IP [1]: " ip_choice
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$ip_choice" || "$ip_choice" =~ ^[0-9]+$ && "$ip_choice" -le "$ip_count" ]]; do
        echo "Invalid choice."
        read -rp "Select IP [1]: " ip_choice
    done
    [ -z "$ip_choice" ] && ip_choice=1
    ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_choice}p")
}

set_port() {
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nEnter the port for WireGuard [51820]:"
        read -r port_input
        PORT_NUM="${port_input:-51820}"
        until [[ "$PORT_NUM" =~ ^[0-9]+$ && "$PORT_NUM" -le 65535 ]]; do
            echo "Invalid port."
            read -r port_input
            PORT_NUM="${port_input:-51820}"
        done
    else
        PORT_NUM="${PORT_NUM:-51820}"
    fi
}

choose_dns() {
    if [ "$AUTO_SETUP" = 0 ] || [ "$ADD_USER" = 1 ]; then
        echo -e "\nSelect DNS for the VPN user:"
        echo "  1) System DNS"
        echo "  2) Google (8.8.8.8, 8.8.4.4)"
        echo "  3) Cloudflare (1.1.1.1, 1.0.0.1)"
        echo "  4) OpenDNS (208.67.222.222, 208.67.220.220)"
        echo "  5) Quad9 (9.9.9.9, 149.112.112.112)"
        echo "  6) AdGuard (94.140.14.14, 94.140.15.15)"
        echo "  7) NextDNS (45.90.28.0, 45.90.30.0)"
        echo "  8) CleanBrowsing (185.228.168.168, 185.228.169.168)"
        echo "  9) Custom DNS"
        read -rp "Choice [2]: " dns_opt
        until [[ -z "$dns_opt" || "$dns_opt" =~ ^[1-9]$ ]]; do
            echo "Invalid selection."
            read -rp "Choice [2]: " dns_opt
        done
    else
        dns_opt=2
    fi
    case "$dns_opt" in
        1)
            DNS_SET=$(grep -v '^#\|^;' /etc/resolv.conf | grep '^nameserver' | grep -v '127.0.0.53' | awk '{print $2}' | paste -sd ', ')
            ;;
        2|"") DNS_SET="8.8.8.8, 8.8.4.4" ;;
        3) DNS_SET="1.1.1.1, 1.0.0.1" ;;
        4) DNS_SET="208.67.222.222, 208.67.220.220" ;;
        5) DNS_SET="9.9.9.9, 149.112.112.112" ;;
        6) DNS_SET="94.140.14.14, 94.140.15.15" ;;
        7) DNS_SET="45.90.28.0, 45.90.30.0" ;;
        8) DNS_SET="185.228.168.168, 185.228.169.168" ;;
        9)
            echo "Enter primary DNS:"
            read -r custom_pri
            until is_valid_ip "$custom_pri"; do
                echo "Invalid IP."
                read -r custom_pri
            done
            echo "Enter secondary DNS (or press Enter to skip):"
            read -r custom_sec
            [ -n "$custom_sec" ] && until is_valid_ip "$custom_sec"; do
                echo "Invalid IP."
                read -r custom_sec
            done
            DNS_SET="$custom_pri"
            [ -n "$custom_sec" ] && DNS_SET="$custom_pri, $custom_sec"
            ;;
    esac
}

set_initial_user() {
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nName for the first VPN user [user]:"
        read -r user_input
        FIRST_USER="${user_input:-user}"
        sanitize_name "RAW_NAME=$FIRST_USER"
        FIRST_USER="$SAFE_NAME"
    fi
    [ -z "$FIRST_USER" ] && FIRST_USER="user"
}

prepare_install() {
    [ "$AUTO_SETUP" = 0 ] && echo -e "\n${BLUE}Ready to deploy WireGuard VPN.${NC}"
}

setup_packages() {
    echo -e "${YELLOW}Installing required packages...${NC}"
    case "$SYS_TYPE" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables || fail_apt
            ;;
        "centos")
            [ "$SYS_VER" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables || fail_yum
            [ "$SYS_VER" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables || fail_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables || fail "dnf install failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables || fail_zypper
            ;;
    esac
    mkdir -p /etc/wireguard "$USER_DIR"
    chmod 700 /etc/wireguard "$USER_DIR"
}

configure_vpn() {
    TEMP_KEY=$(mktemp)
    wg genkey > "$TEMP_KEY"
    SERVER_KEY=$(cat "$TEMP_KEY")
    echo "$SERVER_KEY" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    mv "$TEMP_KEY" /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    cat > "$VPN_CONFIG" << EOF
# Endpoint: $ENDPOINT_IP
[Interface]
Address = ${VPN_IPV4}.1/24$( [ "$ENABLE_IPV6" = 1 ] && echo ", ${VPN_IPV6}1/64" )
PrivateKey = $SERVER_KEY
ListenPort = $PORT_NUM
EOF
    chmod 600 "$VPN_CONFIG"
}

setup_firewall() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$PORT_NUM"/udp --permanent
        firewall-cmd --zone=trusted --add-source="${VPN_IPV4}.0/24" --permanent
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "${VPN_IPV4}.0/24" ! -d "${VPN_IPV4}.0/24" -j MASQUERADE --permanent
        [ "$ENABLE_IPV6" = 1 ] && firewall-cmd --zone=trusted --add-source="${VPN_IPV6}/64" --permanent
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$PORT_NUM" -j ACCEPT
        iptables -A FORWARD -s "${VPN_IPV4}.0/24" -j ACCEPT
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s "${VPN_IPV4}.0/24" -o "$net_if" -j MASQUERADE
        [ "$ENABLE_IPV6" = 1 ] && ip6tables -t nat -A POSTROUTING -s "${VPN_IPV6}/64" -o "$net_if" -j MASQUERADE
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
    [ "$ENABLE_IPV6" = 1 ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vpn.conf
    sysctl -p /etc/sysctl.d/99-vpn.conf
}

add_vpn_user() {
    local user_name="${1:-$FIRST_USER}"
    local ip_octet=2
    while grep -q "AllowedIPs = ${VPN_IPV4}.$ip_octet/32" "$VPN_CONFIG"; do
        ((ip_octet++))
    done
    [ "$ip_octet" -eq 255 ] && fail "VPN subnet full. Max 253 users."
    TEMP_KEY=$(mktemp)
    TEMP_PSK=$(mktemp)
    wg genkey > "$TEMP_KEY"
    wg genpsk > "$TEMP_PSK"
    USER_KEY=$(cat "$TEMP_KEY")
    USER_PSK=$(cat "$TEMP_PSK")
    echo "$USER_KEY" | wg pubkey > "$USER_DIR/$user_name.pub"
    USER_PUB=$(cat "$USER_DIR/$user_name.pub")
    mv "$TEMP_KEY" "$USER_DIR/$user_name.key"
    mv "$TEMP_PSK" "$USER_DIR/$user_name.psk"
    chmod 600 "$USER_DIR/$user_name.key" "$USER_DIR/$user_name.pub" "$USER_DIR/$user_name.psk"
    cat >> "$VPN_CONFIG" << EOF

# BEGIN_PEER $user_name
[Peer]
PublicKey = $USER_PUB
PresharedKey = $USER_PSK
AllowedIPs = ${VPN_IPV4}.$ip_octet/32$( [ "$ENABLE_IPV6" = 1 ] && echo ", ${VPN_IPV6}$ip_octet/128" )
# END_PEER $user_name
EOF
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    cat > "$USER_DIR/$user_name.conf" << EOF
[Interface]
Address = ${VPN_IPV4}.$ip_octet/24$( [ "$ENABLE_IPV6" = 1 ] && echo ", ${VPN_IPV6}$ip_octet/64" )
DNS = $DNS_SET
PrivateKey = $USER_KEY

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $USER_PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $ENDPOINT_IP:$PORT_NUM
PersistentKeepalive = $KEEPALIVE_DEFAULT
EOF
    chmod 600 "$USER_DIR/$user_name.conf"
    systemctl restart wg-quick@wg0
    qrencode -t UTF8 < "$USER_DIR/$user_name.conf"
    echo -e "${GREEN}User '$user_name' added. Config saved to: $USER_DIR/$user_name.conf${NC}"
}

start_service() {
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service || fail "Failed to start VPN service."
}

complete_setup() {
    echo -e "${GREEN}VPN setup completed successfully!${NC}"
    echo "User config saved to: $USER_DIR/$FIRST_USER.conf"
}

list_users() {
    grep '^# BEGIN_PEER' "$VPN_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    local user_count=$(grep -c '^# BEGIN_PEER' "$VPN_CONFIG")
    echo -e "\nTotal users: $user_count"
}

remove_user() {
    echo "Select user to remove:"
    list_users
    read -rp "User number: " user_num
    local user_count=$(grep -c '^# BEGIN_PEER' "$VPN_CONFIG")
    until [[ "$user_num" =~ ^[0-9]+$ && "$user_num" -le "$user_count" ]]; do
        echo "Invalid selection."
        read -rp "User number: " user_num
    done
    SAFE_NAME=$(grep '^# BEGIN_PEER' "$VPN_CONFIG" | cut -d ' ' -f 3 | sed -n "${user_num}p")
    sed -i "/^# BEGIN_PEER $SAFE_NAME$/,/^# END_PEER $SAFE_NAME$/d" "$VPN_CONFIG"
    rm -f "$USER_DIR/$SAFE_NAME.conf" "$USER_DIR/$SAFE_NAME.key" "$USER_DIR/$SAFE_NAME.pub" "$USER_DIR/$SAFE_NAME.psk"
    systemctl restart wg-quick@wg0
    echo -e "${GREEN}User '$SAFE_NAME' removed.${NC}"
}

show_qr_code() {
    echo "Select user for QR code:"
    list_users
    read -rp "User number: " user_num
    local user_count=$(grep -c '^# BEGIN_PEER' "$VPN_CONFIG")
    until [[ "$user_num" =~ ^[0-9]+$ && "$user_num" -le "$user_count" ]]; do
        echo "Invalid selection."
        read -rp "User number: " user_num
    done
    SAFE_NAME=$(grep '^# BEGIN_PEER' "$VPN_CONFIG" | cut -d ' ' -f 3 | sed -n "${user_num}p")
    [ -f "$USER_DIR/$SAFE_NAME.conf" ] || fail "Config file for '$SAFE_NAME' not found."
    qrencode -t UTF8 < "$USER_DIR/$SAFE_NAME.conf"
    echo -e "${BLUE}QR code for '$SAFE_NAME' displayed above.${NC}"
}

uninstall_vpn() {
    systemctl stop wg-quick@wg0
    systemctl disable wg-quick@wg0
    rm -rf /etc/wireguard "$USER_DIR" /etc/sysctl.d/99-vpn.conf
    iptables -D INPUT -p udp --dport "$PORT_NUM" -j ACCEPT
    iptables -t nat -D POSTROUTING -s "${VPN_IPV4}.0/24" -j MASQUERADE
    [ "$ENABLE_IPV6" = 1 ] && ip6tables -t nat -D POSTROUTING -s "${VPN_IPV6}/64" -j MASQUERADE
    case "$SYS_TYPE" in
        "ubuntu"|"debian") apt-get remove -y wireguard qrencode iptables ;;
        "centos") yum remove -y wireguard-tools qrencode iptables ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables ;;
    esac
    echo -e "${GREEN}WireGuard uninstalled.${NC}"
}

main() {
    parse_options "$@"
    validate_options
    check_privileges
    verify_shell
    validate_kernel
    detect_system
    verify_system_version
    check_container_env

    if [ "$ADD_USER" = 1 ]; then
        sanitize_name
        choose_dns
        add_vpn_user "$SAFE_NAME"
    elif [ "$LIST_USERS" = 1 ]; then
        list_users
    elif [ "$DEL_USER" = 1 ]; then
        remove_user
    elif [ "$SHOW_QR" = 1 ]; then
        show_qr_code
    elif [ "$UNINSTALL" = 1 ]; then
        uninstall_vpn
    elif [ "$AUTO_SETUP" = 1 ]; then
        welcome_message
        fetch_endpoint
        set_port
        choose_dns
        setup_packages
        configure_vpn
        setup_firewall
        add_vpn_user "$FIRST_USER"
        start_service
        complete_setup
    else
        if [ -e "$VPN_CONFIG" ]; then
            echo -e "\n${BLUE}WireGuard is already installed. Choose an action:${NC}"
            echo "  1) Add new user"
            echo "  2) List users"
            echo "  3) Remove user"
            echo "  4) Show QR code"
            echo "  5) Uninstall"
            echo "  6) Exit"
            read -rp "Option: " action
            case "$action" in
                1) choose_dns; add_vpn_user ;;
                2) list_users ;;
                3) remove_user ;;
                4) show_qr_code ;;
                5) uninstall_vpn ;;
                6) exit 0 ;;
                *) fail "Invalid option." ;;
            esac
        else
            welcome_message
            fetch_endpoint
            set_port
            set_initial_user
            choose_dns
            prepare_install
            setup_packages
            configure_vpn
            setup_firewall
            add_vpn_user "$FIRST_USER"
            start_service
            complete_setup
        fi
    fi
}

main "$@"
exit 0

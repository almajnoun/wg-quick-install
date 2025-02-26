#!/bin/bash

# Script for automating WireGuard VPN deployment
# Designed for easy setup and user management on Linux systems
# Repository: https://github.com/almajnoun/wireguard-installer-auto
# Developed by Almajnoun, enhanced with Grok 3 (xAI)
# MIT License - 2025

# Ensure secure file creation
umask 077

# Define terminal colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions to handle errors and exits
fail() { echo -e "${RED}Error: $1${NC}" >&2; exit 1; }
fail_apt() { fail "Package installation via apt-get encountered an issue."; }
fail_yum() { fail "Unable to install packages using yum."; }
fail_zypper() { fail "Zypper package installation failed."; }

# Helper functions for validation
is_valid_ip() {
    local ip_check='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    echo "$1" | grep -Eq "$ip_check"
}

is_private_ip() {
    local priv_ip='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    echo "$1" | grep -Eq "$priv_ip"
}

is_valid_domain() {
    local domain_check='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    echo "$1" | grep -Eq "$domain_check"
}

check_privileges() {
    # Verify the script runs with root privileges
    [ "$(id -u)" -ne 0 ] && fail "This script requires root access. Use 'sudo'."
}

verify_shell() {
    # Ensure the script is executed with bash
    readlink /proc/$$/exe | grep -q "dash" && fail "Execute with 'bash', not 'sh'."
}

validate_kernel() {
    # Check for outdated kernel versions
    [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && fail "Your kernel is too old for WireGuard."
}

detect_system() {
    # Identify the operating system and version
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
        fail "Your system is not supported. Use Ubuntu, Debian, CentOS, Fedora, or openSUSE."
    fi
}

verify_system_version() {
    # Validate minimum OS version requirements
    [ "$SYS_TYPE" = "ubuntu" ] && [ "$SYS_VER" -lt 2004 ] && fail "Requires Ubuntu 20.04 or newer."
    [ "$SYS_TYPE" = "debian" ] && [ "$SYS_VER" -lt 11 ] && fail "Requires Debian 11 or newer."
    [ "$SYS_TYPE" = "centos" ] && [ "$SYS_VER" -lt 8 ] && fail "Requires CentOS 8 or newer."
}

check_container_env() {
    # Detect if running inside a container
    systemd-detect-virt -cq 2>/dev/null && fail "Containers are not supported for this setup."
}

sanitize_name() {
    # Clean input name for safe usage
    SAFE_NAME=$(echo "$RAW_NAME" | sed 's/[^0-9a-zA-Z_-]/_/g' | cut -c-15)
}

# Default settings with initialized variables
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
AUTO_SETUP=0
ADD_USER=0
LIST_USERS=0
DEL_USER=0
SHOW_QR=0
UNINSTALL=0
CONFIRM_YES=0
ENABLE_IPV6=0  # Default to disabled, will prompt user

# Parse command-line flags
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
            *) display_help "Unrecognized flag: $1"; exit 1 ;;
        esac
    done
}

validate_options() {
    # Validate command-line options
    [ "$AUTO_SETUP" = 1 ] && [ -e "$VPN_CONFIG" ] && fail "Cannot use '--quick' with existing WireGuard setup."
    [ "$(($ADD_USER + $LIST_USERS + $DEL_USER + $SHOW_QR))" -gt 1 ] && fail "Only one action flag is allowed at a time."
    [ "$UNINSTALL" = 1 ] && [ "$(($ADD_USER + $LIST_USERS + $DEL_USER + $SHOW_QR + $AUTO_SETUP))" -gt 0 ] && fail "'--remove' cannot be used with other actions."
    if [ ! -e "$VPN_CONFIG" ]; then
        local pre_msg="WireGuard setup is required before you can"
        [ "$ADD_USER" = 1 ] && fail "$pre_msg create a new user."
        [ "$LIST_USERS" = 1 ] && fail "$pre_msg display user list."
        [ "$DEL_USER" = 1 ] && fail "$pre_msg remove a user."
        [ "$SHOW_QR" = 1 ] && fail "$pre_msg generate a QR code."
        [ "$UNINSTALL" = 1 ] && fail "No WireGuard installation to remove."
    fi
    [ "$ADD_USER" = 1 ] && sanitize_name && [ -z "$SAFE_NAME" ] && fail "User name must use letters, numbers, '-', or '_' only."
    [ "$DEL_USER" = 1 ] || [ "$SHOW_QR" = 1 ] && sanitize_name && { [ -z "$SAFE_NAME" ] || ! grep -q "^# BEGIN_PEER $SAFE_NAME$" "$VPN_CONFIG"; } && fail "User name is invalid or does not exist."
    [ -n "$ENDPOINT_NAME" ] && ! { is_valid_domain "$ENDPOINT_NAME" || is_valid_ip "$ENDPOINT_NAME"; } && fail "Endpoint must be a valid domain or IP address."
    [ -n "$PORT_NUM" ] && { [[ ! "$PORT_NUM" =~ ^[0-9]+$ || "$PORT_NUM" -gt 65535 ]]; } && fail "Port must be a number between 1 and 65535."
    [ -n "$DNS_PRI" ] && ! is_valid_ip "$DNS_PRI" && fail "Primary DNS must be a valid IP address."
    [ -n "$DNS_SEC" ] && ! is_valid_ip "$DNS_SEC" && fail "Secondary DNS must be a valid IP address."
    [ -z "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && fail "Primary DNS is required if secondary DNS is specified."
    DNS_SET="$DNS_DEFAULT"
    [ -n "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && DNS_SET="$DNS_PRI, $DNS_SEC"
    [ -n "$DNS_PRI" ] && [ -z "$DNS_SEC" ] && DNS_SET="$DNS_PRI"
}

display_help() {
    # Show usage instructions
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
    # Display initial greeting
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "${GREEN}WireGuard Auto Deployer Setup${NC}"
        echo "Please provide some details to configure your VPN."
        echo "Hit Enter to use the suggested settings."
    else
        echo -e "${BLUE}Deploying VPN with $([ -n "$ENDPOINT_NAME" ] || [ -n "$PORT_NUM" ] || [ -n "$FIRST_USER" ] || [ -n "$DNS_PRI" ] && echo "specified" || echo "default") options.${NC}"
    fi
}

fetch_endpoint() {
    # Determine the VPN endpoint
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nWould you like to use a domain instead of an IP? [y/N]: "
        read -r choice
        case "$choice" in
            [yY]*) 
                echo -e "\nProvide the domain name for your VPN:"
                read -r domain
                until is_valid_domain "$domain"; do
                    echo "Invalid domain name entered."
                    read -r domain
                done
                ENDPOINT_IP="$domain"
                echo -e "${YELLOW}Make sure '$domain' points to this server's IP.${NC}"
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
    # Automatically detect server IP
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        ENDPOINT_IP=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! is_valid_ip "$ENDPOINT_IP"; then
            ENDPOINT_IP=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! is_valid_ip "$ENDPOINT_IP"; then
                [ "$AUTO_SETUP" = 0 ] && select_ip_manually || fail "Unable to detect server IP automatically."
            fi
        fi
    fi
    is_private_ip "$ENDPOINT_IP" && PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com || fail "Failed to detect public IP for NAT.")
    echo -e "${BLUE}Detected Server IP: $ENDPOINT_IP${NC}"
    [ -n "$PUBLIC_IP" ] && echo -e "${BLUE}Public IP (NAT): $PUBLIC_IP${NC}"
}

select_ip_manually() {
    # Manually select IP if multiple detected
    echo -e "\nDetected multiple IPs. Pick one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "Choose IP [1]: " ip_choice
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$ip_choice" || "$ip_choice" =~ ^[0-9]+$ && "$ip_choice" -le "$ip_count" ]]; do
        echo "Invalid choice."
        read -rp "Choose IP [1]: " ip_choice
    done
    [ -z "$ip_choice" ] && ip_choice=1
    ENDPOINT_IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_choice}p")
}

set_port() {
    # Set the VPN port
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nSpecify the VPN port [51820]:"
        read -r port_input
        PORT_NUM="${port_input:-51820}"
        until [[ "$PORT_NUM" =~ ^[0-9]+$ && "$PORT_NUM" -le 65535 ]]; do
            echo "Invalid port number."
            read -r port_input
            PORT_NUM="${port_input:-51820}"
        done
    else
        PORT_NUM="${PORT_NUM:-51820}"
    fi
    echo -e "${BLUE}Using Port: $PORT_NUM${NC}"
}

set_ip_version() {
    # Choose IPv4, IPv6, or both
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nEnable IPv6 support alongside IPv4? [y/N]:"
        read -r ipv6_choice
        case "$ipv6_choice" in
            [yY]*) ENABLE_IPV6=1 ;;
            *) ENABLE_IPV6=0 ;;
        esac
    fi
    if [ "$ENABLE_IPV6" = 1 ]; then
        echo -e "${BLUE}IPv6 Enabled: Server will use both IPv4 (${VPN_IPV4}.1/24) and IPv6 (${VPN_IPV6}1/64)${NC}"
    else
        echo -e "${BLUE}IPv6 Disabled: Server will use IPv4 only (${VPN_IPV4}.1/24)${NC}"
    fi
}

choose_dns() {
    # Select DNS servers for VPN users
    if [ "$AUTO_SETUP" = 0 ] || [ "$ADD_USER" = 1 ]; then
        echo -e "\nPick DNS servers for VPN users:"
        echo "  1) Use system DNS"
        echo "  2) Google DNS (8.8.8.8, 8.8.4.4)"
        echo "  3) Cloudflare DNS (1.1.1.1, 1.0.0.1)"
        echo "  4) OpenDNS (208.67.222.222, 208.67.220.220)"
        echo "  5) Quad9 (9.9.9.9, 149.112.112.112)"
        echo "  6) AdGuard DNS (94.140.14.14, 94.140.15.15)"
        echo "  7) NextDNS (45.90.28.0, 45.90.30.0)"
        echo "  8) CleanBrowsing (185.228.168.168, 185.228.169.168)"
        echo "  9) Enter custom DNS"
        read -rp "Option [2]: " dns_opt
        until [[ -z "$dns_opt" || "$dns_opt" =~ ^[1-9]$ ]]; do
            echo "Invalid option."
            read -rp "Option [2]: " dns_opt
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
            echo "Provide primary DNS:"
            read -r custom_pri
            until is_valid_ip "$custom_pri"; do
                echo "Invalid DNS IP."
                read -r custom_pri
            done
            echo "Provide secondary DNS (optional, press Enter to skip):"
            read -r custom_sec
            [ -n "$custom_sec" ] && until is_valid_ip "$custom_sec"; do
                echo "Invalid DNS IP."
                read -r custom_sec
            done
            DNS_SET="$custom_pri"
            [ -n "$custom_sec" ] && DNS_SET="$custom_pri, $custom_sec"
            ;;
    esac
    echo -e "${BLUE}Selected DNS: $DNS_SET${NC}"
}

set_initial_user() {
    # Define the initial VPN user
    if [ "$AUTO_SETUP" = 0 ]; then
        echo -e "\nEnter the first VPN user name [user]:"
        read -r user_input
        FIRST_USER="${user_input:-user}"
        sanitize_name "RAW_NAME=$FIRST_USER"
        FIRST_USER="$SAFE_NAME"
    fi
    [ -z "$FIRST_USER" ] && FIRST_USER="user"
    echo -e "${BLUE}Initial User: $FIRST_USER${NC}"
}

prepare_install() {
    # Signal readiness for VPN installation
    [ "$AUTO_SETUP" = 0 ] && echo -e "\n${BLUE}VPN installation is about to start.${NC}"
}

setup_packages() {
    # Install necessary software packages
    echo -e "${YELLOW}Setting up required software...${NC}"
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
    # Configure WireGuard VPN server
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
    # Configure firewall rules for VPN
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
        if [ "$ENABLE_IPV6" = 1 ]; then
            ip6tables -A INPUT -p udp --dport "$PORT_NUM" -j ACCEPT
            ip6tables -A FORWARD -s "${VPN_IPV6}/64" -j ACCEPT
            ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
            ip6tables -t nat -A POSTROUTING -s "${VPN_IPV6}/64" -o "$net_if" -j MASQUERADE
        fi
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
    [ "$ENABLE_IPV6" = 1 ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vpn.conf
    sysctl -p /etc/sysctl.d/99-vpn.conf
}

add_vpn_user() {
    # Add a new VPN user
    local user_name="${1:-$FIRST_USER}"
    local ip_octet=2
    local custom_ip=""
    if [ "$AUTO_SETUP" = 0 ] || [ "$ADD_USER" = 1 ]; then
        echo -e "\nAssign a custom IP for '$user_name'? [y/N]:"
        read -r custom_choice
        if [[ "$custom_choice" =~ ^[yY]$ ]]; then
            echo "Enter IPv4 address (e.g., ${VPN_IPV4}.X, where X is 2-254):"
            read -r custom_ip
            ip_octet=$(echo "$custom_ip" | cut -d '.' -f 4)
            until [[ "$custom_ip" =~ ^${VPN_IPV4}\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]] && ! grep -q "AllowedIPs = ${VPN_IPV4}.$ip_octet/32" "$VPN_CONFIG"; do
                if [[ ! "$custom_ip" =~ ^${VPN_IPV4}\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
                    echo "Invalid IP. Must be in range ${VPN_IPV4}.2 to ${VPN_IPV4}.254."
                else
                    echo "IP already in use."
                fi
                read -r custom_ip
                ip_octet=$(echo "$custom_ip" | cut -d '.' -f 4)
            done
        fi
    fi
    if [ -z "$custom_ip" ]; then
        while grep -q "AllowedIPs = ${VPN_IPV4}.$ip_octet/32" "$VPN_CONFIG"; do
            ((ip_octet++))
        done
        [ "$ip_octet" -eq 255 ] && fail "VPN subnet full. Max 253 users."
    fi
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
AllowedIPs = 0.0.0.0/0$( [ "$ENABLE_IPV6" = 1 ] && echo ", ::/0" )
Endpoint = $ENDPOINT_IP:$PORT_NUM
PersistentKeepalive = $KEEPALIVE_DEFAULT
EOF
    chmod 600 "$USER_DIR/$user_name.conf"
    systemctl restart wg-quick@wg0 || fail "Failed to restart WireGuard service."
    echo -e "${GREEN}User '$user_name' added with IP: ${VPN_IPV4}.$ip_octet${NC}"
    [ "$ENABLE_IPV6" = 1 ] && echo -e "${GREEN}IPv6 IP: ${VPN_IPV6}$ip_octet${NC}"
    qrencode -t UTF8 < "$USER_DIR/$user_name.conf"
    echo -e "${BLUE}Config saved to: $USER_DIR/$user_name.conf${NC}"
}

start_service() {
    # Start and enable WireGuard service
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service || fail "Failed to start VPN service."
}

complete_setup() {
    # Confirm successful setup
    echo -e "${GREEN}VPN setup completed successfully!${NC}"
    echo "User config saved to: $USER_DIR/$FIRST_USER.conf"
}

list_users() {
    # List all VPN users
    grep '^# BEGIN_PEER' "$VPN_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    local user_count=$(grep -c '^# BEGIN_PEER' "$VPN_CONFIG")
    echo -e "\nTotal users: $user_count"
}

remove_user() {
    # Remove a VPN user
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
    systemctl restart wg-quick@wg0 || fail "Failed to restart WireGuard service after user removal."
    echo -e "${GREEN}User '$SAFE_NAME' removed.${NC}"
}

show_qr_code() {
    # Display QR code for a VPN user
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
    # Uninstall WireGuard and clean up
    systemctl stop wg-quick@wg0
    systemctl disable wg-quick@wg0
    rm -rf /etc/wireguard "$USER_DIR" /etc/sysctl.d/99-vpn.conf
    iptables -D INPUT -p udp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s "${VPN_IPV4}.0/24" -j MASQUERADE 2>/dev/null
    if [ "$ENABLE_IPV6" = 1 ]; then
        ip6tables -D INPUT -p udp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null
        ip6tables -t nat -D POSTROUTING -s "${VPN_IPV6}/64" -j MASQUERADE 2>/dev/null
    fi
    case "$SYS_TYPE" in
        "ubuntu"|"debian") apt-get remove -y wireguard qrencode iptables 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
    esac
    echo -e "${GREEN}WireGuard uninstalled.${NC}"
}

main() {
    # Main execution flow
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
        set_ip_version
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
            set_ip_version
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

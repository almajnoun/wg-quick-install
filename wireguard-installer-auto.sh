#!/bin/bash

# WireGuard Auto Deploy Tool
# A streamlined script for deploying WireGuard VPN servers
# Repository: https://github.com/almajnoun/wireguard-installer-auto
# Created by Almajnoun with enhancements from Grok 3 (xAI)
# Licensed under MIT - 2025

# Utility Functions
terminate() { echo "Fatal: $1" >&2; exit 1; }
fail_apt() { terminate "Failed to install packages via apt-get."; }
fail_yum() { terminate "Failed to install packages via yum."; }
fail_zypper() { terminate "Failed to install packages via zypper."; }

validate_ip() {
    local ip_pattern='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    echo "$1" | grep -Eq "$ip_pattern"
}

is_private_ip() {
    local priv_pattern='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    echo "$1" | grep -Eq "$priv_pattern"
}

check_domain() {
    local domain_pattern='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    echo "$1" | grep -Eq "$domain_pattern"
}

ensure_root() {
    [ "$(id -u)" -ne 0 ] && terminate "Run this script as root with 'sudo bash $0'."
}

verify_bash() {
    readlink /proc/$$/exe | grep -q "dash" && terminate "Use 'bash' instead of 'sh' to run this script."
}

check_kernel_version() {
    [ "$(uname -r | cut -d '.' -f 1)" -eq 2 ] && terminate "Incompatible old kernel detected."
}

identify_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        OS_TYPE="ubuntu"
        OS_VER=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [ -e /etc/debian_version ]; then
        OS_TYPE="debian"
        OS_VER=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
        OS_TYPE="centos"
        OS_VER=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [ -e /etc/fedora-release ]; then
        OS_TYPE="fedora"
        OS_VER=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [ -e /etc/SUSE-brand ] && grep -q "openSUSE" /etc/SUSE-brand; then
        OS_TYPE="openSUSE"
        OS_VER=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        terminate "Unsupported OS. Compatible with Ubuntu, Debian, CentOS, Fedora, and openSUSE."
    fi
}

verify_os_version() {
    [ "$OS_TYPE" = "ubuntu" ] && [ "$OS_VER" -lt 2004 ] && terminate "Ubuntu 20.04 or later required."
    [ "$OS_TYPE" = "debian" ] && [ "$OS_VER" -lt 11 ] && terminate "Debian 11 or later required."
    [ "$OS_TYPE" = "centos" ] && [ "$OS_VER" -lt 8 ] && terminate "CentOS 8 or later required."
}

detect_container() {
    systemd-detect-virt -cq 2>/dev/null && terminate "Running inside a container is not supported."
}

sanitize_user() {
    USER_SAFE=$(echo "$USER_RAW" | sed 's/[^0-9a-zA-Z_-]/_/g' | cut -c-15)
}

# Argument Parsing
process_flags() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --fast) FAST_MODE=1; shift ;;
            --new-user) NEW_USER=1; USER_RAW="$2"; shift 2 ;;
            --list-users) LIST_USERS=1; shift ;;
            --drop-user) DROP_USER=1; USER_RAW="$2"; shift 2 ;;
            --view-qr) VIEW_QR=1; USER_RAW="$2"; shift 2 ;;
            --wipe) WIPE_WG=1; shift ;;
            --host) HOST_NAME="$2"; shift 2 ;;
            --port-num) PORT_NUM="$2"; shift 2 ;;
            --username) FIRST_USER="$2"; shift 2 ;;
            --dns-pri) DNS_PRI="$2"; shift 2 ;;
            --dns-sec) DNS_SEC="$2"; shift 2 ;;
            -y|--confirm) CONFIRM_YES=1; shift ;;
            -h|--guide) display_guide; exit 0 ;;
            *) display_guide "Unrecognized option: $1"; exit 1 ;;
        esac
    done
}

validate_flags() {
    [ "$FAST_MODE" = 1 ] && [ -e "$VPN_CONFIG" ] && display_guide "Cannot use '--fast' when WireGuard is already installed."
    [ "$(($NEW_USER + $LIST_USERS + $DROP_USER + $VIEW_QR))" -gt 1 ] && display_guide "Specify only one action: '--new-user', '--list-users', '--drop-user', or '--view-qr'."
    [ "$WIPE_WG" = 1 ] && [ "$(($NEW_USER + $LIST_USERS + $DROP_USER + $VIEW_QR + $FAST_MODE))" -gt 0 ] && display_guide "'--wipe' cannot be combined with other actions."
    if [ ! -e "$VPN_CONFIG" ]; then
        local msg="WireGuard must be configured first to"
        [ "$NEW_USER" = 1 ] && terminate "$msg add a user."
        [ "$LIST_USERS" = 1 ] && terminate "$msg list users."
        [ "$DROP_USER" = 1 ] && terminate "$msg remove a user."
        [ "$VIEW_QR" = 1 ] && terminate "$msg display QR code."
        [ "$WIPE_WG" = 1 ] && terminate "No WireGuard installation to remove."
    fi
    [ "$NEW_USER" = 1 ] && sanitize_user && [ -z "$USER_SAFE" ] && terminate "User name must be alphanumeric with '-' or '_' only."
    [ "$DROP_USER" = 1 ] || [ "$VIEW_QR" = 1 ] && sanitize_user && { [ -z "$USER_SAFE" ] || ! grep -q "^# USER_START $USER_SAFE$" "$VPN_CONFIG"; } && terminate "Invalid or non-existent user name."
    [ -n "$HOST_NAME" ] && ! { check_domain "$HOST_NAME" || validate_ip "$HOST_NAME"; } && terminate "Host must be a valid domain or IPv4 address."
    [ -n "$PORT_NUM" ] && { [[ ! "$PORT_NUM" =~ ^[0-9]+$ || "$PORT_NUM" -gt 65535 ]]; } && terminate "Port must be a number between 1 and 65535."
    [ -n "$DNS_PRI" ] && ! validate_ip "$DNS_PRI" && terminate "Primary DNS must be a valid IP."
    [ -n "$DNS_SEC" ] && ! validate_ip "$DNS_SEC" && terminate "Secondary DNS must be a valid IP."
    [ -z "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && terminate "Specify --dns-pri with --dns-sec."
    DNS_SET="$DNS_DEFAULT"
    [ -n "$DNS_PRI" ] && [ -n "$DNS_SEC" ] && DNS_SET="$DNS_PRI, $DNS_SEC"
    [ -n "$DNS_PRI" ] && [ -z "$DNS_SEC" ] && DNS_SET="$DNS_PRI"
}

# Display Functions
display_intro() {
    cat <<'EOF'

WireGuard Auto Deploy Tool
https://github.com/almajnoun/wireguard-installer-auto
EOF
}

display_welcome() {
    cat <<'EOF'

Welcome to the WireGuard Auto Deploy Tool!
Repository: https://github.com/almajnoun/wireguard-installer-auto

EOF
}

display_credits() {
    cat <<'EOF'

Created by Almajnoun with enhancements from Grok 3 (xAI)
MIT License - 2025
EOF
}

display_guide() {
    [ -n "$1" ] && echo "Error: $1" >&2
    display_intro
    display_credits
    cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:
  --new-user [name]       Create a new VPN user
  --dns-pri [IP]          Primary DNS server (default: 8.8.8.8)
  --dns-sec [IP]          Secondary DNS server (optional)
  --list-users            Display all VPN users
  --drop-user [name]      Remove a VPN user
  --view-qr [name]        Show QR code for a user
  --wipe                  Uninstall WireGuard and configurations
  -y, --confirm           Auto-confirm removal prompts
  -h, --guide             Display this guide

Setup Options (optional):
  --fast                  Fast setup with defaults or custom settings
  --host [DNS/IP]         VPN host (domain or IPv4)
  --port-num [number]     WireGuard port (1-65535, default: 51820)
  --username [name]       Initial VPN user name (default: user)
  --dns-pri [IP]          Primary DNS for initial user
  --dns-sec [IP]          Secondary DNS for initial user

Run without arguments for interactive setup.
EOF
    exit 1
}

greet_user() {
    if [ "$FAST_MODE" = 0 ]; then
        display_welcome
        echo "I'll need some details to set up your VPN."
        echo "Press Enter to accept defaults."
    else
        display_intro
        local mode="default"
        [ -n "$HOST_NAME" ] || [ -n "$PORT_NUM" ] || [ -n "$FIRST_USER" ] || [ -n "$DNS_PRI" ] && mode="custom"
        echo
        echo "Initiating VPN deployment with $mode settings."
    fi
}

notify_domain() {
    cat <<EOF

Note: Ensure the domain '$1'
      resolves to this server's IPv4 address.
EOF
}

# Setup Functions
choose_endpoint() {
    if [ "$FAST_MODE" = 0 ]; then
        echo -e "\nUse a domain name (e.g., vpn.example.com) instead of IP? [y/N]:"
        read -r choice
        case "$choice" in
            [yY]*) 
                echo -e "\nEnter the VPN server's domain name:"
                read -r host
                until check_domain "$host"; do
                    echo "Invalid domain. Must be a valid FQDN."
                    read -r host
                done
                ENDPOINT="$host"
                notify_domain "$ENDPOINT"
                ;;
            *) detect_endpoint_ip ;;
        esac
    else
        [ -n "$HOST_NAME" ] && ENDPOINT="$HOST_NAME" || detect_endpoint_ip
    fi
    [ -z "$ENDPOINT" ] && terminate "Could not determine endpoint address."
}

detect_endpoint_ip() {
    local ip_count=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    if [ "$ip_count" -eq 1 ]; then
        ENDPOINT=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        ENDPOINT=$(ip -4 route get 1 | awk '{print $NF;exit}' 2>/dev/null)
        if ! validate_ip "$ENDPOINT"; then
            ENDPOINT=$(curl -s http://ipv4.icanhazip.com || curl -s http://ip1.dynupdate.no-ip.com)
            if ! validate_ip "$ENDPOINT"; then
                [ "$FAST_MODE" = 0 ] && pick_endpoint_ip || terminate "Unable to detect server IP in fast mode."
            fi
        fi
    fi
    is_private_ip "$ENDPOINT" && PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com || terminate "Failed to detect public IP for NAT.")
    echo -e "${BLUE}Server IP: $ENDPOINT${NC}"
    [ -n "$PUBLIC_IP" ] && echo -e "${BLUE}Public IP (NAT): $PUBLIC_IP${NC}"
}

pick_endpoint_ip() {
    echo -e "\nMultiple IPs found. Select one:"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -rp "IP [1]: " ip_idx
    local ip_total=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    until [[ -z "$ip_idx" || "$ip_idx" =~ ^[0-9]+$ && "$ip_idx" -le "$ip_total" ]]; do
        echo "Invalid selection."
        read -rp "IP [1]: " ip_idx
    done
    [ -z "$ip_idx" ] && ip_idx=1
    ENDPOINT=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_idx}p")
}

set_vpn_port() {
    if [ "$FAST_MODE" = 0 ]; then
        echo -e "\nChoose a port for WireGuard [51820]:"
        read -r port_input
        PORT_NUM="${port_input:-51820}"
        until [[ "$PORT_NUM" =~ ^[0-9]+$ && "$PORT_NUM" -le 65535 ]]; do
            echo "Invalid port."
            read -r port_input
            PORT_NUM="${port_input:-51820}"
        done
    else
        PORT_NUM="${PORT_NUM:-$PORT_DEFAULT}"
    fi
    echo -e "${BLUE}Port: $PORT_NUM${NC}"
}

configure_ip_versions() {
    if [ "$FAST_MODE" = 0 ]; then
        echo -e "\nEnable IPv6 alongside IPv4? [y/N]:"
        read -r ipv6_choice
        case "$ipv6_choice" in
            [yY]*) IPV6_ON=1 ;;
            *) IPV6_ON=0 ;;
        esac
    fi
    if [ "$IPV6_ON" = 1 ] && ip -6 addr | grep -q 'inet6 [23]'; then
        IPV6_ADDR=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | head -1)
        echo -e "${BLUE}IPv6 Enabled: Using IPv4 (${VPN_IPV4}.1/24) and IPv6 (${VPN_IPV6}1/64)${NC}"
    else
        IPV6_ON=0
        echo -e "${BLUE}IPv6 Disabled: Using IPv4 only (${VPN_IPV4}.1/24)${NC}"
    fi
}

pick_dns_servers() {
    if [ "$FAST_MODE" = 0 ] || [ "$NEW_USER" = 1 ]; then
        echo -e "\nSelect DNS servers for VPN users:"
        echo "  1) System resolvers"
        echo "  2) Google DNS (8.8.8.8, 8.8.4.4)"
        echo "  3) Cloudflare DNS (1.1.1.1, 1.0.0.1)"
        echo "  4) OpenDNS (208.67.222.222, 208.67.220.220)"
        echo "  5) Quad9 (9.9.9.9, 149.112.112.112)"
        echo "  6) AdGuard DNS (94.140.14.14, 94.140.15.15)"
        echo "  7) Custom DNS"
        read -rp "Choice [2]: " dns_choice
        until [[ -z "$dns_choice" || "$dns_choice" =~ ^[1-7]$ ]]; do
            echo "Invalid choice."
            read -rp "Choice [2]: " dns_choice
        done
    else
        dns_choice=2
    fi
    case "$dns_choice" in
        1) DNS_SET=$(grep -v '^#\|^;' /etc/resolv.conf | grep '^nameserver' | grep -v '127.0.0.53' | awk '{print $2}' | paste -sd ', ') ;;
        2|"") DNS_SET="8.8.8.8, 8.8.4.4" ;;
        3) DNS_SET="1.1.1.1, 1.0.0.1" ;;
        4) DNS_SET="208.67.222.222, 208.67.220.220" ;;
        5) DNS_SET="9.9.9.9, 149.112.112.112" ;;
        6) DNS_SET="94.140.14.14, 94.140.15.15" ;;
        7) 
            echo "Enter primary DNS:"
            read -r pri_dns
            until validate_ip "$pri_dns"; do
                echo "Invalid IP."
                read -r pri_dns
            done
            echo "Enter secondary DNS (optional):"
            read -r sec_dns
            [ -n "$sec_dns" ] && until validate_ip "$sec_dns"; do
                echo "Invalid IP."
                read -r sec_dns
            done
            DNS_SET="$pri_dns"
            [ -n "$sec_dns" ] && DNS_SET="$pri_dns, $sec_dns"
            ;;
    esac
    echo -e "${BLUE}DNS: $DNS_SET${NC}"
}

set_first_user() {
    if [ "$FAST_MODE" = 0 ]; then
        echo -e "\nName the first VPN user [user]:"
        read -r user_raw
        FIRST_USER="${user_raw:-user}"
        USER_RAW="$FIRST_USER"
        sanitize_user
        FIRST_USER="$USER_SAFE"
    fi
    [ -z "$FIRST_USER" ] && FIRST_USER="user"
    echo -e "${BLUE}First User: $FIRST_USER${NC}"
}

prepare_deployment() {
    [ "$FAST_MODE" = 0 ] && echo -e "\n${BLUE}Ready to deploy WireGuard VPN.${NC}"
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y wireguard qrencode iptables || fail_apt
            ;;
        "centos")
            [ "$OS_VER" -eq 9 ] && yum install -y epel-release wireguard-tools qrencode iptables || fail_yum
            [ "$OS_VER" -eq 8 ] && yum install -y epel-release elrepo-release kmod-wireguard wireguard-tools qrencode iptables || fail_yum
            ;;
        "fedora")
            dnf install -y wireguard-tools qrencode iptables || terminate "dnf install failed."
            ;;
        "openSUSE")
            zypper install -y wireguard-tools qrencode iptables || fail_zypper
            ;;
    esac
    mkdir -p /etc/wireguard "$USER_DIR"
    chmod 700 /etc/wireguard "$USER_DIR"
}

setup_vpn_config() {
    local temp_key=$(mktemp)
    wg genkey > "$temp_key"
    SERVER_PRIV=$(cat "$temp_key")
    echo "$SERVER_PRIV" | wg pubkey > /etc/wireguard/server.pub
    SERVER_PUB=$(cat /etc/wireguard/server.pub)
    mv "$temp_key" /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key /etc/wireguard/server.pub
    [ -z "$ENDPOINT" ] && terminate "Endpoint not set for server config."
    cat > "$VPN_CONFIG" << EOF
# HOST $ENDPOINT
[Interface]
Address = ${VPN_IPV4}.1/24$( [ "$IPV6_ON" = 1 ] && echo ", ${VPN_IPV6}1/64" )
PrivateKey = $SERVER_PRIV
ListenPort = $PORT_NUM
EOF
    chmod 600 "$VPN_CONFIG"
}

configure_network_rules() {
    local net_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$PORT_NUM"/udp --permanent
        firewall-cmd --zone=trusted --add-source="${VPN_IPV4}.0/24" --permanent
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s ${VPN_IPV4}.0/24 ! -d ${VPN_IPV4}.0/24 -j MASQUERADE --permanent
        [ "$IPV6_ON" = 1 ] && firewall-cmd --zone=trusted --add-source="${VPN_IPV6}/64" --permanent
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$PORT_NUM" -j ACCEPT
        iptables -A FORWARD -s ${VPN_IPV4}.0/24 -j ACCEPT
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -s ${VPN_IPV4}.0/24 -o "$net_if" -j MASQUERADE
        [ "$IPV6_ON" = 1 ] && ip6tables -t nat -A POSTROUTING -s "${VPN_IPV6}/64" -o "$net_if" -j MASQUERADE
    fi
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn.conf
    [ "$IPV6_ON" = 1 ] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vpn.conf
    sysctl -p /etc/sysctl.d/99-vpn.conf
}

add_new_user() {
    local user_name="${1:-$FIRST_USER}"
    local ip_octet=2
    while grep -q "AllowedIPs = ${VPN_IPV4}.$ip_octet/32" "$VPN_CONFIG"; do
        ((ip_octet++))
    done
    [ "$ip_octet" -eq 255 ] && terminate "VPN subnet full. Max 253 users."
    local temp_key=$(mktemp)
    local temp_psk=$(mktemp)
    wg genkey > "$temp_key"
    wg genpsk > "$temp_psk"
    USER_PRIV=$(cat "$temp_key")
    USER_PSK=$(cat "$temp_psk")
    echo "$USER_PRIV" | wg pubkey > "$USER_DIR/$user_name.pub"
    USER_PUB=$(cat "$USER_DIR/$user_name.pub")
    mv "$temp_key" "$USER_DIR/$user_name.key"
    mv "$temp_psk" "$USER_DIR/$user_name.psk"
    chmod 600 "$USER_DIR/$user_name.key" "$USER_DIR/$user_name.pub" "$USER_DIR/$user_name.psk"
    cat >> "$VPN_CONFIG" << EOF

# USER_START $user_name
[Peer]
PublicKey = $USER_PUB
PresharedKey = $USER_PSK
AllowedIPs = ${VPN_IPV4}.$ip_octet/32$( [ "$IPV6_ON" = 1 ] && echo ", ${VPN_IPV6}$ip_octet/128" )
# USER_END $user_name
EOF
    local server_pub=$(cat /etc/wireguard/server.pub)
    cat > "$USER_DIR/$user_name.conf" << EOF
[Interface]
Address = ${VPN_IPV4}.$ip_octet/24$( [ "$IPV6_ON" = 1 ] && echo ", ${VPN_IPV6}$ip_octet/64" )
DNS = $DNS_SET
PrivateKey = $USER_PRIV

[Peer]
PublicKey = $server_pub
PresharedKey = $USER_PSK
AllowedIPs = 0.0.0.0/0$( [ "$IPV6_ON" = 1 ] && echo ", ::/0" )
Endpoint = $ENDPOINT:$PORT_NUM
PersistentKeepalive = $KEEPALIVE_DEFAULT
EOF
    chmod 600 "$USER_DIR/$user_name.conf"
    wg addconf wg0 <(grep -A 4 "^# USER_START $user_name" "$VPN_CONFIG")
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to add user configuration dynamically. Restarting service:${NC}"
        systemctl restart wg-quick@wg0.service
        [ $? -ne 0 ] && terminate "Failed to restart WireGuard service. Check systemctl status wg-quick@wg0.service."
    fi
    echo -e "${GREEN}Added user '$user_name' with IP: ${VPN_IPV4}.$ip_octet${NC}"
    [ "$IPV6_ON" = 1 ] && echo -e "${GREEN}IPv6 IP: ${VPN_IPV6}$ip_octet${NC}"
    qrencode -t UTF8 < "$USER_DIR/$user_name.conf"
    echo -e "${BLUE}Config file: $USER_DIR/$user_name.conf${NC}"
}

launch_vpn() {
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start VPN service. Details:${NC}"
        systemctl status wg-quick@wg0.service
        terminate "Service start failed."
    fi
}

finalize_setup() {
    echo -e "${GREEN}VPN deployment completed!${NC}"
    echo "User config saved at: $USER_DIR/$FIRST_USER.conf"
}

list_all_users() {
    grep '^# USER_START' "$VPN_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    local user_count=$(grep -c '^# USER_START' "$VPN_CONFIG")
    echo -e "\nTotal users: $user_count"
}

remove_user() {
    echo "Select user to remove:"
    list_all_users
    read -rp "User number: " user_idx
    local user_total=$(grep -c '^# USER_START' "$VPN_CONFIG")
    until [[ "$user_idx" =~ ^[0-9]+$ && "$user_idx" -le "$user_total" ]]; do
        echo "Invalid selection."
        read -rp "User number: " user_idx
    done
    USER_SAFE=$(grep '^# USER_START' "$VPN_CONFIG" | cut -d ' ' -f 3 | sed -n "${user_idx}p")
    wg set wg0 peer "$(grep -A 1 "^# USER_START $USER_SAFE" "$VPN_CONFIG" | grep 'PublicKey' | cut -d ' ' -f 3)" remove
    sed -i "/^# USER_START $USER_SAFE$/,/^# USER_END $USER_SAFE$/d" "$VPN_CONFIG"
    rm -f "$USER_DIR/$USER_SAFE.conf" "$USER_DIR/$USER_SAFE.key" "$USER_DIR/$USER_SAFE.pub" "$USER_DIR/$USER_SAFE.psk"
    echo -e "${GREEN}User '$USER_SAFE' removed.${NC}"
}

show_user_qr() {
    echo "Select user for QR code:"
    list_all_users
    read -rp "User number: " user_idx
    local user_total=$(grep -c '^# USER_START' "$VPN_CONFIG")
    until [[ "$user_idx" =~ ^[0-9]+$ && "$user_idx" -le "$user_total" ]]; do
        echo "Invalid selection."
        read -rp "User number: " user_idx
    done
    USER_SAFE=$(grep '^# USER_START' "$VPN_CONFIG" | cut -d ' ' -f 3 | sed -n "${user_idx}p")
    [ -f "$USER_DIR/$USER_SAFE.conf" ] || terminate "Config file for '$USER_SAFE' not found."
    qrencode -t UTF8 < "$USER_DIR/$USER_SAFE.conf"
    echo -e "${BLUE}QR code for '$USER_SAFE' shown above.${NC}"
}

wipe_vpn() {
    systemctl stop wg-quick@wg0
    systemctl disable wg-quick@wg0
    rm -rf /etc/wireguard "$USER_DIR" /etc/sysctl.d/99-vpn.conf
    iptables -D INPUT -p udp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -s "${VPN_IPV4}.0/24" -j MASQUERADE 2>/dev/null
    [ "$IPV6_ON" = 1 ] && ip6tables -t nat -D POSTROUTING -s "${VPN_IPV6}/64" -j MASQUERADE 2>/dev/null
    case "$OS_TYPE" in
        "ubuntu"|"debian") apt-get remove -y wireguard qrencode iptables 2>/dev/null ;;
        "centos") yum remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "fedora") dnf remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
        "openSUSE") zypper remove -y wireguard-tools qrencode iptables 2>/dev/null ;;
    esac
    echo -e "${GREEN}WireGuard uninstalled.${NC}"
}

# Main Logic
deploy_vpn() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ensure_root
    verify_bash
    check_kernel_version
    identify_os
    verify_os_version
    detect_container

    VPN_CONFIG="/etc/wireguard/wg0.conf"
    USER_DIR="$HOME/wireguard-users"
    VPN_IPV4="10.7.0"  # Correctly defined here
    VPN_IPV6="fddd:2c4:2c4:2c4::"
    DNS_DEFAULT="8.8.8.8, 8.8.4.4"
    KEEPALIVE_DEFAULT=25
    PORT_DEFAULT=51820

    FAST_MODE=0
    CONFIRM_YES=0
    NEW_USER=0
    LIST_USERS=0
    DROP_USER=0
    VIEW_QR=0
    WIPE_WG=0
    PUBLIC_IP=""
    HOST_NAME=""
    PORT_NUM=""
    FIRST_USER=""
    USER_RAW=""
    USER_SAFE=""
    DNS_SET=""
    DNS_PRI=""
    DNS_SEC=""

    process_flags "$@"
    validate_flags

    if [ "$NEW_USER" = 1 ]; then
        display_intro
        sanitize_user
        pick_dns_servers
        add_new_user "$USER_SAFE"
        echo -e "${BLUE}QR code displayed above.${NC}"
        echo -e "${GREEN}User '$USER_SAFE' added. Config at: $USER_DIR/$USER_SAFE.conf${NC}"
        exit 0
    fi

    if [ "$LIST_USERS" = 1 ]; then
        display_intro
        echo -e "\nListing users..."
        list_all_users
        exit 0
    fi

    if [ "$DROP_USER" = 1 ]; then
        display_intro
        sanitize_user
        remove_user
        exit 0
    fi

    if [ "$VIEW_QR" = 1 ]; then
        display_intro
        sanitize_user
        show_user_qr
        exit 0
    fi

    if [ "$WIPE_WG" = 1 ]; then
        display_intro
        wipe_vpn
        exit 0
    fi

    if [ ! -e "$VPN_CONFIG" ]; then
        greet_user
        choose_endpoint
        set_vpn_port
        configure_ip_versions
        set_first_user
        pick_dns_servers
        prepare_deployment
        install_dependencies
        setup_vpn_config
        configure_network_rules
        add_new_user "$FIRST_USER"
        launch_vpn
        echo -e "${BLUE}QR code displayed above.${NC}"
        finalize_setup
    else
        display_intro
        echo -e "\n${BLUE}WireGuard is already deployed. Select an action:${NC}"
        echo "  1) Add new user"
        echo "  2) List users"
        echo "  3) Remove user"
        echo "  4) Show QR code"
        echo "  5) Uninstall"
        echo "  6) Quit"
        read -rp "Option: " choice
        until [[ "$choice" =~ ^[1-6]$ ]]; do
            echo "Invalid option."
            read -rp "Option: " choice
        done
        case "$choice" in
            1) pick_dns_servers; add_new_user; echo -e "${BLUE}QR code displayed above.${NC}"; echo -e "${GREEN}User added. Config at: $USER_DIR/$USER_SAFE.conf${NC}" ;;
            2) list_all_users ;;
            3) remove_user ;;
            4) show_user_qr ;;
            5) wipe_vpn ;;
            6) exit 0 ;;
        esac
    fi
}

deploy_vpn "$@"
exit 0

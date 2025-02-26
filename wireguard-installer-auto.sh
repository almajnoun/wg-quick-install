#!/bin/bash

# سكريبت تثبيت وإدارة WireGuard محسّن مع خيارات DNS إضافية
# المؤلف: Grok 3 (بتاريخ 26 فبراير 2025)

# ألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# متغيرات افتراضية
WG_PORT=51820
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="$HOME/wireguard-clients"
LOG_FILE="$HOME/wireguard.log"
IPV4_RANGE="10.0.0"
DNS_SERVER="8.8.8.8"
KEEPALIVE=25
PUBLIC_IP=""
SERVER_ADDR=""
CLIENT_NAME="client"

# دوال مساعدة
msg() {
    case $1 in
        "error") echo -e "${RED}خطأ: $2${NC}" >&2; log "ERROR: $2"; exit 1 ;;
        "success") echo -e "${GREEN}نجاح: $2${NC}"; log "SUCCESS: $2" ;;
        "info") echo -e "${BLUE}معلومات: $2${NC}"; log "INFO: $2" ;;
        "warning") echo -e "${YELLOW}تحذير: $2${NC}"; log "WARNING: $2" ;;
    esac
}

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"; }

check_root() { [[ $EUID -ne 0 ]] && msg "error" "يجب تشغيل السكريبت كـ root"; }

check_kernel() {
    [[ $(uname -r | cut -d "." -f 1) -eq 2 ]] && msg "error" "النواة قديمة جدًا";
    systemd-detect-virt -cq 2>/dev/null && msg "error" "الحاويات غير مدعومة";
}

check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"; os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        [[ "$os_version" -lt 2004 ]] && msg "error" "Ubuntu 20.04+ مطلوب";
    elif [[ -e /etc/debian_version ]]; then
        os="debian"; os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        [[ "$os_version" -lt 11 ]] && msg "error" "Debian 11+ مطلوب";
    elif [[ -e /etc/centos-release ]]; then
        os="centos"; os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
        [[ "$os_version" -lt 8 ]] && msg "error" "CentOS 8+ مطلوب";
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"; os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [[ -e /etc/opensuse-release ]]; then
        os="opensuse"
    else
        msg "error" "نظام غير مدعوم"
    fi
}

check_ip() { [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

detect_public_ip() {
    PUBLIC_IP=$(ip -4 addr | grep inet | grep -v '127' | awk '{print $2}' | cut -d '/' -f 1 | head -1)
    if ! check_ip "$PUBLIC_IP"; then
        PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com)
    fi
    if ! check_ip "$PUBLIC_IP"; then
        read -p "فشل اكتشاف IP العام، أدخله يدويًا: " PUBLIC_IP
        check_ip "$PUBLIC_IP" || msg "error" "IP غير صالح"
    fi
}

install_deps() {
    case $os in
        "ubuntu"|"debian") apt update && apt install -y wireguard qrencode iptables iproute2 ;;
        "centos") yum install -y epel-release && yum install -y wireguard-tools qrencode iptables iproute ;;
        "fedora") dnf install -y wireguard-tools qrencode iptables iproute ;;
        "opensuse") zypper install -y wireguard-tools qrencode iptables iproute2 ;;
    esac
}

setup_firewall() {
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="$WG_PORT"/udp
        firewall-cmd --permanent --zone=trusted --add-source="$IPV4_RANGE".0/24
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$IPV4_RANGE".0/24 ! -d "$IPV4_RANGE".0/24 -j MASQUERADE
        firewall-cmd --reload
    else
        iptables_path=$(command -v iptables)
        [[ $(systemd-detect-virt) == "openvz" ]] && command -v iptables-legacy &>/dev/null && iptables_path=$(command -v iptables-legacy)
        $iptables_path -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        $iptables_path -A FORWARD -i wg0 -j ACCEPT
        $iptables_path -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        $iptables_path -t nat -A POSTROUTING -s "$IPV4_RANGE".0/24 ! -d "$IPV4_RANGE".0/24 -j MASQUERADE
        prevent_dns_leak
    fi
}

prevent_dns_leak() {
    IFS=', ' read -r -a dns_array <<< "$DNS_SERVER"
    iptables -A FORWARD -i wg0 -p udp --dport 53 -j DROP
    for dns in "${dns_array[@]}"; do
        iptables -A FORWARD -i wg0 -p udp --dport 53 -d "$dns" -j ACCEPT
    done
}

enable_bbr() {
    if modprobe tcp_bbr &>/dev/null && [[ $(uname -r) > "4.20" ]]; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        msg "success" "تم تفعيل TCP BBR"
    fi
}

select_dns() {
    echo "اختر خادم DNS:"
    echo "  1) Google (8.8.8.8, 8.8.4.4)"
    echo "  2) Cloudflare (1.1.1.1, 1.0.0.1)"
    echo "  3) OpenDNS (208.67.222.222, 208.67.220.220)"
    echo "  4) AdGuard (94.140.14.14, 94.140.15.15) - حماية من الإعلانات"
    echo "  5) Quad9 (9.9.9.9, 149.112.112.112) - حماية من البرمجيات الخبيثة"
    echo "  6) NextDNS (45.90.28.0, 45.90.30.0) - تصفية متقدمة وقابلة للتخصيص"
    echo "  7) CleanBrowsing (185.228.168.168, 185.228.169.168) - تصفية عائلية"
    echo "  8) مخصص"
    read -p "اختيارك [1]: " dns_choice
    case $dns_choice in
        1|"") DNS_SERVER="8.8.8.8, 8.8.4.4" ;;
        2) DNS_SERVER="1.1.1.1, 1.0.0.1" ;;
        3) DNS_SERVER="208.67.222.222, 208.67.220.220" ;;
        4) DNS_SERVER="94.140.14.14, 94.140.15.15" ;;
        5) DNS_SERVER="9.9.9.9, 149.112.112.112" ;;
        6) DNS_SERVER="45.90.28.0, 45.90.30.0" ;;
        7) DNS_SERVER="185.228.168.168, 185.228.169.168" ;;
        8) read -p "أدخل DNS (مثال: 8.8.8.8 أو 8.8.8.8, 8.8.4.4): " DNS_SERVER ;;
        *) DNS_SERVER="8.8.8.8, 8.8.4.4" ;;
    esac
}

setup_server() {
    read -p "أدخل المنفذ [$WG_PORT]: " port
    WG_PORT=${port:-$WG_PORT}
    wg genkey | tee /etc/wireguard/server_privatekey | wg pubkey > /etc/wireguard/server_publickey
    SERVER_PRIVATE=$(cat /etc/wireguard/server_privatekey)
    SERVER_PUBLIC=$(cat /etc/wireguard/server_publickey)
    cat > "$WG_CONFIG" <<EOF
# ENDPOINT $PUBLIC_IP
[Interface]
PrivateKey = $SERVER_PRIVATE
Address = $IPV4_RANGE.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
    chmod 600 "$WG_CONFIG"
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
}

add_client() {
    local client_name=${1:-$CLIENT_NAME}
    read -p "اسم العميل [$client_name]: " input_name
    client_name=${input_name:-$client_name}
    read -p "عنوان IP (مثال: $IPV4_RANGE.2): " client_ip
    if grep -q "AllowedIPs = $client_ip" "$WG_CONFIG"; then
        msg "error" "العنوان $client_ip مستخدم"
        return
    fi
    wg genkey | tee "$CLIENT_DIR/$client_name.key" | wg pubkey > "$CLIENT_DIR/$client_name.pub"
    wg genpsk > "$CLIENT_DIR/$client_name.psk"
    CLIENT_PRIVATE=$(cat "$CLIENT_DIR/$client_name.key")
    CLIENT_PUBLIC=$(cat "$CLIENT_DIR/$client_name.pub")
    CLIENT_PSK=$(cat "$CLIENT_DIR/$client_name.psk")
    echo -e "\n# BEGIN_PEER $client_name" >> "$WG_CONFIG"
    echo "[Peer]" >> "$WG_CONFIG"
    echo "PublicKey = $CLIENT_PUBLIC" >> "$WG_CONFIG"
    echo "PresharedKey = $CLIENT_PSK" >> "$WG_CONFIG"
    echo "AllowedIPs = $client_ip/32" >> "$WG_CONFIG"
    echo "# END_PEER $client_name" >> "$WG_CONFIG"
    read -p "PersistentKeepalive [$KEEPALIVE]: " keepalive
    KEEPALIVE=${keepalive:-$KEEPALIVE}
    cat > "$CLIENT_DIR/$client_name.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = $client_ip/24
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_PUBLIC
PresharedKey = $CLIENT_PSK
Endpoint = $PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $KEEPALIVE
EOF
    chmod 600 "$CLIENT_DIR/$client_name.conf"
    systemctl restart wg-quick@wg0
    qrencode -t ansiutf8 < "$CLIENT_DIR/$client_name.conf"
    msg "success" "تم إضافة $client_name، التكوين في $CLIENT_DIR/$client_name.conf"
}

list_clients() {
    grep '^# BEGIN_PEER' "$WG_CONFIG" | cut -d ' ' -f 3 | nl -s ') '
    msg "info" "إجمالي العملاء: $(grep -c '^# BEGIN_PEER' "$WG_CONFIG")"
}

remove_client() {
    list_clients
    read -p "اختر العميل للحذف (رقم): " client_num
    client=$(grep '^# BEGIN_PEER' "$WG_CONFIG" | cut -d ' ' -f 3 | sed -n "${client_num}p")
    [[ -z "$client" ]] && msg "error" "اختيار غير صالح"
    sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONFIG"
    rm -f "$CLIENT_DIR/$client.conf" "$CLIENT_DIR/$client.key" "$CLIENT_DIR/$client.pub" "$CLIENT_DIR/$client.psk"
    systemctl restart wg-quick@wg0
    msg "success" "تم حذف $client"
}

show_client_qr() {
    list_clients
    read -p "اختر العميل لعرض QR (رقم): " client_num
    client=$(grep '^# BEGIN_PEER' "$WG_CONFIG" | cut -d ' ' -f 3 | sed -n "${client_num}p")
    [[ -z "$client" ]] && msg "error" "اختيار غير صالح"
    [[ ! -f "$CLIENT_DIR/$client.conf" ]] && msg "error" "ملف تكوين $client مفقود"
    qrencode -t ansiutf8 < "$CLIENT_DIR/$client.conf"
    msg "info" "رمز QR لـ $client معروض أعلاه"
}

remove_wireguard() {
    systemctl stop wg-quick@wg0
    systemctl disable wg-quick@wg0
    rm -rf /etc/wireguard "$CLIENT_DIR"
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --remove-port="$WG_PORT"/udp
        firewall-cmd --permanent --zone=trusted --remove-source="$IPV4_RANGE".0/24
        firewall-cmd --reload
    else
        iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        iptables -D FORWARD -i wg0 -j ACCEPT
        iptables -t nat -D POSTROUTING -s "$IPV4_RANGE".0/24 ! -d "$IPV4_RANGE".0/24 -j MASQUERADE
    fi
    case $os in
        "ubuntu"|"debian") apt remove -y wireguard ;;
        "centos") yum remove -y wireguard-tools ;;
        "fedora") dnf remove -y wireguard-tools ;;
        "opensuse") zypper remove -y wireguard-tools ;;
    esac
    msg "success" "تم إزالة WireGuard"
}

# معالجة خيارات سطر الأوامر
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --auto) AUTO=1; shift ;;
        --addclient) ADD_CLIENT="$2"; shift 2 ;;
        --listclients) LIST_CLIENTS=1; shift ;;
        --removeclient) REMOVE_CLIENT="$2"; shift 2 ;;
        --showclientqr) SHOW_QR="$2"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        --serveraddr) SERVER_ADDR="$2"; shift 2 ;;
        --port) WG_PORT="$2"; shift 2 ;;
        --clientname) CLIENT_NAME="$2"; shift 2 ;;
        --dns1) DNS_SERVER="$2"; shift 2 ;;
        --yes) YES=1; shift ;;
        *) msg "error" "خيار غير معروف: $1"; exit 1 ;;
    esac
done

# التنفيذ بناءً على الخيارات
check_root
check_kernel
check_os
if [[ $ADD_CLIENT ]]; then
    install_deps
    detect_public_ip
    add_client "$ADD_CLIENT"
elif [[ $LIST_CLIENTS ]]; then
    [[ ! -f "$WG_CONFIG" ]] && msg "error" "WireGuard غير مثبت"
    list_clients
elif [[ $REMOVE_CLIENT ]]; then
    [[ ! -f "$WG_CONFIG" ]] && msg "error" "WireGuard غير مثبت"
    client=$REMOVE_CLIENT
    sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONFIG"
    rm -f "$CLIENT_DIR/$client.conf" "$CLIENT_DIR/$client.key" "$CLIENT_DIR/$client.pub" "$CLIENT_DIR/$client.psk"
    systemctl restart wg-quick@wg0
    msg "success" "تم حذف $client"
elif [[ $SHOW_QR ]]; then
    [[ ! -f "$WG_CONFIG" ]] && msg "error" "WireGuard غير مثبت"
    qrencode -t ansiutf8 < "$CLIENT_DIR/$SHOW_QR.conf"
    msg "info" "رمز QR لـ $SHOW_QR"
elif [[ $UNINSTALL ]]; then
    remove_wireguard
elif [[ $AUTO ]]; then
    install_deps
    detect_public_ip
    setup_firewall
    enable_bbr
    setup_server
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    add_client "$CLIENT_NAME"
else
    if [[ -f "$WG_CONFIG" ]]; then
        echo "WireGuard مثبت بالفعل، اختر خيارًا:"
        echo "1) إضافة عميل"
        echo "2) قائمة العملاء"
        echo "3) إزالة عميل"
        echo "4) عرض رمز QR"
        echo "5) إزالة WireGuard"
        read -p "اختيارك: " choice
        case $choice in
            1) add_client ;;
            2) list_clients ;;
            3) remove_client ;;
            4) show_client_qr ;;
            5) remove_wireguard ;;
            *) exit 0 ;;
        esac
    else
        install_deps
        detect_public_ip
        setup_firewall
        enable_bbr
        select_dns
        setup_server
        systemctl enable wg-quick@wg0
        systemctl start wg-quick@wg0
        add_client
    fi
fi

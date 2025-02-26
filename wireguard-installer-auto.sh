#!/bin/bash

# سكريبت تثبيت وإدارة WireGuard محسّن مع وضع افتراضي واختياري


# ضبط umask لضمان أذونات آمنة
umask 077

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
IPV6_RANGE="fd00::"
DNS_SERVER="8.8.8.8,8.8.4.4"
KEEPALIVE=25
PUBLIC_IP=""
SERVER_ADDR=""
CLIENT_NAME="client"
MTU=1420
USE_IPV6=1

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

validate_ipv6() {
    [[ "$1" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || return 1
}

check_kernel() {
    local kernel_version=$(uname -r | cut -d "." -f 1)
    if [[ $kernel_version -lt 3 ]]; then
        msg "error" "النواة قديمة جدًا (مطلوب إصدار 3.x أو أعلى)"
    fi
}

check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"; os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        [[ "$os_version" -lt 2004 ]] && msg "error" "Ubuntu 20.04+ مطلوب"
    elif [[ -e /etc/debian_version ]]; then
        os="debian"; os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        [[ "$os_version" -lt 11 ]] && msg "error" "Debian 11+ مطلوب"
    elif [[ -e /etc/centos-release ]]; then
        os="centos"; os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
        [[ "$os_version" -lt 8 ]] && msg "error" "CentOS 8+ مطلوب"
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
    local attempts=3
    for ((i=1; i<=attempts; i++)); do
        PUBLIC_IP=$(ip -4 addr | grep inet | grep -v '127' | awk '{print $2}' | cut -d '/' -f 1 | head -1)
        if check_ip "$PUBLIC_IP"; then break; fi
        PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com)
        if check_ip "$PUBLIC_IP"; then break; fi
        [[ $i -lt $attempts ]] && sleep 2
    done
    if ! check_ip "$PUBLIC_IP"; then
        while true; do
            read -p "فشل اكتشاف IP العام بعد $attempts محاولات، أدخله يدويًا: " PUBLIC_IP
            if check_ip "$PUBLIC_IP"; then break; fi
            echo -e "${RED}عنوان IP غير صالح، حاول مرة أخرى${NC}"
        done
    fi
}

detect_interface() {
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$DEFAULT_INTERFACE" ]] || ! ip link show "$DEFAULT_INTERFACE" >/dev/null 2>&1; then
        echo -e "${YELLOW}لم يتم اكتشاف واجهة شبكة افتراضية صالحة${NC}"
        while true; do
            read -p "أدخل اسم واجهة الشبكة (مثل eth0 أو ens3): " DEFAULT_INTERFACE
            if ip link show "$DEFAULT_INTERFACE" >/dev/null 2>&1; then break; fi
            echo -e "${RED}الواجهة $DEFAULT_INTERFACE غير موجودة${NC}"
        done
    fi
}

install_deps() {
    echo -e "${YELLOW}جارٍ تثبيت الحزم... [===>]${NC}"
    case $os in
        "ubuntu"|"debian") apt update && apt install -y wireguard qrencode iptables iproute2 ;;
        "centos") yum install -y epel-release && yum install -y wireguard-tools qrencode iptables iproute ;;
        "fedora") dnf install -y wireguard-tools qrencode iptables iproute ;;
        "opensuse") zypper install -y wireguard-tools qrencode iptables iproute2 ;;
    esac
    mkdir -p /etc/wireguard "$CLIENT_DIR"
    chmod 700 /etc/wireguard "$CLIENT_DIR"
    echo -e "${GREEN}تم تثبيت الحزم بنجاح [========>]${NC}"
}

setup_firewall() {
    detect_interface
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="$WG_PORT"/udp
        firewall-cmd --permanent --zone=trusted --add-source="$IPV4_RANGE".0/24
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$IPV4_RANGE".0/24 ! -d "$IPV4_RANGE".0/24 -j MASQUERADE
        [[ $USE_IPV6 -eq 1 ]] && {
            firewall-cmd --permanent --zone=trusted --add-source="$IPV6_RANGE"/64
            firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source address="'"$IPV6_RANGE"'/64" accept'
        }
        firewall-cmd --reload
    else
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        [[ $(systemd-detect-virt) == "openvz" ]] && command -v iptables-legacy &>/dev/null && iptables_path=$(command -v iptables-legacy)
        
        # IPv4 Rules
        $iptables_path -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        $iptables_path -I FORWARD -i wg0 -j ACCEPT
        $iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        $iptables_path -t nat -I POSTROUTING -s "$IPV4_RANGE".0/24 ! -d "$IPV4_RANGE".0/24 -o "$DEFAULT_INTERFACE" -j MASQUERADE

        # IPv6 Rules
        if [[ $USE_IPV6 -eq 1 ]]; then
            $ip6tables_path -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT
            $ip6tables_path -I FORWARD -i wg0 -j ACCEPT
            $ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
            $ip6tables_path -t nat -I POSTROUTING -s "$IPV6_RANGE"/64 -o "$DEFAULT_INTERFACE" -j MASQUERADE
        fi

        # حفظ القواعد
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        fi
    fi
    sysctl -p
}

setup_server() {
    # التحقق من صحة IPv6
    [[ $USE_IPV6 -eq 1 ]] && {
        if ! validate_ipv6 "$IPV6_RANGE"; then
            msg "error" "عنوان IPv6 غير صالح: $IPV6_RANGE"
        fi
    }

    # إنشاء مفاتيح الخادم
    wg genkey | tee /etc/wireguard/server_privatekey | wg pubkey > /etc/wireguard/server_publickey
    [[ -s /etc/wireguard/server_privatekey ]] || msg "error" "فشل إنشاء مفتاح الخادم"
    SERVER_PRIVATE=$(cat /etc/wireguard/server_privatekey)
    SERVER_PUBLIC=$(cat /etc/wireguard/server_publickey)

    # إنشاء تكوين الخادم
    IPV6_ADDRESS="${IPV6_RANGE}1/64"
    cat > "$WG_CONFIG" <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE
Address = $IPV4_RANGE.1/24${USE_IPV6:+, $IPV6_ADDRESS}
ListenPort = $WG_PORT
MTU = $MTU
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT; ip6tables -I FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -i wg0 -j ACCEPT
EOF

    chmod 600 "$WG_CONFIG"
    wg validate "$WG_CONFIG" || msg "error" "تكوين $WG_CONFIG غير صالح"
}

add_client() {
    local client_name=${1:-$CLIENT_NAME}
    local client_ip=""
    local attempts=0

    # إنشاء عنوان IPv4 فريد
    while true; do
        client_ip="$IPV4_RANGE.$((2 + attempts))"
        if ! grep -q "AllowedIPs = $client_ip/32" "$WG_CONFIG"; then
            break
        fi
        ((attempts++))
        [[ $attempts -gt 254 ]] && msg "error" "لا توجد عناوين IPv4 متاحة"
    done

    # إنشاء عناوين IPv6 فريدة
    if [[ $USE_IPV6 -eq 1 ]]; then
        while true; do
            CLIENT_IPV6_ADDRESS="${IPV6_RANGE}$((RANDOM % 9000 + 1000))/128"
            if ! grep -q "$CLIENT_IPV6_ADDRESS" "$WG_CONFIG"; then
                break
            fi
        done
        CLIENT_IPV6_SUBNET="${IPV6_RANGE}$((RANDOM % 9000 + 1000))/64"
    fi

    # إنشاء مفاتيح العميل
    wg genkey | tee "$CLIENT_DIR/$client_name.key" | wg pubkey > "$CLIENT_DIR/$client_name.pub"
    wg genpsk > "$CLIENT_DIR/$client_name.psk"
    CLIENT_PRIVATE=$(cat "$CLIENT_DIR/$client_name.key")
    CLIENT_PUBLIC=$(cat "$CLIENT_DIR/$client_name.pub")
    CLIENT_PSK=$(cat "$CLIENT_DIR/$client_name.psk")

    # إضافة العميل إلى تكوين الخادم
    cat >> "$WG_CONFIG" <<EOF

# BEGIN_PEER $client_name
[Peer]
PublicKey = $CLIENT_PUBLIC
PresharedKey = $CLIENT_PSK
AllowedIPs = $client_ip/32${USE_IPV6:+, $CLIENT_IPV6_ADDRESS}
# END_PEER $client_name
EOF

    # إنشاء تكوين العميل
    cat > "$CLIENT_DIR/$client_name.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = $client_ip/24${USE_IPV6:+, $CLIENT_IPV6_SUBNET}
DNS = $DNS_SERVER
MTU = $MTU

[Peer]
PublicKey = $SERVER_PUBLIC
PresharedKey = $CLIENT_PSK
Endpoint = $PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0${USE_IPV6:+, ::/0}
PersistentKeepalive = $KEEPALIVE
EOF

    systemctl restart wg-quick@wg0
    test_connection "$client_ip"
    msg "success" "تم إضافة $client_name، التكوين في $CLIENT_DIR/$client_name.conf"
}

test_connection() {
    local client_ip=$1
    echo -e "${YELLOW}جارٍ اختبار الاتصال لـ $client_ip... [===>]${NC}"
    
    # اختبار ping لـ IPv4
    if ping -c 3 -W 2 "$client_ip" &>/dev/null; then
        msg "success" "الاتصال بـ $client_ip ناجح"
    else
        msg "warning" "فشل الاتصال بـ $client_ip"
    fi

    # اختبار IPv6 إذا كان مفعلاً
    [[ $USE_IPV6 -eq 1 ]] && {
        if ping6 -c 3 -W 2 "${CLIENT_IPV6_ADDRESS%%/*}" &>/dev/null; then
            msg "success" "الاتصال بـ IPv6 ناجح"
        else
            msg "warning" "فشل الاتصال بـ IPv6"
        fi
    }
}

# باقي الدوال (remove_client, list_clients, etc...) تبقى كما هي مع تعديلات بسيطة

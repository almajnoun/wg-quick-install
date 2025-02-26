#!/bin/bash

# سكريبت متكامل لإدارة WireGuard مع دعم كامل للعملاء وIPv6
# يحتوي على جميع الميزات الأصلية مع تحسينات في الأمان والتنظيم

umask 077 # تأمين أذونات الملفات

# ألوان للواجهة
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# متغيرات التكوين
WG_PORT=51820
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
LOG_FILE="/var/log/wg-manager.log"
IPV4_NET="10.8.0.0/24"
IPV6_NET="fd42:42:42::/64"
DNS_SERVERS="8.8.8.8,8.8.4.4"
ENDPOINT_IP="" # سيتم الكشف التلقائي
DEFAULT_INTERFACE=""

# تسجيل الأحداث
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# إدارة الأخطاء
fatal_error() {
    echo -e "${RED}خطأ شديد: $1${NC}" >&2
    log "FATAL ERROR: $1"
    exit 1
}

# التحقق من صلاحيات root
check_root() {
    [[ $EUID -eq 0 ]] || fatal_error "يجب تشغيل السكريبت كـ root"
}

# الكشف عن نظام التشغيل
detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        echo "ubuntu"
    elif grep -qs "debian" /etc/os-release; then
        echo "debian"
    elif grep -qs "centos" /etc/os-release; then
        echo "centos"
    else
        fatal_error "نظام التشغيل غير مدعوم"
    fi
}

# تثبيت التبعيات
install_dependencies() {
    local os=$(detect_os)
    case $os in
        ubuntu|debian)
            apt update && apt install -y wireguard qrencode iptables
            ;;
        centos)
            yum install -y epel-release
            yum install -y wireguard-tools qrencode
            ;;
    esac || fatal_error "فشل تثبيت الحزم المطلوبة"
}

# تكوين الجدار الناري
configure_firewall() {
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=$WG_PORT/udp
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
        iptables -A FORWARD -i wg0 -j ACCEPT
        iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4
        
        ip6tables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
        ip6tables -A FORWARD -i wg0 -j ACCEPT
        ip6tables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
        ip6tables-save > /etc/iptables/rules.v6
    fi
}

# إنشاء تكوين الخادم
init_server() {
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    
    cat > $WG_CONFIG <<EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = $IPV4_NET, $IPV6_NET
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
EOL
}

# إضافة عميل جديد
add_client() {
    local client_name=$1
    local client_ipv4="${IPV4_NET%.*}.$(($(grep -c '^### Client' $WG_CONFIG) + 2))"
    local client_ipv6=$(printf "%s%04x" "$IPV6_NET" $RANDOM)
    
    # إنشاء المفاتيح
    wg genkey | tee $CLIENT_DIR/$client_name.key | wg pubkey > $CLIENT_DIR/$client_name.pub
    wg genpsk > $CLIENT_DIR/$client_name.psk
    
    # إضافة إلى تكوين الخادم
    cat >> $WG_CONFIG <<EOL

### Client: $client_name
[Peer]
PublicKey = $(cat $CLIENT_DIR/$client_name.pub)
PresharedKey = $(cat $CLIENT_DIR/$client_name.psk)
AllowedIPs = $client_ipv4/32, $client_ipv6/128
EOL

    # إنشاء تكوين العميل
    cat > $CLIENT_DIR/$client_name.conf <<EOL
[Interface]
PrivateKey = $(cat $CLIENT_DIR/$client_name.key)
Address = $client_ipv4/24, $client_ipv6/64
DNS = $DNS_SERVERS

[Peer]
PublicKey = $(cat /etc/wireguard/publickey)
Endpoint = $ENDPOINT_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

    # إنشاء QR code
    qrencode -t ansiutf8 < $CLIENT_DIR/$client_name.conf
    echo -e "${GREEN}تم إنشاء العميل: $CLIENT_DIR/$client_name.conf${NC}"
}

# إزالة عميل
remove_client() {
    local client_name=$1
    sed -i "/### Client: $client_name/,/### Client/d" $WG_CONFIG
    rm -f $CLIENT_DIR/$client_name.*
    echo -e "${YELLOW}تم إزالة العميل: $client_name${NC}"
}

# قائمة العملاء
list_clients() {
    echo -e "${BLUE}العملاء الموجودون:${NC}"
    grep '### Client' $WG_CONFIG | awk '{print $3}'
}

# واجهة المستخدم الرئيسية
main_menu() {
    echo -e "${GREEN}\n==== إدارة WireGuard ====${NC}"
    echo "1) إضافة عميل جديد"
    echo "2) عرض العملاء"
    echo "3) إزالة عميل"
    echo "4) إنشاء QR code"
    echo "5) إزالة السيرفر"
    echo "6) خروج"
    
    read -p "اختر خيارًا: " choice
    case $choice in
        1) read -p "اسم العميل: " name; add_client "$name" ;;
        2) list_clients ;;
        3) read -p "اسم العميل: " name; remove_client "$name" ;;
        4) read -p "اسم العميل: " name; qrencode -t ansiutf8 < "$CLIENT_DIR/$name.conf" ;;
        5) uninstall_server ;;
        6) exit 0 ;;
        *) echo -e "${RED}اختيار غير صالح!${NC}" ;;
    esac
}

# إزالة السيرفر
uninstall_server() {
    rm -rf /etc/wireguard/
    iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT
    ip6tables -D INPUT -p udp --dport $WG_PORT -j ACCEPT
    echo -e "${YELLOW}تم إزالة WireGuard بالكامل${NC}"
}

# التنفيذ الرئيسي
check_root
mkdir -p $CLIENT_DIR
detect_os
install_dependencies
configure_firewall
init_server

# تشغيل الواجهة
while true; do
    main_menu
done

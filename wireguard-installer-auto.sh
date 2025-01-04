#!/bin/bash

# التأكد من تشغيل السكربت كمستخدم root
if [ "$EUID" -ne 0 ]; then
  echo "يرجى تشغيل السكربت كمستخدم root."
  exit 1
fi

# التحقق من التوزيعة المدعومة
if [ -f /etc/debian_version ]; then
  DISTRO="Debian"
  VERSION=$(grep -o "^[0-9]*" /etc/debian_version)
  if [ "$VERSION" -ne 12 ]; then
    echo "هذا السكربت يدعم فقط Debian 12."
    exit 1
  fi
elif [ -f /etc/centos-release ]; then
  DISTRO="CentOS"
  VERSION=$(grep -o "^[0-9]*" /etc/centos-release | head -n1)
  if [ "$VERSION" -lt 8 ]; then
    echo "هذا السكربت يدعم فقط CentOS 8 وما بعده."
    exit 1
  fi
elif [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release; then
  DISTRO="Ubuntu"
  VERSION=$(grep DISTRIB_RELEASE /etc/lsb-release | cut -d= -f2)
  if (( $(echo "$VERSION < 20.04" | bc -l) )); then
    echo "هذا السكربت يدعم فقط Ubuntu 20.04 وما بعده."
    exit 1
  fi
else
  echo "نظام التشغيل غير مدعوم. يدعم السكربت Debian 12، Ubuntu 20.04 وما بعده، وCentOS 8 وما بعده."
  exit 1
fi

# تثبيت الحزم المطلوبة حسب التوزيعة
if [ "$DISTRO" == "Debian" ] || [ "$DISTRO" == "Ubuntu" ]; then
  apt update && apt upgrade -y
  apt install -y wireguard qrencode resolvconf
elif [ "$DISTRO" == "CentOS" ]; then
  yum update -y
  yum install -y epel-release elrepo-release
  yum install -y kmod-wireguard wireguard-tools qrencode
fi

# إنشاء مجلد إعدادات WireGuard إذا لم يكن موجودًا
WG_DIR="/etc/wireguard"
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

# إنشاء مفتاح خاص ومفتاح عام
wg genkey | tee "$WG_DIR/privatekey" | wg pubkey > "$WG_DIR/publickey"

# قراءة المفتاح الخاص والعام
PRIVATE_KEY=$(cat "$WG_DIR/privatekey")
PUBLIC_KEY=$(cat "$WG_DIR/publickey")

# إعداد شبكة WireGuard
SERVER_IP=$(hostname -I | awk '{print $1}')
WG_LOCAL_IP="10.0.0.1/24"
WG_PORT=51820

# قائمة DNS العامة
DNS_OPTIONS=("1.1.1.1" "8.8.8.8" "9.9.9.9" "اختيار مخصص")
echo "اختر DNS لاستخدامه مع العملاء:"
select DNS_CHOICE in "${DNS_OPTIONS[@]}"; do
  case $DNS_CHOICE in
    "1.1.1.1"|"8.8.8.8"|"9.9.9.9")
      DNS_SERVER=$DNS_CHOICE
      break
      ;;
    "اختيار مخصص")
      read -p "أدخل DNS المخصص: " DNS_SERVER
      break
      ;;
    *)
      echo "اختيار غير صالح."
      ;;
  esac
done

# كتابة ملف الإعدادات الخاص بالخادم
cat > "$WG_DIR/wg0.conf" << EOF
[Interface]
Address = $WG_LOCAL_IP
ListenPort = $WG_PORT
PrivateKey = $PRIVATE_KEY
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = sysctl -w net.ipv4.ip_forward=0
EOF

chmod 600 "$WG_DIR/wg0.conf"

# تحسين أداء الاتصال بإعدادات sysctl إضافية
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# تمكين وإعادة تشغيل الخدمة
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# إضافة عميل جديد
add_client() {
  CLIENT_NAME=$1
  CLIENT_IP=$2
  CLIENT_DIR="$WG_DIR/clients/$CLIENT_NAME"

  mkdir -p "$CLIENT_DIR"
  wg genkey | tee "$CLIENT_DIR/privatekey" | wg pubkey > "$CLIENT_DIR/publickey"

  CLIENT_PRIVATE_KEY=$(cat "$CLIENT_DIR/privatekey")
  CLIENT_PUBLIC_KEY=$(cat "$CLIENT_DIR/publickey")

  cat >> "$WG_DIR/wg0.conf" << EOF

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
EOF

  wg syncconf wg0 <(wg-quick strip wg0)

  cat > "$CLIENT_DIR/$CLIENT_NAME.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = $DNS_SERVER

[Peer]
PublicKey = $PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  qrencode -t ansiutf8 < "$CLIENT_DIR/$CLIENT_NAME.conf"
  echo "تم إنشاء ملف الإعداد للعميل: $CLIENT_DIR/$CLIENT_NAME.conf"
}

# إنشاء عميل افتراضي
read -p "أدخل اسم العميل (افتراضي: client1): " CLIENT_NAME
CLIENT_NAME=${CLIENT_NAME:-client1}
read -p "أدخل IP للعميل (افتراضي: 10.0.0.2/32): " CLIENT_IP
CLIENT_IP=${CLIENT_IP:-10.0.0.2/32}
add_client "$CLIENT_NAME" "$CLIENT_IP"

echo "تم إعداد WireGuard بنجاح!"

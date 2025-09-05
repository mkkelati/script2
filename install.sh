#!/bin/bash
# install.sh - Installation script for MK Script Manager (Ubuntu 20.04 - 24.04)

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this installer as root (using sudo)."
  exit 1
fi

echo "=== Installing MK Script Manager ==="
export DEBIAN_FRONTEND=noninteractive
echo "[*] Installing required packages..."
apt-get update -y && apt-get install -y stunnel4 openssl nload bc zip nano awk sed grep

echo "[*] Configuring stunnel service..."
if [[ -f /etc/default/stunnel4 ]]; then
  if grep -qs "ENABLED=0" /etc/default/stunnel4; then
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
  fi
else
  echo 'ENABLED=1' > /etc/default/stunnel4
fi

mkdir -p /etc/stunnel
STUNNEL_CERT="/etc/stunnel/stunnel.pem"
if [[ ! -f "$STUNNEL_CERT" ]]; then
  echo "[*] Generating self-signed SSL certificate for stunnel..."
  openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=MK-Script/OU=IT/CN=$(hostname)" \
    -keyout /etc/stunnel/key.pem -out /etc/stunnel/cert.pem
  cat /etc/stunnel/key.pem /etc/stunnel/cert.pem > "$STUNNEL_CERT"
  chmod 600 "$STUNNEL_CERT"
fi

STUNNEL_CONF="/etc/stunnel/stunnel.conf"
if [[ ! -f "$STUNNEL_CONF" ]]; then
  echo "[*] Setting up stunnel configuration..."
  cat > "$STUNNEL_CONF" << 'EOC'
# stunnel configuration for SSH-SSL tunneling
sslVersion = TLSv1.3
ciphersuites = TLS_AES_256_GCM_SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2
options = NO_COMPRESSION
options = NO_TICKET

[ssh-tunnel]
accept = 443
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
EOC
fi

echo "[*] Starting stunnel service..."
systemctl restart stunnel4
systemctl enable stunnel4

echo "[*] Deploying menu script..."
INSTALL_DIR="/usr/local/bin"
# Download menu.sh from GitHub if not present locally
if [[ ! -f "menu.sh" ]]; then
  echo "[*] Downloading menu.sh from GitHub..."
  wget -q https://raw.githubusercontent.com/mkkelati/mk-script/main/menu.sh
fi
cp -f menu.sh "${INSTALL_DIR}/menu"
chmod +x "${INSTALL_DIR}/menu"

echo "[*] Creating required directories and files..."
mkdir -p /etc/mk-script
mkdir -p /etc/mk-script/senha
mkdir -p /etc/VPSManager
mkdir -p /etc/VPSManager/senha
mkdir -p /etc/security/limits.d
mkdir -p /var/www/html/openvpn

echo "[*] Initializing configuration files..."
touch /etc/mk-script/users.txt
echo "0" > /etc/VPSManager/Exp

echo "[*] Setting proper permissions..."
chmod 755 /etc/mk-script
chmod 700 /etc/mk-script/senha
chmod 700 /etc/VPSManager/senha
chmod 644 /etc/mk-script/users.txt
chmod 644 /etc/VPSManager/Exp

echo "[+] Installation complete. Run 'menu' to start."
echo "[+] Available features:"
echo "    - User Management (Create, Delete, Modify)"
echo "    - Connection Limiting"
echo "    - Online User Monitoring"
echo "    - Network Traffic Monitoring"
echo "    - User Reports"
echo "    - Password Management"
echo "    - SSH-SSL Tunneling (stunnel)"

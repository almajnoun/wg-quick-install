# WireGuard auto Installer and configuration Script

This script allows you to easily install and configure **WireGuard** on Debian 12, Ubuntu 20.04 and later, and CentOS 8 and later systems.

# install

wget https://github.com/almajnoun/wg-quick-install/raw/refs/heads/main/wg-quick-install.sh
   
chmod +x wg-quick-install.sh

sudo ./wg-quick-install.sh --quick

--------------------------------------
# How to Use 

 Initial setup:  
 
 sudo ./wg-quick-install.sh --quick

 Add a user:   
 
 sudo ./wg-quick-install.sh --new-peer example

Interactive and configuration run:  

sudo ./wg-quick-install.sh

Uninstall WireGuard Completely:

sudo ./wg-quick-install.sh --uninstall

--------------------------------------

# For automatic setup with custom options:

sudo ./wg-quick-install.sh --quick --user myclient --dns-primary 1.1.1.1 --dns-secondary 1.0.0.1

Step-by-Step Mode
 Run the script without any arguments to enter an interactive setup:

sudo ./wg-quick-install.sh

# Options Available:
 Quick Setup: Automatically installs WireGuard with default configurations.
 Custom Setup: Allows you to specify server details, ports, user names, and DNS servers.
 Follow the on-screen instructions to complete the process.
 Available Commands

 Usage: sudo ./wireguard-installer-auto.sh [commands]

Commands:
  --new-user [name]         Create a new VPN user
  --dns-primary [IP]        Set primary DNS server (default: 8.8.8.8)
  --dns-secondary [IP]      Set secondary DNS server (optional)
  --show-users              Show all existing users
  --delete-user [name]      Delete a specific user
  --get-qr [name]           Display QR code for a user
  --remove                  Remove WireGuard and all configurations
  -y, --confirm             Skip confirmation prompts for removal
  -h, --info                View this help guide

Setup Commands (optional):
  --quick                   Perform an automated installation
  --endpoint [DNS/IP]       Define VPN endpoint (domain or IPv4)
  --port-num [number]       Set WireGuard port (1-65535, default: 51820)
  --user [name]             Name the first VPN user (default: user)
  --dns-primary [IP]        Primary DNS for the first user
  --dns-secondary [IP]      Secondary DNS for the first user

# WireGuard auto Installer Script

This script allows you to easily install and configure **WireGuard** on Debian 12, Ubuntu 20.04 and later, and CentOS 8 and later systems.


## How to use

wget https://raw.githubusercontent.com/almajnoun/wireguard-installer-auto/main/wireguard-installer-auto.sh
   
chmod +x wireguard-installer-auto.sh
sudo ./wireguard-installer-auto.sh --quick

For automatic setup with custom options:

sudo ./wireguard-installer-auto.sh --quick --user myclient --dns-primary 1.1.1.1 --dns-secondary 1.0.0.1

How to Use
Step-by-Step Mode
Run the script without any arguments to enter an interactive setup:

sudo ./wireguard-installer-auto.sh

Options Available:
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

Practical Examples
Deploy with Default Configuration:

sudo ./wireguard-installer-auto.sh --quick

Add a New VPN User:

sudo ./wireguard-installer-auto.sh --new-user newuser

Remove an Existing User:

sudo ./wireguard-installer-auto.sh --delete-user newuser

Uninstall WireGuard Completely:

sudo ./wireguard-installer-auto.sh --wipe
  

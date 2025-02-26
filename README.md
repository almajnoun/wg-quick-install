# WireGuard auto Installer Script

This script allows you to easily install and configure **WireGuard** on Debian 12, Ubuntu 20.04 and later, and CentOS 8 and later systems.


## How to use

1. Download the script using the command:
2. 
3. bash or
4. 
wget https://raw.githubusercontent.com/almajnoun/wireguard-installer-auto/main/wireguard-installer-auto.sh
   
chmod +x wireguard-installer-auto.sh
sudo ./wireguard-installer-auto.sh

For automatic setup with custom options:

sudo ./wireguard-installer-auto.sh --auto --clientname myclient --dns1 1.1.1.1 --dns2 1.0.0.1

Usage
Interactive Mode
Run the script without arguments to enter interactive mode:

sudo ./wireguard-installer-auto.sh

Choose between Default Mode (fully automated) or Custom Mode (customize settings).
Follow the prompts to configure the server address, port, client name, and DNS.
Command-Line Options

Usage: bash wireguard-installer-auto.sh [options]

Options:
  --addclient [client name]      Add a new client
  --dns1 [DNS server IP]         Primary DNS server for new client (default: 8.8.8.8)
  --dns2 [DNS server IP]         Secondary DNS server for new client (optional)
  --listclients                  List the names of existing clients
  --removeclient [client name]   Remove an existing client
  --showclientqr [client name]   Show QR code for an existing client
  --uninstall                    Remove WireGuard and delete all configuration
  -y, --yes                      Assume "yes" for prompts when removing a client or WireGuard
  -h, --help                     Show this help message and exit

Install Options (optional):
  --auto                         Auto-install WireGuard with default or custom options
  --serveraddr [DNS name or IP]  Server address (FQDN or IPv4)
  --port [number]                Port for WireGuard (1-65535, default: 51820)
  --clientname [client name]     Name for the first WireGuard client (default: client)
  --dns1 [DNS server IP]         Primary DNS server for first client
  --dns2 [DNS server IP]         Secondary DNS server for first client

  Examples
Install with Default Settings:

sudo ./wireguard-installer-auto.sh --auto
Add a New Client:
sudo ./wireguard-installer-auto.sh --addclient newclient
Remove a Client
sudo ./wireguard-installer-auto.sh --removeclient newclient
Uninstall WireGuard:
sudo ./wireguard-installer-auto.sh --uninstall
  

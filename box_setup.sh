#!/bin/bash

# Script Title: HTB VPN and Terminal Setup Helper
# Date: 03/03/2025
# Author: Robboman (Falcon Security)
# GitHub: https://github.com/falconsecurity-io
# Version: 1.0
# Description: This script is intended to automation the initial setup and VPN connection of a Kali machine to use against HTB's platform. Use of alias recommended for easier script init.
# Requirments: Xdotool (https://github.com/jordansissel/xdotool)

# Declare start time elapsed variables
start_time=$(date +%s)

# Define color variables
red='\033[0;31m'
green='\033[0;32m'
nc='\033[0m'

# Check to see if xdotool is installed
if ! command -v xdotool &> /dev/null; then
    printf "${red}xdotool is not installed. Exiting script.${nc}\n"
    printf "${red}run ${green}sudo apt-get install xdotool -y ${red}first.${nc}\n"
    exit 1
fi

# Validate arguments
if [ $# -lt 2 ]; then
    printf "${red}Usage: $0 <platform> [type]${nc}\n"
    printf "${red}Example: setup htb main${nc}\n"
    printf "${red}Example: setup htb academy${nc}\n"
    printf "${red}Example: setup htb prolab${nc}\n"
    exit 1
fi

# Extract arguments
platform=$1
type=$2

# Start VPN
sudo openvpn /mnt/hgfs/share/openvpn/$platform/$type.ovpn

# Terminal commands
sleep 30 #add time to enter username and password
xdotool key alt+shift+s && sleep 0.5 && xdotool type "vpn" && xdotool key Return
xdotool key ctrl+shift+t && sleep 0.5 && xdotool key alt+shift+s && sleep 0.5 && xdotool type "pivot" && xdotool key Return && sleep 0.5 && xdotool key ctrl+shift+d && sleep 0.5 && xdotool type "ligolo -selfcert" && xdotool key Return && sleep 0.5 && xdotool key ctrl+shift+r
xdotool key ctrl+shift+t && sleep 0.5 && xdotool key alt+shift+s && sleep 0.5 && xdotool type "transfer" && xdotool key Return && sleep 0.5 && xdotool key ctrl+shift+r && sleep 0.5 && xdotool key ctrl+shift+r && sleep 0.5 && xdotool key alt+Left && xdotool key alt+Left && sleep 0.5 && xdotool type "http 82 --directory=/home/kali/Transfer" && xdotool key Return && sleep 0.5 && xdotool type "kali" && xdotool key Return && sleep 0.5 && xdotool key ctrl+shift+r && sleep 0.5 && xdotool type "tree Transfer -L 3" && xdotool key Return
xdotool key ctrl+shift+t && sleep 0.5 && xdotool key alt+shift+s && sleep 0.5 && xdotool type "exploits" && xdotool key Return && cd /home/kali/Transfer/exploits
xdotool key ctrl+shift+t && sleep 0.5 && cd ~ && xdotool key alt+shift+s && sleep 0.5 && xdotool type "bloodhound" && xdotool key Return && sleep 0.5 && xdotool key ctrl+shift+d && sleep 0.5 && xdotool type "sudo neo4j start" && xdotool key Return && sleep 0.5 && xdotool type "kali" && xdotool key Return && sleep 7 && xdotool key ctrl+shift+r && sleep 0.5 && xdotool type "bloodhound" && xdotool key Return

end_time=$(date +%s)
duration=$((end_time - start_time))
printf "$green Overall elapsed time: $duration seconds.${nc}\n"

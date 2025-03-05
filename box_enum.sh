#!/bin/bash

# Script Title: HTB Machine Setup and Enumeration Helper
# Date: 03/03/2025
# Author: Robboman (Falcon Security)
# GitHub: https://github.com/falconsecurity-io
# Version: 1.1
# Description: This script is the culmination of my efforts to automate certain repetitive aspects of the initial enumeration of a HTB machine, like directory creation, terminal tab renaming, initial and in-depth nmap scanning, and domain enumeration. This script also prints a selection of enumeration commands for every network port/service identified. There are no autopwn/autoexploit functions or commands in this script, all functionality is intended to enhance manual enumeration and organization. Use of alias recommended for easier script init.
# Requirments: Xdotool (https://github.com/jordansissel/xdotool)

# Declare start time elapsed variables
start_time=$(date +%s)

# Define color variables
black='\033[0;30m'
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
gray='\033[0;37m'
dark_gray='\033[1;30m'
bold_red='\033[1;31m'
bold_green='\033[1;32m'
bold_yellow='\033[1;33m'
bold_blue='\033[1;34m'
bold_magenta='\033[1;35m'
bold_cyan='\033[1;36m'
bold_white='\033[1;37m'
nc='\033[0m'

# Check to see if xdotool is installed
if ! command -v xdotool &> /dev/null; then
    printf "${red}xdotool is not installed. Exiting script.${nc}\n"
    printf "${red}run ${green}sudo apt-get install xdotool -y ${red}first.${nc}\n"
    exit 1
fi

# Validate arguments
if [ $# -lt 4 ]; then
    printf "${red}Usage: $0 <type> <name> <yes/no> <ip1>${nc}\n"
    printf "${red}Explanation: $0 <HTB Platform Type> <Box Name> <Auto Terminal (Xdotool)> <IP>${nc}\n"
    printf "${red}Example: enum main lame yes 10.129.0.1${nc}\n"
    printf "${red}Example: enum academy section no 10.129.0.1${nc}\n"
    exit 1
fi

# Extract arguments
type=$1
name=$2
autoterm=$3
shift 3

# Extract and validate IP addresses
arg_ip_list=""
ip_regex='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
for ip in "$@"; do
    if [[ $ip =~ $ip_regex ]]; then
        if [[ -n "$arg_ip_list" ]]; then
            arg_ip_list+=$'\n'
        fi
        arg_ip_list+="$ip"
    else
        printf "${red}Warning: Invalid IP address format detected - $ip${nc}\n"
        exit 1
    fi
done

# Define functions
function print_header() {
    local header_text="$1"
    local color="$2"
    local include_line="$3"
    local header_length=${#header_text}
    local total_length=80
    local side_length=$(( (total_length - header_length) / 2 ))
    local extra=$(( (total_length - header_length) % 2 ))
    local left_padding=$(printf "%*s" $((side_length)) "" | tr ' ' '-')
    local right_padding=$(printf "%*s" $((side_length + extra)) "" | tr ' ' '-')
    printf "${bold_cyan}%s${color}%s${bold_cyan}%s${nc}\n" "$left_padding" "$header_text" "$right_padding"
    if [[ "$include_line" == "true" ]]; then
        printf "${bold_cyan}%*s${nc}\n" $total_length "" | tr ' ' '-'
    fi
}

function print_time() {
    local message_type="$1"
    local current_date=$(date +"%Y %m %d %H:%M:%S")
    if [ "$message_type" == "start" ]; then
        printf "$pre_info Started at: ${cyan}$current_date${nc}\n"
    elif [ "$message_type" == "end" ]; then
        printf "$pre_info Ended at: ${cyan}$current_date${nc}\n"
    fi
}

function determine_os() {
    if [ -z "$ip" ]; then
        echo "Error: ip variable is not set"
        return 1
    fi
    local ttl
    ttl=$(ping -c 1 "$ip" 2>/dev/null | grep -oP 'ttl=\K\d+')
    if [ -z "$ttl" ]; then
        echo "Error: Could not extract TTL from ping output"
        return 1
    fi
    if ! [[ "$ttl" =~ ^[0-9]+$ ]] || [ "$ttl" -lt 1 ] || [ "$ttl" -gt 255 ]; then
        echo "Error: Invalid TTL value"
        return 1
    fi
    if [ "$ttl" -le 64 ]; then
        os="Linux"
    elif [ "$ttl" -le 128 ]; then
        os="Windows"
    else
        os="Unknown OS"
    fi
}

function http_commands() {
    print_header "Port $port HTTP(S)" "${bold_magenta}" "false"
    print_header "Firefox" "${bold_yellow}" "true"
    printf "${yellow}firefox $url_ip/ &${nc}\n"
    printf "${yellow}firefox $url_domain/ &${nc}\n"
    print_header "cURL" "${bold_yellow}" "true"
    printf "${yellow}curl -i $url_ip/${nc}\n"
    printf "${yellow}curl -i $url_domain/${nc}\n"
    printf "${yellow}curl -s -L $url_ip/ | grep "title\|href" | sed -e 's/^[[:space:]]*//'${nc}\n"
    printf "${yellow}curl -s -L $url_domain/ | grep "title\|href" | sed -e 's/^[[:space:]]*//'${nc}\n"
    printf "${yellow}curl -s $url_ip/ | grep -Eo '(href|src)=".\*"' | sed -r 's/(href|src)=//g' | tr -d '\"' | sort${nc}\n"
    printf "${yellow}curl -s $url_domain/ | grep -Eo '(href|src)=".\*"' | sed -r 's/(href|src)=//g' | tr -d '\"' | sort${nc}\n"
    printf "${yellow}curl -s -L $url_ip/ | html2text -width '99' | uniq${nc}\n"
    printf "${yellow}curl -s -L $url_domain/ | html2text -width '99' | uniq${nc}\n"
    printf "${yellow}curl -s $url_ip/robots.txt | html2text${nc}\n"
    printf "${yellow}curl -s $url_domain/robots.txt | html2text${nc}\n"
    printf "${yellow}curl -s $url_ip/thispagedefinitelydoesnotexist | wc -c${nc}\n"
    printf "${yellow}curl -s $url_domain/thispagedefinitelydoesnotexist | wc -c${nc}\n"
    print_header "Nikto" "${bold_yellow}" "true"
    printf "${yellow}nikto -h $url_ip/${nc}\n"
    printf "${yellow}nikto -h $url_domain/${nc}\n"
    printf "${yellow}nikto -h $ip -p $open_http${nc}\n"
    printf "${yellow}nikto -h $fqdn -p $open_http${nc}\n"
    print_header "WhatWeb" "${bold_yellow}" "true"
    printf "${yellow}whatweb -a 3 $url_ip/${nc}\n"
    printf "${yellow}whatweb -a 3 $url_domain/${nc}\n"
    print_header "FeroxBuster" "${bold_yellow}" "true"
    printf "${yellow}feroxbuster -u $url_ip/ -w $dir_seclists/Discovery/Web-Content/common.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_domain/ -w $dir_seclists/Discovery/Web-Content/common.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_ip/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-small.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_domain/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-small.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_ip/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_domain/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_ip/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-big.txt -C 404${nc}\n"
    printf "${yellow}feroxbuster -u $url_domain/ -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-big.txt -C 404${nc}\n"
    print_header "Ffuf Directories" "${bold_yellow}" "true"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/common.txt:FUZZ -u $url_ip/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/common.txt:FUZZ -u $url_domain/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u $url_ip/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u $url_domain/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u $url_ip/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u $url_domain/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u $url_ip/FUZZ -ic -c -v${nc}\n"
    printf "${yellow}ffuf -w $dir_seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u $url_domain/FUZZ -ic -c -v${nc}\n"
    print_header "Ffuf For Loops" "${bold_yellow}" "true"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/words); do ffuf -u $url_ip/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/words/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/words); do ffuf -u $url_domain/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/words/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/words); do ffuf -u $url_ip/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/words/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/dir); do ffuf -u $url_domain/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/dir/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/dir); do ffuf -u $url_ip/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/dir/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/files); do ffuf -u $url_domain/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/files/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/files); do ffuf -u $url_ip/FUZZ -w $dir_seclists/Discovery/Web-Content/raft/files/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/ext); do ffuf -u $url_domain/index.FUZZ -w $dir_seclists/Discovery/Web-Content/raft/ext/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/raft/ext); do ffuf -u $url_ip/index.FUZZ -w $dir_seclists/Discovery/Web-Content/raft/ext/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/dirs); do ffuf -u $url_domain/index.FUZZ -w $dir_seclists/Discovery/Web-Content/dirs/\$wordlist -ic -c -v; done${nc}\n"
    printf "${yellow}for wordlist in \$(ls -Sr $dir_seclists/Discovery/Web-Content/dirs); do ffuf -u $url_ip/index.FUZZ -w $dir_seclists/Discovery/Web-Content/dirs/\$wordlist -ic -c -v; done${nc}\n"
}

# Create directory variables
dir_seclists="/usr/share/seclists"
dir_impacket="/opt/impacket-0.9.19/examples"
dir_kalitools="/home/$USER/Tools"
dir_kaliscripts="/home/$USER/Scripts"
dir_kalibackup="/home/$USER/Backup"
dir_kalihtb="/home/$USER/HTB"
dir_type="$dir_kalihtb/$type"
dir_name="$dir_type/$name"
dir_exp="$dir_name/exploits"
dir_tool="$dir_name/tools"
dir_loot="$dir_name/loot"
dir_enum="$dir_name/enum"
dir_hist="$dir_name/history"
dir_init="$dir_enum/init"
dir_nmap="$dir_enum/nmap"
dir_burp="$dir_enum/burp"
dir_smb="$dir_enum/smb"
dir_ldap="$dir_enum/ldap"
dir_nfs="$dir_enum/nfs"
dir_http="$dir_enum/http"
dir_eye="$dir_enum/eyewitness"
dir_blood="$dir_enum/bloodhound"
dir_auto="$dir_enum/autorecon"

# Check if directories exist, if not create them
if [ ! -d "$dir_name" ]; then
    mkdir -p $dir_name
fi
if [ ! -d "$dir_exp" ]; then
    mkdir -p $dir_exp
fi
if [ ! -d "$dir_tool" ]; then
    mkdir -p $dir_tool
fi
if [ ! -d "$dir_loot" ]; then
    mkdir -p $dir_loot
fi
if [ ! -d "$dir_enum" ]; then
    mkdir -p $dir_enum
fi
if [ ! -d "$dir_hist" ]; then
    mkdir -p $dir_hist
fi
if [ ! -d "$dir_init" ]; then
    mkdir -p $dir_init
fi
if [ ! -d "$dir_nmap" ]; then
    mkdir -p $dir_nmap
fi
if [ ! -d "$dir_burp" ]; then
    mkdir -p $dir_burp
fi
if [ ! -d "$dir_smb" ]; then
    mkdir -p $dir_smb
fi
if [ ! -d "$dir_ldap" ]; then
    mkdir -p $dir_ldap
fi
if [ ! -d "$dir_nfs" ]; then
    mkdir -p $dir_nfs
fi
if [ ! -d "$dir_http" ]; then
    mkdir -p $dir_http
fi
if [ ! -d "$dir_eye" ]; then
    mkdir -p $dir_eye
fi
if [ ! -d "$dir_blood" ]; then
    mkdir -p $dir_blood
fi
if [ ! -d "$dir_auto" ]; then
    mkdir -p $dir_auto
fi

# Define color prefixes
pre_info="${dark_gray}[${bold_white}/${dark_gray}]${bold_blue}"
pre_cmd="${dark_gray}[${bold_cyan}\$${dark_gray}]${bold_blue}"
pre_out="${dark_gray}[${bold_magenta}=${dark_gray}]${bold_blue}"
pre_fail="${dark_gray}[${bold_red}-${dark_gray}]${bold_blue}"
pre_win="${dark_gray}[${bold_green}+${dark_gray}]${bold_blue}"
pre_warn="${dark_gray}[${bold_yellow}!${dark_gray}]${bold_blue}"

# Write script output to file
exec > >(tee $dir_name/box-$name-output.txt) 2>&1

# Print symbology
print_header "COLOR SYMBOLOGY" "${bold_white}" "true"
printf "$pre_info ${bold_blue}Script Logic${nc}\n"
printf "$pre_info ${bold_cyan}Tool Name${nc}\n"
printf "$pre_info ${bold_white}Tool Syntax${nc}\n"
printf "$pre_info ${bold_magenta}Tool Arguments${nc}\n"
printf "$pre_info ${bold_red}Tool Fail${nc}\n"
printf "$pre_info ${bold_green}Tool Success${nc}\n"
printf "$pre_info ${bold_yellow}Tool Warning${nc}\n"
printf "$pre_info ${yellow}Cheatsheet Command${nc}\n"
printf "$pre_info ${blue}Credentials${nc}\n"
printf "$pre_info ${magenta}Output${nc}\n"
printf "$pre_info ${cyan}System Variables${nc}\n"
printf "$pre_info ${nc}Tool Output${nc}\n"

# Declare empty variables
open_tcp=""
open_udp=""
open_dns=""
open_smb=""
open_ldap=""
open_krb=""
open_http=""
domain_default=""
domain_multi_nmap=""
domain_nmap=""
fqdn_nmap=""
name_nxc=""
domain_nxc=""
dn_domainname=""
dn_tld=""
domain_extraction=""
fqdn_extraction=""
domain=""
fqdn=""
ad=""

# Determine OS
determine_os

# Print box characteristics
print_header "BOX CHARACTERISTICS" "${bold_white}" "true"
printf "$pre_info Box Name: ${magenta}${name^}${nc}\n"
printf "$pre_info Operating System: ${magenta}$os${nc}\n"
printf "$pre_info IP Address: ${magenta}$ip${nc}\n"
printf "$pre_info Auto Terminal Tab Creation: ${magenta}${autoterm^}${nc}\n"

# Run initial scans
print_header "INITIAL TCP SCAN" "${bold_white}" "true"
print_time "start"
printf "$pre_info Tool: ${bold_cyan}Nmap${nc}\n"
scan_tcp_init="sudo nmap -Pn -n -v -T4 -p- --open $ip -oN /nmap_open_tcp"
printf "$pre_info Type: ${bold_magenta}All TCP Ports${nc}\n"
printf "$pre_cmd Command: ${yellow}$scan_tcp_init${nc}\n"
eval $scan_tcp_init
print_time "end"

print_header "INITIAL UDP SCAN" "${bold_white}" "true"
print_time "start"
printf "$pre_info Tool: ${bold_cyan}Nmap${nc}\n"
scan_udp_init="sudo nmap -Pn -v -sU --min-rate=100 --max-retries=2 --open $ip -oN /nmap_open_udp"
printf "$pre_info Type: ${bold_magenta}Top 1000 UDP Ports${nc}\n"
printf "$pre_cmd Command: ${yellow}$scan_udp_init${nc}\n"
eval $scan_udp_init
print_time "end"

# Extract open ports from initial scans
open_tcp=$(grep -oP '\d+/(tcp|udp)\s*open' $dir_nmap/nmap_open_tcp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
open_udp=$(grep -oP '\d+/(tcp|udp)\s*open' $dir_nmap/nmap_open_udp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

# Run comprehensive scans
print_header "COMPREHENSIVE TCP SCAN" "${bold_white}" "true"
print_time "start"
printf "$pre_info Tool: ${bold_cyan}Nmap${nc}\n"
printf "$pre_info Type: ${bold_magenta}Open TCP Ports${nc}\n"
scan_tcp_comp="sudo nmap -Pn -v -sCV -T4 -p $open_tcp $ip -oN $dir_nmap/nmap_scan_tcp"
printf "$pre_cmd Command: ${yellow}$scan_tcp_comp${nc}\n"
if [ ! -z "$open_tcp" ]; then
    eval $scan_tcp_comp
    printf "$pre_win Scan successful.${nc}\n"
    print_time "end"
else
    printf "$pre_fail No ${bold_magenta}open TCP ${bold_blue}ports found. Skipping comprehensive TCP scan and moving to next step.${nc}\n"
    if [ ! -s "$dir_nmap/nmap_scan_tcp" ]; then
        sudo touch $dir_nmap/nmap_scan_tcp
    fi
    print_time "end"
fi

print_header "COMPREHENSIVE UDP SCAN" "${bold_white}" "true"
print_time "start"
printf "$pre_info Tool: ${bold_cyan}Nmap${nc}\n"
printf "$pre_info Type: ${bold_magenta}Open UDP Ports${nc}\n"
scan_udp_comp="sudo nmap -Pn -v -sU -sCV --min-rate=100 --max-retries=2 -p $open_udp $ip -oN $dir_nmap/nmap_scan_udp"
printf "$pre_cmd Command: ${yellow}$scan_udp_comp${nc}\n"
if [ ! -z "$open_udp" ]; then
    eval $scan_udp_comp
    printf "$pre_win Scan successful.${nc}\n"
    print_time "end"
else
    printf "$pre_fail No ${bold_magenta}open UDP ${bold_blue}ports found. Skipping comprehensive TCP scan and moving to next step.${nc}\n"
    if [ ! -s "$dir_nmap/nmap_scan_udp" ]; then
        sudo touch $dir_nmap/nmap_scan_udp
    fi
    print_time "end"
fi

# Extract ports from comprehensive scans and print open ports
print_header "PORTS DETECTED" "${bold_white}" "true"
open_dns=$((grep -q '53/tcp\s*open' $dir_nmap/nmap_open_tcp && echo "53/tcp"; grep -q '53/udp\s*open' $dir_nmap/nmap_open_udp && echo "53/udp") | tr '\n' ',' | sed 's/,$//')
open_smb=$(grep -E '^(139/tcp|445/tcp)\s+open' $dir_nmap/nmap_open_tcp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
open_ldap=$(grep -E '^(389/tcp|636/tcp)\s+open' $dir_nmap/nmap_open_tcp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
open_krb=$(grep -E '^(88/tcp|464/tcp)\s+open' $dir_nmap/nmap_open_tcp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
open_http=$(grep -E '^(443/tcp|80/tcp|8080/tcp|8000/tcp|8443/tcp|8888/tcp|8081/tcp|81/tcp|8008/tcp|82/tcp)\s+open' $dir_nmap/nmap_open_tcp | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
if [ -n "$open_tcp" ]; then
    printf "$pre_info Open TCP ports: ${magenta}$open_tcp${bold_blue}${nc}\n"
else
    printf "$pre_info Open TCP ports: ${nc}None${nc}\n"
fi
if [ -n "$open_udp" ]; then
    printf "$pre_info Open UDP ports: ${magenta}$open_udp${bold_blue}${nc}\n"
else
    printf "$pre_info Open UDP ports: ${nc}None${nc}\n"
fi
if [ -n "$open_dns" ]; then
    printf "$pre_info Open DNS ports: ${magenta}$open_dns${bold_blue}${nc}\n"
else
    printf "$pre_info Open DNS ports: ${nc}None${nc}\n"
fi
if [ -n "$open_smb" ]; then
    printf "$pre_info Open SMB ports: ${magenta}$open_smb${bold_blue}${nc}\n"
else
    printf "$pre_info Open SMB ports: ${nc}None${nc}\n"
fi
if [ -n "$open_ldap" ]; then
    printf "$pre_info Open LDAP ports: ${magenta}$open_ldap${bold_blue}${nc}\n"
else
    printf "$pre_info Open LDAP ports: ${nc}None${nc}\n"
fi
if [ -n "$open_krb" ]; then
    printf "$pre_info Open KRB ports: ${magenta}$open_krb${bold_blue}${nc}\n"
else
    printf "$pre_info Open KRB ports: ${nc}None${nc}\n"
fi
if [ -n "$open_http" ]; then
    printf "$pre_info Open HTTP ports: ${magenta}$open_http${bold_blue}${nc}\n"
    printf "$pre_warn Double check for other HTTP ports!${nc}\n"
else
    printf "$pre_info Open HTTP ports: ${nc}None${nc}\n"
    printf "$pre_warn Double check for other HTTP ports!${nc}\n"
fi

# Enumerate domain and fqdn information
print_header "DOMAIN/FQDN ENUMERATION" "${bold_white}" "true"
print_time "start"
printf "$pre_info Tool: ${bold_cyan}NetExec (NXC)${nc}\n"
printf "$pre_info Type: ${bold_magenta}SMB Mode Domain Info Enum${nc}\n"
printf "$pre_cmd Command: ${yellow}nxc smb $ip -u '' -p ''${nc}\n"
if [ ! -z "$open_smb" ]; then
    nxc smb $ip -u '' -p '' | tee -a $dir_init/nxc_domain
    printf "$pre_win Command ran successfully.${nc}\n"
else
    printf "$pre_fail Server does ${bold_red}not${bold_blue} have an ${bold_magenta}open SMB ${bold_blue}port. Skipping domain enumeration.${nc}\n"
    sudo touch $dir_init/nxc_domain
fi

# Set domain variables
# Set default domain based on scan type
domain_default="$name.htb"

# Set nmap greps based on scan type
######## This likely needs work
domain_multi_nmap=$(grep -oPi '\b[a-z0-9-]+\.[a-z]{2,}\b' "$dir_nmap/nmap_scan_tcp" | sort -u | awk '{print tolower($0)}')
domain_nmap=$(grep -oPi '\b[a-z0-9-]+\.[a-z]{2,}\b' "$dir_nmap/nmap_scan_tcp" | sort -u | head -n 1 | awk '{print tolower($0)}')
fqdn_nmap=$(grep -oPi '\b((?:(?:[a-z0-9-]+\.)+[a-z]{2,}))\b' "$dir_nmap/nmap_scan_tcp" | sort -u | head -n 1 | awk '{print tolower($0)}')

# Set nxc greps
name_nxc=$(grep -oPi '(?<=name:)[^)]+' "$dir_init/nxc_domain" | sort -u | head -n 1 | awk '{print tolower($0)}')
domain_nxc=$(grep -oPi '(?<=domain:)[^)]+'  "$dir_init/nxc_domain" | sort -u | head -n 1 | awk '{print tolower($0)}')
dn_domainname=$(echo ${domain_nxc%%.*} | awk '{print toupper($0)}')
dn_tld=$(echo ${domain_nxc#*.}| awk '{print toupper($0)}')
if [ ! -z "$name_nxc" ] || [ ! -z "$domain_nxc" ]; then
    fqdn_nxc="$name_nxc.$domain_nxc"
    echo -e "$domain_multi_nmap\n$domain_nxc" | sort -u | sed '/^$/d' > "$dir_init/domain_extraction"
    echo -e "$fqdn_nmap\n$fqdn_nxc" | sort -u | sed '/^$/d' > "$dir_init/fqdn_extraction"
else
    echo -e "$domain_multi_nmap\n$domain_nxc" | sort -u | sed '/^$/d' > "$dir_init/domain_extraction"
    echo -e "$fqdn_nmap" | sort -u | sed '/^$/d' > "$dir_init/fqdn_extraction"
fi
domain_extraction="$dir_init/domain_extraction"
fqdn_extraction="$dir_init/fqdn_extraction"
# Set blank final domain variables for further processing
domain=""
fqdn=""

# Check variables to determine domain and FQDN
if [ -s "$domain_extraction" ] || [ -s "$fqdn_extraction" ]; then
    domain=$(cat $domain_extraction | sort -u | head -n 1 | awk '{print tolower($0)}')
    fqdn=$(cat $fqdn_extraction | sort -u | head -n 1 | awk '{print tolower($0)}')
    printf "$pre_win This machine is likely part of an Active Directory domain!${nc}\n"
    printf "$pre_info Domain Name: ${magenta}$domain${nc}\n"
    printf "$pre_info FQDN: ${magenta}$fqdn${nc}\n"
    if [ -n "$open_dns" ]; then
        printf "$pre_info Tool: ${bold_cyan}nslookup${nc}\n"
        printf "$pre_info Type: ${bold_magenta}DNS Query LDAP Domain Controller${nc}\n"
        printf "$pre_cmd Command: ${yellow}nslookup -type=SRV _ldap._tcp.dc._msdcs.$domain $ip${nc}\n"
        nslookup -type=SRV _ldap._tcp.dc._msdcs.$domain $ip > $dir_init/output_nslookup
        dc=$(grep -oP 'service = \d+ \d+ \d+ \K[^ ]+' $dir_init/output_nslookup | sed 's/\.$//' | awk '{print tolower($0)}')
        if [ ! -z "$dc" ]; then
            if [ "$dc" = "$fqdn" ]; then
                printf "$pre_win This machine is likely an Active Directory Domain Controller. FQDN: ${magenta}$dc${nc}\n"
                ad="true"
            else
                printf "$pre_info Active Directory Domain Controller FQDN: ${magenta}$dc${nc}\n"
                ad="true"
            fi
        else
            printf "$pre_fail Unable to determine if this is an Active Directory Domain Controller${nc}\n"
            ad="true"
        fi
    else
        printf "$pre_fail This machine is ${bold_red}not${bold_blue} a Windows machine or does ${bold_red}not${bold_blue} have an open DNS port. Skipping domain controller enumeration.${nc}\n"
        ad="true"
    fi
else
    domain=$domain_default
    fqdn=$domain_default
    printf "$pre_fail Unable to extract domain, FQDN, and Active Directory information from scans, using default domain name based on machine name.${nc}\n"
    printf "$pre_info Domain Name: ${magenta}$domain${nc}\n"
    printf "$pre_info FQDN: ${magenta}$fqdn${nc}\n"
    ad="false"
fi
print_time "end"

# Dump domain debug information
print_header "DOMAIN DEBUG INFORMATION" "${bold_white}" "true"
printf "$pre_warn Dumping Domain Debug Information${nc}\n"
printf "$pre_info Default Domain Name (Based on scan type): ${magenta}$domain_default${nc}\n"
printf "$pre_info Nmap Domain Names: ${magenta}$domain_multi_nmap${nc}\n"
printf "$pre_info Nmap Domain Name (Sorted, Top): ${magenta}$domain_nmap${nc}\n"
printf "$pre_info Nmap FQDN: ${magenta}$fqdn_nmap${nc}\n"
printf "$pre_info NXC Domain Name: ${magenta}$domain_nxc${nc}\n"
printf "$pre_info NXC Hostname: ${magenta}$name_nxc${nc}\n"
printf "$pre_info NXC FQDN: ${magenta}$fqdn_nxc${nc}\n"
printf "$pre_info NXC Domain (DN): ${magenta}$dn_domainname${nc}\n"
printf "$pre_info NXC TLD (DN): ${magenta}$dn_tld${nc}\n"
printf "$pre_info Domain: ${magenta}$domain${nc}\n"
printf "$pre_info FQDN: ${magenta}$fqdn${nc}\n"
printf "$pre_info Active Directory: ${magenta}${ad^}${nc}\n"

# Print IP and FQDN to file
echo "$ip $fqdn" >> $dir_name/hosts

# Print commands for manual port enumeration
print_header "PORT ENUMERATION COMMANDS" "${bold_white}" "true"
print_header "TCP PORTS" "${bold_magenta}" "true"
IFS=',' read -r -a ports_tcp <<< "$open_tcp"
for port in "${ports_tcp[@]}"; do
    if [ "$port" -eq 21 ]; then
        print_header "Port $port FTP" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script ftp-* -p 21 $ip${nc}\n"
        print_header "Wget" "${bold_yellow}" "true"
        printf "${yellow}wget -m [--no-passive] ftp://anonymous:anonymous@$ip${nc}\n"
        printf "${yellow}wget -r --user=${blue}username${yellow} --password=${blue}password${yellow} ftp://$ip/${nc}\n"
        print_header "Browser" "${bold_yellow}" "true"
        printf "${yellow}firefox ftp://anonymous:anonymous@$ip/ &${nc}\n"
        print_header "FTP Client" "${bold_yellow}" "true"
        printf "${yellow}ftp $ip${nc}\n"
        printf "Anonymous Login:${nc}\n"
        printf "username: anonymous, password: press enter${nc}\n"
        printf "Commands:${nc}\n"
        printf "help, [list|ls] -R, get Important\ Notes.txt, put test.txt, type i (switch to binary), ascii, binary${nc}\n"
        print_header "Brute Force" "${bold_yellow}" "true"
        printf "${yellow}hydra -t 4 -l ${blue}username${yellow} -P /usr/share/wordlists/rockyou.txt -vV $ip ftp${nc}\n"
        printf "${yellow}medusa -u ${blue}username${yellow} -P /usr/share/wordlists/rockyou.txt -h $ip -M ftp${nc}\n"
    elif [ "$port" -eq 22 ] || [ "$port" -eq 2222 ]; then
        print_header "Port $port SSH" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script ssh-* -p $port $ip${nc}\n"
        print_header "SSH Audit" "${bold_yellow}" "true"
        printf "${yellow}ssh-audit $ip:$port${nc}\n"s
        print_header "SSH Client" "${bold_yellow}" "true"
        printf "${yellow}ssh ${blue}username${yellow}@$ip${nc}\n"
        printf "${yellow}ssh -i id_rsa ${blue}username${yellow}@$ip${nc}\n"
        print_header "Brute Force" "${bold_yellow}" "true"
        printf "${yellow}hydra -l ${blue}username${yellow} -P ${magenta}enum/passwords${yellow} -t 32 -s $port $ip -S -vV ssh${nc}\n"
    elif [ "$port" -eq 25 ] || [ "$port" -eq 465 ] || [ "$port" -eq 587 ]; then
        print_header "Port $port SMTP" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script smtp-* -p $port $ip${nc}\n"
        print_header "SMTP User Enum" "${bold_yellow}" "true"
        printf "${yellow}smtp-user-enum -M [VRFY|EXPN|RCPT] -U ${magenta}enum/usernames${yellow} -D $domain -t $ip${nc}\n"
        print_header "Brute Force" "${bold_yellow}" "true"
        printf "${yellow}hydra -l ${blue}username${yellow} -P ${magenta}enum/passwords${yellow} -s $port $ip -S -vV${nc}\n"
    elif [ "$port" -eq 53 ]; then
        print_header "Port $port DNS" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' $ip${nc}\n"
        print_header "Dig" "${bold_yellow}" "true"
        printf "${yellow}dig version.bind CHAOS TXT @$ip${nc}\n"
        printf "${yellow}dig -x x.x.x.x @$ip${nc}\n"
        printf "${yellow}dig @$ip $domain ANY +nocmd +noall +answer +multiline${nc}\n"
        printf "${yellow}dig -x 2a00:1450:400c:c06::93 @$ip${nc}\n"
        print_header "Zone Transfer" "${bold_yellow}" "true"
        printf "${yellow}dig @$ip $domain AXFR +nocmd +noall +answer +multiline${nc}\n"
        printf "${yellow}fierce --domain $domain --dns-servers $ip${nc}\n"
        print_header "DNSEnum" "${bold_yellow}" "true"
        printf "${yellow}dnsenum --dnsserver $ip --enum -p 0 -s 0 -o ${magenta}enum/dnsenum_sub${yellow} -f $dir_seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain${nc}\n"
        print_header "DNSRecon" "${bold_yellow}" "true"
        printf "${yellow}dnsrecon -r 127.0.0.0/24 -n $ip -d $domain${nc}\n"
        print_header "Dig Bash 1L" "${bold_yellow}" "true"
        printf "${yellow}for sub in \$(cat $dir_seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.$domain @$ip | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a ${magenta}enum/subdomains${yellow};done${nc}\n"
    elif [ "$port" -eq 88 ] || [ "$port" -eq 464 ]; then
        print_header "Port $port Kerberos" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script krb5-* -p $port $ip${nc}\n"
        print_header "Kerbrute" "${bold_yellow}" "true"
        printf "${yellow}kerbrute userenum -d $domain --dc $ip ${magenta}enum/usernames${yellow}${nc}\n"
        printf "${yellow}sudo kerbrute userenum -d $domain --dc $ip $dir_init/usernames --hash-file $dir_init/kerbrute_asrep -t 20${nc}\n"
        printf "${yellow}sudo kerbrute userenum -d $domain --dc $ip $dir_init/usernames --downgrade --hash-file $dir_init/kerbrute_asrep -t 20${nc}\n"
        print_header "Username Extraction" "${bold_yellow}" "true"
        printf "awk -F'\t' '/VALID USERNAME:/ {split(\$2, a, "@"); print a[1]}' kerbrute_output | sort -u > valid_users${nc}\n"
        printf "awk -F'\t' '/VALID USERNAME:/ {print \$2}' kerbrute_output | sort -u > valid_emails${nc}\n"
        print_header "Impacket" "${bold_yellow}" "true"
        printf "${yellow}GetUserSPNs.py -request -dc-ip $ip $domain/${blue}username${yellow}:${blue}password${yellow} -outputfile enum/output_getuserspns${nc}\n"
        printf "${yellow}GetUserSPNs.py -request -dc-ip $ip -hashes ${blue}lm:nthash${yellow}$domain/${blue}username${yellow} -outputfile enum/output_getuserspns${nc}\n"
        printf "${yellow}GetNPUsers.py $domain/ -dc-ip $ip -usersfile valid_users -format hashcat 2> /dev/null | grep -v 'Kerberos SessionError:'${nc}\n"
    elif [ "$port" -eq 110 ] || [ "$port" -eq 995 ]; then
        print_header "Port $port POP3" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script 'pop3-capabilities or pop3-ntlm-info' -sV -p $port $ip${nc}\n"
        print_header "0365 Spray" "${bold_yellow}" "true"
        printf "${yellow}python3 o365spray.py --validate --domain $domain${nc}\n"
        printf "${yellow}python3 o365spray.py --enum -U ${magenta}enum/usernames${yellow} --domain $domain${nc}\n"
        printf "${yellow}python3 o365spray.py --spray -U ${magenta}enum/valid_users${yellow} -p ${blue}password${yellow} --count 1 --lockout 1 --domain $domain${nc}\n"
        print_header "Brute Force" "${bold_yellow}" "true"
        printf "${yellow}hydra -L ${magenta}enum/usernames${yellow} -p ${blue}password${yellow} -f $ip pop3${nc}\n"
    elif [ "$port" -eq 135 ] || [ "$port" -eq 593 ]; then
        print_header "Port $port RPC" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script rpcinfo -p $port $ip${nc}\n"
        print_header "Impacket" "${bold_yellow}" "true"
        printf "${yellow}wmiexec.py $domain/${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}dcomexec.py -object [MMC20|ShellWindows|ShellBrowserWindow] $domain/${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}rpcdump.py $ip -p $port${nc}\n"
    elif [ "$port" -eq 137 ] || [ "$port" -eq 138 ] || [ "$port" -eq 139 ]; then
        print_header "Port $port NetBIOS" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script nbstat -p $port $ip${nc}\n"
        print_header "NMBLookup" "${bold_yellow}" "true"
        printf "${yellow}nmblookup -A $ip${nc}\n"
        print_header "NBTScan" "${bold_yellow}" "true"
        printf "${yellow}nbtscan $ip/30${nc}\n"
    elif [ "$port" -eq 139 ] || [ "$port" -eq 445 ]; then
        print_header "Port $port SMB" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script smb-* -p $port $ip${nc}\n"
        print_header "SMBClient" "${bold_yellow}" "true"
        printf "${yellow}smbclient -N -L //$ip${nc}\n"
        printf "${yellow}smbclient -N //$ip/share${nc}\n"
        printf "${yellow}smbclient //$fqdn/sharename -U $dn_domainname\\\\${blue}username${nc}\n"
        printf "${yellow}smbclient -U ${blue}username${yellow}%%${blue}password${yellow} //$ip/share${nc}\n"
        printf "${yellow}smbclient -U ${blue}username${yellow}%%${blue}nthash${yellow} --pw-nt-hash //$ip/share${nc}\n"
        print_header "RPCClient" "${bold_yellow}" "true"
        printf "${yellow}rpcclient -U '' -N $ip${nc}\n"
        printf "${yellow}rpcclient -U '%%' $ip${nc}\n"
        printf "${yellow}rpcclient -U ${blue}username${yellow}:${blue}password${yellow} $ip${nc}\n"
        printf "${yellow}rpcclient -U $domain/${blue}username${yellow}%%${blue}nthash${yellow} --pw-nt-hash //$ip${nc}\n"
        print_header "Mount Share CIFS" "${bold_yellow}" "true"
        printf "${yellow}sudo mkdir -p $dir_smb/share${nc}\n"
        printf "${yellow}sudo mount -t cifs -o username=${blue}username${yellow},password=${blue}password${yellow},domain=$domain //$ip/share $dir_smb/share; cd $dir_smb/share${nc}\n"
        printf "${yellow}sudo mount -t cifs //$ip/share $dir_smb/share -o credentials=${blue}cred_file${yellow}${nc}\n"
        print_header "Impacket" "${bold_yellow}" "true"
        printf "${yellow}wmiexec.py ${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}wmiexec.py -hashes ${blue}lm:nthash${yellow} ${blue}username${yellow}@$ip${nc}\n"
        printf "${yellow}psexec.py ${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}psexec.py -hashes ${blue}lm:nthash${yellow} ${blue}username${yellow}@$ip${nc}\n"
        printf "${yellow}dcomexec.py ${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}dcomexec.py -hashes ${blue}lm:nthash${yellow} ${blue}username${yellow}@$ip${nc}\n"
        printf "${yellow}atexec.py ${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}atexec.py -hashes ${blue}lm:nthash${yellow} ${blue}username${yellow}@$ip${nc}\n"
        printf "${yellow}samrdump.py -port $port $DOMAIN/${blue}username${yellow}:${blue}password${yellow}@$ip${nc}\n"
        printf "${yellow}samrdump.py $ip${nc}\n"
        printf "${yellow}reg.py $domain/${blue}username${yellow}@$ip -hashes ${blue}lm:nthash${yellow} query -keyName HKLM -s${nc}\n"
        print_header "NetExec (NXC)" "${bold_yellow}" "true"
        printf "${yellow}nxc smb $ip -u 'a' -p '' --users${nc}\n"
        printf "${yellow}nxc smb $ip -u '' -p '' --users${nc}\n"
        printf "${yellow}nxc smb $ip -u 'a' -p '' --shares${nc}\n"
        printf "${yellow}nxc smb $ip -u '' -p '' --shares${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${magenta}enum/passwords${yellow} --continue-on-success${nc}\n"
        printf "${yellow}nxc smb $ip -u ${magenta}enum/usernames${yellow} -p ${magenta}enum/passwords${yellow} --continue-on-success${nc}\n"
        printf "${yellow}nxc smb $ip -u ${magenta}enum/usernames${yellow} -p ${magenta}enum/passwords${yellow} --local-auth --continue-on-success${nc}\n"
        printf "${yellow}nxc smb $ip -u ${magenta}enum/usernames${yellow} -H ${blue}nthash${yellow}${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${blue}password${yellow} --shares --local-auth${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${blue}password${yellow} -M spider_plus --share share${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${blue}password${yellow} --local-auth -x 'whoami' --exec-method smbexec${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${blue}password${yellow} --local-auth --loggedon-users${nc}\n"
        printf "${yellow}nxc smb $ip -u ${blue}username${yellow} -p ${blue}password${yellow} --local-auth --sam${nc}\n"
        print_header "SMBMap" "${bold_yellow}" "true"
        printf "${yellow}smbmap -H $ip${nc}\n"
        printf "${yellow}smbmap -u ${blue}username${yellow} -p ${blue}password${yellow} -H $ip -P $port${nc}\n"
        printf "${yellow}smbmap -u ${blue}username${yellow} -p ${blue}lt:nthash${yellow} -H $ip -P $port${nc}\n"
        printf "${yellow}smbmap -R dir -H $ip -u ${blue}username${yellow} -p ${blue}password${yellow}${nc}\n"
        printf "${yellow}smbmap -H $ip --download share file${nc}\n"
        printf "${yellow}smbmap -H $ip --upload file share${nc}\n"
        print_header "Enum4Linux NG" "${bold_yellow}" "true"
        printf "${yellow}enum4linux -a $ip${nc}\n"
        printf "${yellow}enum4linux-ng $ip -A${nc}\n"
        printf "${yellow}enum4linux-ng $ip -A -C${nc}\n"
        printf "${yellow}enum4linux-ng -U $ip | grep 'username:' | awk '{print $2}' | sort -u${nc}\n"
    elif [ "$port" -eq 143 ] || [ "$port" -eq 993 ]; then
        print_header "Port $port IMAP" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script imap-* -p $port $ip${nc}\n"
        print_header "cUrl" "${bold_yellow}" "true"
        printf "${yellow}curl -k 'imap://$ip' --user ${blue}username${yellow}:${blue}password${yellow} -v${nc}\n"
        printf "${yellow}curl -k 'imaps://$ip:993' --user ${blue}username${yellow}:${blue}password${yellow} -v${nc}\n"
        print_header "OpenSSL" "${bold_yellow}" "true"
        printf "${yellow}openssl s_client -connect $ip:imaps${nc}\n"
    elif [ "$port" -eq 161 ] || [ "$port" -eq 162 ] || [ "$port" -eq 10161 ] || [ "$port" -eq 10162 ]; then
        print_header "Port $port SNMP" "${bold_magenta}" "false"
        print_header "Brute Force MIB Values" "${bold_yellow}" "true"
        printf "${yellow}onesixtyone -c $dir_seclists/Discovery/SNMP/snmp.txt $ip${nc}\n"
        printf "${yellow}onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt $ip${nc}\n"
        printf "${yellow}hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $ip snmp${nc}\n"
        print_header "SNMPWalk" "${bold_yellow}" "true"
        printf "${yellow}snmpwalk -v 2c -c public $ip .1${nc}\n"
        printf "${yellow}snmpwalk -v 2c -c public $ip 1.3.6.1.2.1.4.34.1.3${nc}\n"
        printf "${yellow}snmpwalk -v X -c public $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull${nc}\n"
        print_header "Braa" "${bold_yellow}" "true"
        printf "${yellow}braa <community string>@$ip:.1.3.6.*${nc}\n"
        print_header "MIB Values" "${bold_yellow}" "true"
        printf "1.3.6.1.2.1.25.1.6.0 - System Processes${nc}\n"
        printf "1.3.6.1.2.1.25.4.2.1.2 - Running Programs${nc}\n"
        printf "1.3.6.1.2.1.25.4.2.1.4 - Processes Path${nc}\n"
        printf "1.3.6.1.2.1.25.2.3.1.4 - Storage Units${nc}\n"
        printf "1.3.6.1.2.1.25.6.3.1.2 - Software Name${nc}\n"
        printf "1.3.6.1.4.1.77.1.2.25 - User Accounts${nc}\n"
        printf "1.3.6.1.2.1.6.13.1.3 - TCP Local Ports${nc}\n"
    elif [ "$port" -eq 389 ]; then
        print_header "Port $port LDAP" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script ldap-* $ip${nc}\n"
        print_header "LDAPSearch" "${bold_yellow}" "true"
        printf "${yellow}ldapsearch -H ldap://$domain/ -x -s base -b '' '(objectClass=*)' '*'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldap://$fqdn/ -x -b 'CN=Users,DC=$dn_domainname,DC=$dn_tld' ${nc}\n"
        printf "${yellow}ldapsearch -x -H ldap://$ip -D '' -w '' -b 'DC=$dn_domainname,DC=$dn_tld'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldap://$ip -D $domain\\\\${blue}username${yellow} -w ${blue}password${yellow} -b 'DC=$dn_domainname,DC=$dn_tld'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldap://$ip -D $domain\\\\${blue}username${yellow} -w ${blue}password${yellow} -b 'DC=$dn_domainname,DC=$dn_tld' | grep -i -A2 -B2 'userpas'${nc}\n"
        print_header "LDAPDomainDump" "${bold_yellow}" "true"
        printf "${yellow}ldapdomaindump ldap://$ip -u $domain\\\\\\\\${blue}username${yellow} -p ${blue}password${yellow} --no-json --no-grep -o $dir_ldap/ldapdomaindump${nc}\n"
        printf "${yellow}ldapdomaindump ldap://$ip -u $domain\\\\\\\\${blue}username${yellow} -p ${blue}lm:nthash${yellow} --no-json --no-grep -o $dir_ldap/ldapdomaindump${nc}\n"
        print_header "WinDAPSearch" "${bold_yellow}" "true"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m admin-objects${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m computers${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m custom${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m dns-names${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m dns-zones${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m domain-admins${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m gpos${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m groups${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m members${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m metadata${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m privileged-users${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m search${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m unconstrained${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m user-spns${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m users${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v -m users --full${nc}\n"
        print_header "NetExec (NXC)" "${bold_yellow}" "true"
        printf "${yellow}nxc ldap $ip -u '' -p '' -M get-desc-users | grep "User:"  | awk -F 'User: | description: ' '{print \$2" "\$3}'${nc}\n"
    elif [ "$port" -eq 636 ]; then
        print_header "Port $port LDAPS" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script ldap-* -p $port $ip${nc}\n"
        print_header "LDAPSearch" "${bold_yellow}" "true"
        printf "${yellow}ldapsearch -H ldaps://$domain/ -x -s base -b '' '(objectClass=*)' '*'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldaps://$fqdn/ -x -b 'CN=Users,DC=$dn_domainname,DC=$dn_tld' ${nc}\n"
        printf "${yellow}ldapsearch -x -H ldaps://$ip -D '' -w '' -b 'DC=$dn_domainname,DC=$dn_tld'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldaps://$ip -D $domain\\\\${blue}username${yellow} -w ${blue}password${yellow} -b 'DC=$dn_domainname,DC=$dn_tld'${nc}\n"
        printf "${yellow}ldapsearch -x -H ldaps://$ip -D $domain\\\\${blue}username${yellow} -w ${blue}password${yellow} -b 'DC=$dn_domainname,DC=$dn_tld' | grep -i -A2 -B2 'userpas'${nc}\n"
        print_header "LDAPDomainDump" "${bold_yellow}" "true"
        printf "${yellow}ldapdomaindump ldaps://$ip -u $domain\\\\\\\\${blue}username${yellow} -p ${blue}password${yellow} --no-json --no-grep -o $dir_ldap/ldapdomaindump${nc}\n"
        printf "${yellow}ldapdomaindump ldaps://$ip -u $domain\\\\\\\\${blue}username${yellow} -p ${blue}lm:nthash${yellow} --no-json --no-grep -o $dir_ldap/ldapdomaindump${nc}\n"
        print_header "WinDAPSearch" "${bold_yellow}" "true"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m admin-objects${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m computers${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m custom${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m dns-names${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m dns-zones${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m domain-admins${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m gpos${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m groups${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m members${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m metadata${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m privileged-users${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m search${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m unconstrained${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m user-spns${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m users${nc}\n"
        printf "${yellow}windapsearch -d $domain --dc $ip -v --secure -m users --full${nc}\n"
    elif [ "$port" -eq 873 ]; then
        print_header "Port $port RSync" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap -sV --script 'rsync-list-modules' -p $port $ip${nc}\n"
        print_header "RSync" "${bold_yellow}" "true"
        printf "${yellow}rsync -av --list-only rsync://$ip/shared_name${nc}\n"
        printf "${yellow}rsync -av rsync://$ip:8730/shared_name ./directory${nc}\n"
        printf "${yellow}rsync -av --list-only rsync://${blue}username${yellow}@$ip/shared_name${nc}\n"
        printf "${yellow}rsync -av rsync://${blue}username${yellow}@$ip:8730/shared_name ./directory${nc}\n"
        printf "${yellow}rsync -av directory/.ssh/ rsync://${blue}username${yellow}@$ip/directory/.ssh${nc}\n"
        print_header "Other" "${bold_yellow}" "true"
        printf "${yellow}rlogin $ip -l ${blue}username${yellow}${nc}\n"
        printf "${yellow}rwho${nc}\n"
        printf "${yellow}rusers -al $ip${nc}\n"
    elif [ "$port" -eq 1433 ]; then
        print_header "Port $port MSSQL" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script ms-sql-* -p $port $ip${nc}\n"
        print_header "Impacket" "${bold_yellow}" "true"
        printf "${yellow}python3 $dir_impacket/mssqlclient.py -p $port usern${blue}username${yellow}ame@$ip${nc}\n"
        printf "${yellow}python3 $dir_impacket/mssqlclient.py -p $port ${blue}username${yellow}@$ip -windows-auth${nc}\n"
        print_header "Sqsh" "${bold_yellow}" "true"
        printf "${yellow}sqsh -S $ip -U ${blue}username${yellow} -P ${blue}password${yellow} -D database${nc}\n"
        printf "${yellow}sqsh -S $ip -U .\\\\${blue}username${yellow} -P ${blue}password${yellow} -D database${nc}\n"
        print_header "NetExec (NXC)" "${bold_yellow}" "true"
        printf "${yellow}nxc mssql $ip -d $domain -u ${magenta}enum/usernames${yellow} -p ${magenta}enum/passwords${yellow}${nc}\n"
        printf "${yellow}nxc mssql $ip -d $domain -u ${blue}username${yellow} -p ${blue}password${yellow} -x 'whoami'${nc}\n"
        printf "${yellow}nxc mssql $ip -d $domain -u ${blue}username${yellow} -H ${blue}nthash${yellow} -X '$PSVersionTable'${nc}\n"
        print_header "Brute Forcing" "${bold_yellow}" "true"
        printf "${yellow}hydra -L ${magenta}enum/usernames${yellow} -P ${magenta}enum/passwords${yellow} $ip mssql${nc}\n"
        printf "${yellow}medusa -h $ip -U ${magenta}enum/usernames${yellow} -P ${magenta}enum/passwords${yellow} -M mssql${nc}\n"
    elif [ "$port" -eq 110 ] || [ "$port" -eq 2049 ]; then
        print_header "Port $port NFS" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script nfs-* -p $port $ip${nc}\n"
        print_header "Mount Share NFS" "${bold_yellow}" "true"
        printf "${yellow}showmount -e $ip${nc}\n"
        printf "${yellow}sudo mkdir $dir_nfs/share${nc}\n"
        printf "${yellow}sudo mount -t nfs $ip:/share $dir_nfs/share -o nolock${nc}\n"
        printf "${yellow}cd $dir_nfs/share${nc}\n"
        printf "${yellow}tree .${nc}\n"
        printf "${yellow}cd ~${nc}\n"
        printf "${yellow}sudo umount -f -l $dir_nfs/share${nc}\n"
    elif [ "$port" -eq 3306 ]; then
        print_header "Port $port MySQL" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script mysql-* -p $port $ip${nc}\n"
        print_header "Connect to DB" "${bold_yellow}" "true"
        printf "${yellow}mysql -h $ip -u ${blue}username${yellow} -p${blue}password${yellow}${nc}\n"
        printf "${yellow}mysql -h $ip -u ${blue}username${yellow} -p${blue}password${yellow} -e 'show databases;'${nc}\n"
        print_header "Commands" "${bold_yellow}" "true"
        printf "show databases;${nc}\n"
        printf "use database;${nc}\n"
        printf "connect database;${nc}\n"
        printf "show tables;${nc}\n"
        printf "describe table_name;${nc}\n"
        printf "show columns from table;${nc}\n"
        printf "SELECT column FROM table;${nc}\n"
        printf "SELECT * FROM table;${nc}\n"
        printf "SELECT * FROM table WHERE column = string;${nc}\n"
        printf "select version();${nc}\n"
        printf "select @@version();${nc}\n"
        printf "select user();${nc}\n"
        printf "select database();${nc}\n"
    elif [ "$port" -eq 3389 ]; then
        print_header "Port $port RDP" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script rdp-* -p $port $ip${nc}\n"
        print_header "Connect to Desktop" "${bold_yellow}" "true"
        printf "${yellow}xfreerdp /v:$ip /u:${blue}username${yellow} /p:${blue}password${yellow} /cert:ignore /dynamic-resolution +clipboard /drive:$dir_tools,tools${nc}\n"
        printf "${yellow}xfreerdp /v:$ip /u:${blue}username${yellow} /pth:${blue}nthash${yellow} /cert:ignore /dynamic-resolution +clipboard /drive:$dir_tools,tools${nc}\n"
        printf "${yellow}rdesktop -d $domain -u ${blue}username${yellow} -p ${blue}password${yellow} $ip -g 95%%${nc}\n"
    elif [ "$port" -eq 5985 ] || [ "$port" -eq 5986 ]; then
        print_header "Port $port WinRM" "${bold_magenta}" "false"
        print_header "NSE" "${bold_yellow}" "true"
        printf "${yellow}nmap --script winrm-* -p $port $ip${nc}\n"
        print_header "EvilWinRM" "${bold_yellow}" "true"
        printf "${yellow}evil-winrm -i $ip -u ${blue}username${yellow} -p ${blue}password${yellow}${nc}\n"
        printf "${yellow}evil-winrm -i $ip -u ${blue}username${yellow} -H ${blue}nthash${yellow}${nc}\n"
        print_header "Brute Force" "${bold_yellow}" "true"
        printf "${yellow}nxc winrm $ip -d $domain -u ${magenta}enum/usernames${yellow} -p ${magenta}enum/passwords${yellow}${nc}\n"
    elif [ "$port" -eq 80 ]; then
        url_ip="http://$ip"
        url_domain="http://$fqdn"
        http_commands
    elif [ "$port" -eq 443 ]; then
        url_ip="https://$ip"
        url_domain="https://$fqdn"
        http_commands
    elif [ "$port" -eq 81 ] || [ "$port" -eq 82 ] || [ "$port" -eq 8000 ] || [ "$port" -eq 8008 ] || [ "$port" -eq 8080 ] || [ "$port" -eq 8081 ] || [ "$port" -eq 8443 ] || [ "$port" -eq 8888 ]; then
        url_ip="http://$ip:$port"
        url_domain="http://$fqdn:$port"
        http_commands
    elif [ "$port" -eq 9389 ] || [ "$port" -eq 47001 ]; then
        print_header "Port $port Active Directory Protocol" "${bold_magenta}" "false"
        printf "$pre_info This port is used by Active Directory but likely does not need further enumeration.${nc}\n"
    elif [ "$port" -eq 3268 ] || [ "$port" -eq 3269 ]; then
        print_header "Port $port Global Catalog" "${bold_magenta}" "false"
        printf "$pre_info This port is used by Active Directory. See LDAP notes for further enumeration.${nc}\n"
    else
        print_header "Port $port Unknown Protocol" "${bold_magenta}" "false"
        printf "$pre_warn Research further using Google and/or HackTricks.${nc}\n"
    fi
done
print_header "UDP PORTS" "${bold_magenta}" "true"
IFS=',' read -r -a ports_udp <<< "$open_udp"
for port in "${ports_udp[@]}"; do
    if [ "$port" -eq 161 ] || [ "$port" -eq 162 ]; then
        print_header "Port $port SNMP" "${bold_magenta}" "false"
        print_header "Brute Force MIB Values" "${bold_yellow}" "true"
        printf "${yellow}onesixtyone -c $dir_seclists/Discovery/SNMP/snmp.txt $ip${nc}\n"
        printf "${yellow}onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt $ip${nc}\n"
        printf "${yellow}hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $ip snmp${nc}\n"
        print_header "SNMPWalk" "${bold_yellow}" "true"
        printf "${yellow}snmpwalk -v 2c -c public $ip .1${nc}\n"
        printf "${yellow}snmpwalk -v 2c -c public $ip 1.3.6.1.2.1.4.34.1.3${nc}\n"
        printf "${yellow}snmpwalk -v X -c public $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull${nc}\n"
        print_header "Braa" "${bold_yellow}" "true"
        printf "${yellow}braa <community string>@$ip:.1.3.6.*${nc}\n"
        print_header "MIB Values" "${bold_yellow}" "true"
        printf "1.3.6.1.2.1.25.1.6.0 - System Processes${nc}\n"
        printf "1.3.6.1.2.1.25.4.2.1.2 - Running Programs${nc}\n"
        printf "1.3.6.1.2.1.25.4.2.1.4 - Processes Path${nc}\n"
        printf "1.3.6.1.2.1.25.2.3.1.4 - Storage Units${nc}\n"
        printf "1.3.6.1.2.1.25.6.3.1.2 - Software Name${nc}\n"
        printf "1.3.6.1.4.1.77.1.2.25 - User Accounts${nc}\n"
        printf "1.3.6.1.2.1.6.13.1.3 - TCP Local Ports${nc}\n"
    #elif [ "$port" -eq ## ]; then
    else
        print_header "Port $port Unknown Protocol" "${bold_magenta}" "false"
        printf "$pre_warn Research further using Google and/or HackTricks.${nc}\n"
    fi
done

# Print commands for Bloodhound
print_header "BLOODHOUND" "${bold_white}" "true"
if [ "$ad" == "true" ]; then
    printf "$pre_info To run Bloodhound against $domain, first run the following commands:${nc}\n"
    printf "${yellow}sudo neo4j start${nc}\n"
    printf "${yellow}bloodhound${nc}\n"
    printf "Credentials are: neo4j:neo4j1${nc}\n"
    printf "$pre_info Then run the following commands:${nc}\n"
    printf "${yellow}cd $dir_blood${nc}\n"
    printf "${yellow}bloodhound-python -d $domain -u ${blue}username${yellow} -p ${blue}password${yellow} -ns $ip -c all --zip${nc}\n"
    printf "${yellow}nxc ldap $ip -u ${blue}username${yellow} -p ${blue}password${yellow} --bloodhound -ns $ip --collection All${nc}\n"
else
    printf "$pre_warn This machine does not belong to an Active Directory domain.${nc}\n"
fi

# Print commands for Autorecon
print_header "AUTORECON" "${bold_white}" "true"
printf "$pre_info To run autorecon against $hostname:${nc}\n"
printf "${yellow}sudo \$(which autorecon) $ip --global.domain $domain --single-target --heartbeat 30 -v -m 100 --only-scans-dir --dirbuster.threads=50 --output $dir_auto${nc}\n"
printf "${yellow}sudo \$(which autorecon) $ip --single-target --heartbeat 30 -v -m 100 --only-scans-dir --dirbuster.threads=50 --output $dir_auto${nc}\n"

# Print commands for subdomain enumeration
print_header "SUBDOMAIN ENUMERATION" "${bold_white}" "true"
if [ ! -z "$dns_all" ]; then
    printf "$pre_info To run a comprehensive Nmap scan against the subdomains discovered from the Dig enumeration:${nc}\n"
    printf "$pre_info Note: You must add DNS subdomains to /etc/hosts first per instructions above${nc}\n"
    printf "${yellow}sudo nmap -Pn -p $open_http -iL $dir_init/subdomains -oA $dir_nmap/http${nc}\n"
    printf "${yellow}eyewitness --web -x $dir_nmap/http.xml -d $dir_eye${nc}\n"
    printf "$pre_info To run a comprehensive Nmap scan against manually discovered subdomains:${nc}\n"
    printf "$pre_info Note: You must add any discovered subdomains to /etc/hosts first using the following command:${nc}\n"
    printf "${yellow}subdomains $dir_init/subdomains $domain $ip${nc}\n"
    printf "${yellow}sudo nmap -Pn -p $open_http -iL $dir_init/subdomains -oA $dir_nmap/http${nc}\n"
    printf "${yellow}eyewitness --web -x $dir_nmap/http.xml -d $dir_eye${nc}\n"
else
    printf "$pre_info To run a comprehensive Nmap scan against manually discovered subdomains:${nc}\n"
    printf "$pre_info Note: You must add any discovered subdomains to /etc/hosts first using the following command:${nc}\n"
    printf "${yellow}subdomains $dir_init/subdomains $domain $ip${nc}\n"
    printf "${yellow}sudo nmap -Pn -p $open_http -iL $dir_init/subdomains -oA $dir_nmap/http${nc}\n"
    printf "${yellow}eyewitness --web -x $dir_nmap/http.xml -d $dir_eye${nc}\n"
fi

# Print directory tree
print_header "MACHINE DIRECTORIES" "${bold_white}" "true"
tree -A -C --dirsfirst $dir_name
printf "${yellow}cd $dir_name${nc}\n"

# Declare end time elapsed variables and print
end_time=$(date +%s)
duration=$((end_time - start_time))
curr_time=$(date +%Y%m%d_%H%M%S)
export curr_time
export dir_hist
printf "$pre_warn Add FQDNs and IPs to /etc/hosts!${nc}\n"
printf "$pre_win Keep a positive attitude. Take breaks. KISS. You got this!${nc}\n"
printf "$pre_info Overall elapsed time: $duration seconds.${nc}\n"

# Terminal commands
if [ "$autoterm" == "yes" ]; then
    xdotool key alt+shift+s && sleep 1 && xdotool type "start" && xdotool key Return && sleep 1
    xdotool key ctrl+shift+t && sleep 1 && xdotool key alt+shift+s && sleep 1 && xdotool type "scans" && xdotool key Return && sleep 1 && xdotool type "script -f $dir_hist/scans_a_$curr_time.log" && xdotool key Return && sleep 1 && xdotool key ctrl+shift+d && sleep 1 && xdotool type "script -f $dir_hist/scans_b_$curr_time.log" && xdotool key Return
    xdotool key ctrl+shift+t && sleep 1 && xdotool key alt+shift+s && sleep 1 && xdotool type "bust" && xdotool key Return && sleep 1 && xdotool type "script -f $dir_hist/bust_$curr_time.log" && xdotool key Return
    xdotool key ctrl+shift+t && sleep 1 && xdotool key alt+shift+s && sleep 1 && xdotool type "enum" && xdotool key Return && sleep 1 && xdotool type "script -f $dir_hist/enum_$curr_time.log" && xdotool key Return
    xdotool key ctrl+shift+t && sleep 1 && xdotool key alt+shift+s && sleep 1 && xdotool type "shell" && xdotool key Return && sleep 1 && xdotool type "script -f $dir_hist/shell_$curr_time.log" && xdotool key Return
fi

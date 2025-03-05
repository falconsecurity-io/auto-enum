#!/bin/bash

# Script Title: NTLM Hash Query Tool (https://ntlm.pw)
# Date: 03/03/2025
# Author: Robboman (Falcon Security)
# GitHub: https://github.com/falconsecurity-io
# Version: 1.0

# Set colors
red='\033[0;31m'
green='\033[0;32m'
cyan='\033[0;36m'
nc='\033[0m'

# Validate and extract arguments
if [ $# -lt 2 ]; then
    printf "${red}Usage: ntlmpw <type> <file>${nc}\n"
    printf "${red}Example: ntlmpw nt/lm/sha256 hashes_nt${nc}\n"
    exit 1
fi

if [ ! -s "$2" ]; then
    echo "File not found or is empty: $2"
    exit 1
fi

type=$1
filename=$2

# Read each hash from file and curl API
while read -r hashvalue
do
    if [[ $hashvalue =~ ^\s*$ ]]; then
        continue
    fi
    url="https://ntlm.pw/api/lookup/$type/$hashvalue"
    printf "${cyan}Querying NT hash: $hashvalue${nc}\n"
    curl -s "$url" | tee -a ntlmpw_output
done < "$filename"

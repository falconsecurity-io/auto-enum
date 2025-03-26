#!/bin/bash

red='\033[0;31m'
nc='\033[0m'

if [ $# -ne 2 ]; then
  echo "Usage: $0 <input_file> <output_file>"
  exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

BASE_DOMAIN=$(grep -oE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$INPUT_FILE" \
  | sed 's/\.$//' \
  | awk -F. '{ if (NF >= 2) print $(NF-1)"."$NF }' \
  | sort | uniq -c | sort -nr | awk 'NR==1{print $2}' )
  
if [ -z "$BASE_DOMAIN" ]; then
  echo "Error: Could not determine base domain from input."
  exit 1
fi

HOSTNAMES=$(grep -oE "[a-zA-Z0-9.-]+\.${BASE_DOMAIN//./\\.}\." "$INPUT_FILE" \
  | sed 's/\.$//' \
  | sort -u)

SUBDOMAINS=$(echo "$HOSTNAMES" | grep -v "^$BASE_DOMAIN$")

{
  echo "$BASE_DOMAIN"
  echo "$SUBDOMAINS"
} > "$OUTPUT_FILE"

SUBDOMAIN_COUNT=$(echo "$SUBDOMAINS" | wc -l)
all_domains="$BASE_DOMAIN $(echo "$SUBDOMAINS" | tr '\n' ' ')"

echo "Base domain detected: $BASE_DOMAIN"
echo "Number of unique subdomains: $SUBDOMAIN_COUNT"
echo "Subdomains saved to $OUTPUT_FILE file\n"
echo "Subdomains:"
echo -e "${red}"
cat "$OUTPUT_FILE"
echo -e "${nc}"
echo -e "One liners to modify /etc/hosts...${nc}\n"
echo "cat /etc/hosts"
echo "sudo sed -i '\$d' /etc/hosts"
echo "printf \"%s\t%s\n\n\" \"\$ip\" \"$all_domains\" | sudo tee -a /etc/hosts"

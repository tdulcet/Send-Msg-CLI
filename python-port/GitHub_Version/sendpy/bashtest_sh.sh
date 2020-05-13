#!/bin/bash

# Teal Dulcet
# E-mail validation extracted from the Send Msg CLI (sendmsg.sh)
# This is for testing only

# ./bashtest.sh

set -e

if [[ $# -ne 0 ]]; then
	echo "Usage: $0" >&2
	exit 1
fi

RED='\e[0;31m'
GREEN='\e[0;32m'
BOLD='\e[1m'
NC='\e[m' # No Color

RE1='^.{6,254}$'
RE2='^.{1,64}@'
RE3='^[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+(\.[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+)*@((xn--)?[[:alnum:]]([[:alnum:]-]{0,61}[[:alnum:]])?\.)+(xn--)?[[:alpha:]]{2,63}$'

# check <e-mail address> <valid output> <invalid output>
check() {
	if ! [[ $1 =~ $RE1 ]]; then
		echo -e "$3 (e-mail address too short or too long)"
	elif ! [[ $1 =~ $RE2 ]]; then
		echo -e "$3 (local-part too short or too long)"
	elif ! [[ $1 =~ $RE3 ]]; then
		echo -e "$3"
	else
		echo -e "$2"
	fi
}

echo -e "\n${BOLD}Valid examples${NC}"
mapfile -t VALID < valid.txt
for email in "${VALID[@]}"; do
	printf '%s\t' "$email"
	check "$email" "✔️ ${GREEN}Valid${NC}" "❌ ${RED}Error Invalid${NC}"
done | column -t -s $'\t'

echo -e "\n${BOLD}Invalid examples${NC}"
mapfile -t INVALID < invalid.txt
for email in "${INVALID[@]}"; do
	printf '%s\t' "$email"
	check "$email" "❌ ${RED}Error Valid${NC}" "✔️ ${GREEN}Invalid${NC}"
done | column -t -s $'\t'

echo -e "\n${BOLD}Firefox examples${NC} (both Valid and Invalid)"
mapfile -t FIREFOX < firefox.txt
for email in "${FIREFOX[@]}"; do
	printf '%s\t' "$email"
	email=$(echo -e "$email")
	check "$email" "${GREEN}Valid${NC}" "${RED}Invalid${NC}"
done | column -t -s $'\t'

echo -e "\n${BOLD}Chrome/Chromium examples${NC} (both Valid and Invalid)"
mapfile -t CHROMIUM < chromium.txt
for email in "${CHROMIUM[@]}"; do
	printf '%s\t' "$email"
	email=$(echo -e "$email")
	check "$email" "${GREEN}Valid${NC}" "${RED}Invalid${NC}"
done | column -t -s $'\t'

echo

RE1='^.{6,254}$'
RE2='^.{1,64}@'
#RE3='^[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+(\.[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+)*@((xn--)?[[:alnum:]][[:alnum:]-]{0,61}[[:alnum:]]\.)+(xn--)?[a-zA-Z]{2,63}$'
RE3='^[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+(\.[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+)*@((xn--)?[[:alnum:]]([[:alnum:]-]{0,61}[[:alnum:]])?\.)+(xn--)?[[:alpha:]]{2,63}$'
RED='\e[0;31m'
GREEN='\e[0;32m'
NC='\e[m'
mapfile -t VALID < valid.txt
for email in "${VALID[@]}"; do echo -e -n "$email\t"; if [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then echo -e "${GREEN}Valid${NC}"; else echo -e "${RED}Error Invalid${NC}"; fi; done | column -t -s $'\t'
mapfile -t INVALID < invalid.txt
for email in "${INVALID[@]}"; do echo -e -n "$email\t"; if [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then echo -e "${RED}Error Valid${NC}"; else echo -e "${GREEN}Invalid${NC}"; fi; done | column -t -s $'\t'

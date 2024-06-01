#!/bin/bash

# Teal Dulcet
# Send e-mail, with optional message and attachments

# Requires the curl and netcat commands

# Optional S/MIME digital signatures require the openssl command
# Optional PGP/MIME digital signatures require the gpg command

# Run: ./sendmsg.sh <OPTION(S)>... -s <subject>

set -e

# Set the variables below

# Send e-mails
# Comment this out to temporally disable
SEND=1

# To e-mail addresses
# Send text messages by using your mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients)
TOEMAILS=(

)

# CC e-mail addresses
CCEMAILS=(

)

# BCC e-mail addresses
BCCEMAILS=(

)

# Optional From e-mail address
# FROMEMAIL="Example <example@example.com>"

# Optional SMTP server to send e-mails
# Supported protocols: "smtp" and "smtps".
# Use "smtps" for a secure connection with SSL/TLS
# Requires From e-mail address above

# SMTP="smtps://mail.example.com"
# USERNAME="example"
# PASSWORD="password"

# Upgrade to a secure connection with StartTLS
# Requires SMTP server above
# Uncomment this to enable
# STARTTLS=1

# E-mail Priority
# Supported priorities: "5 (Lowest)", "4 (Low)", "Normal", "2 (High)" and "1 (Highest)"
# Requires SMTP server above
# Uncomment this to enable
# PRIORITY="Normal"

# Request Return Receipt/Message Disposition Notification (MDN)
# Requires SMTP server above
# Uncomment this to enable
# MDN=1

# Optional Digitally sign the e-mails with an S/MIME Certificate
# Requires SMTP server above

# List of free S/MIME Certificates: http://kb.mozillazine.org/Getting_an_SMIME_certificate
# Enter the certificate's filename for the CERT variable below.

# CERT="cert.p12"

CLIENTCERT="cert.pem"

# Optional Digitally sign the e-mails with PGP/MIME
# Requires SMTP server above

# Generate a PGP key pair: gpg --gen-key
# Use the same e-mail address as used for the FROMEMAIL variable above. Enter the passphrase for the PASSPHRASE variable below.
# Make sure to send your PGP public key to the recipients before sending them digitally signed e-mails. You can export your PGP public key with: gpg -o key.asc -a --export <e-mail address> and attach key.asc to an e-mail.

# PASSPHRASE="passphrase"

# Days to warn before certificate expiration
WARNDAYS=3

# Compress attachment(s) with zip
# Uncomment this to enable
# ZIPFILE="attachments.zip"

# Set Content-Language
# Uses value of LANG environment variable
# Uncomment this to enable
# CONTENTLANG=1

# Sanitize the Date
# Uses Coordinated Universal Time (UTC), to prevent leaking the local time zone and rounds date down to whole minute, to prevent fingerprinting of clock offset.
# Uncomment this to enable
# UTC=1

# Allow UTF-8 encoding in mailbox names and header fields
# Requires SMTP server above
# Requires support for the SMTPUTF8 extension by the SMTP server
# SMTPUTF8=1

# Use 8 bit data transmission instead of base64
# Requires SMTP server above
# Requires support for the 8BITMIME extension by the SMTP server
BODY8BITMIME=1

# Show the client-server communication
# Requires SMTP server above
# Uncomment this to enable
# VERBOSE=1

# Do not change anything below this

# Output usage
# usage <programname>
usage() {
	echo "Usage:  $1 <OPTION(S)>... -s <subject>
or:     $1 <OPTION>
One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). All the options can also be set by opening the script in an editor and setting the variables at the top. See examples below.

Options:
    -s <subject>    Subject
                        Escape sequences are expanded. Supports Unicode characters.
    -m <message>    Message body
                        Escape sequences are expanded. Supports Unicode characters.
    -a <attachment> Attachment filename
                        Use multiple times for multiple attachments. Supports Unicode characters in filename.
    -t <To address> To e-mail address
                        Use multiple times for multiple To e-mail addresses.
    -c <CC address> CC e-mail address
                        Use multiple times for multiple CC e-mail addresses.
    -b <BCC address>BCC e-mail address
                        Use multiple times for multiple BCC e-mail addresses.
    -f <From address>From e-mail address

    -S <SMTP server>SMTP server
                        Supported protocols: \"smtp\" and \"smtps\". Requires From e-mail address. Use \"smtp://localhost\" if running a mail server on this device.
    -u <username>   SMTP server username
    -p <password>   SMTP server password
    -P <priority>   Priority
                        Supported priorities: \"5 (Lowest)\", \"4 (Low)\", \"Normal\", \"2 (High)\" and \"1 (Highest)\". Requires SMTP server.
    -r              Request Return Receipt
                        Requires SMTP server.
    -C <certificate>S/MIME Certificate filename for digitally signing the e-mails
                        It will ask you for the password the first time you run the script with this option. Requires SMTP server.
    -k <passphrase> PGP secret key passphrase for digitally signing the e-mails with PGP/MIME
                        Requires SMTP server.
    -z <zipfile>    Compress attachment(s) with zip
    -l              Set Content-Language
                        Uses value of LANG environment variable.
    -U              Sanitize the Date
                        Uses Coordinated Universal Time (UTC) and rounds date down to whole minute. Set the TZ environment variable to change time zone.
    -T <seconds>    Time to delay sending of the e-mail
    -d              Dry run, do not send the e-mail
    -V              Verbose, show the client-server communication
                        Requires SMTP server.

    -h              Display this help and exit
    -v              Output version information and exit

Examples:
    Send e-mail
    $ $1 -s \"Example\" -t \"User <user@example.com>\"

    Send e-mail with message
    $ $1 -s \"Example\" -m \"This is an example"'!'"\" -t \"User <user@example.com>\"

    Send e-mail with message and single attachment
    $ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example.txt -t \"User <user@example.com>\"

    Send e-mail with message and multiple attachments
    $ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example1.txt -a example2.txt -t \"User <user@example.com>\"

    Send e-mail to a CC address
    $ $1 -s \"Example\" -t \"User 1 <user1@example.com>\" -c \"User 2 <user2@example.com>\"

    Send e-mail with a From address
    $ $1 -s \"Example\" -f \"Example <example@example.com>\" -t \"User <user@example.com>\"

    Send e-mail with an external SMTP server
    $ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -t \"User <user@example.com>\"

    Send high priority e-mail
    $ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -P \"1 (Highest)\" -t \"User <user@example.com>\"

    Send e-mail digitally signed with an S/MIME Certificate
    $ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -C \"cert.p12\" -t \"User <user@example.com>\"

    Send e-mail digitally signed with PGP/MIME
    $ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -k \"passphrase\" -t \"User <user@example.com>\"
" >&2
}

if [[ $# -eq 0 ]]; then
	usage "$0"
	exit 1
fi

NOW=${EPOCHSECONDS:-$(date +%s)}

SUBJECT=''
MESSAGE=''
ATTACHMENTS=()

# Check if on Linux
if ! echo "$OSTYPE" | grep -iq '^linux'; then
	echo "Error: This script must be run on Linux." >&2
	exit 1
fi

while getopts "a:b:c:df:hk:lm:p:rs:t:u:vz:C:P:S:T:UV" c; do
	case ${c} in
		a)
			ATTACHMENTS+=("$OPTARG")
			;;
		b)
			BCCEMAILS+=("$OPTARG")
			;;
		c)
			CCEMAILS+=("$OPTARG")
			;;
		d)
			SEND=''
			;;
		f)
			FROMEMAIL=$OPTARG
			;;
		h)
			usage "$0"
			exit 0
			;;
		k)
			PASSPHRASE=$OPTARG
			;;
		l)
			CONTENTLANG=1
			;;
		m)
			MESSAGE=$OPTARG
			;;
		p)
			PASSWORD=$OPTARG
			;;
		r)
			MDN=1
			;;
		s)
			SUBJECT=$OPTARG
			;;
		t)
			TOEMAILS+=("$OPTARG")
			;;
		u)
			USERNAME=$OPTARG
			;;
		v)
			echo -e "Send Msg CLI 1.0.1\n"
			exit 0
			;;
		z)
			ZIPFILE="${OPTARG%.zip}.zip"
			;;
		C)
			CERT=$OPTARG
			;;
		P)
			PRIORITY=$OPTARG
			;;
		S)
			SMTP=$OPTARG
			;;
		T)
			TIME=$OPTARG
			;;
		U)
			UTC=1
			;;
		V)
			VERBOSE=1
			;;
		\?)
			echo -e "Try '$0 -h' for more information.\n" >&2
			exit 1
			;;
	esac
done
shift $((OPTIND - 1))

if [[ $# -ne 0 ]]; then
	usage "$0"
	exit 1
fi

if [[ -z $SUBJECT ]]; then
	echo "Error: A subject is required." >&2
	exit 1
fi

if [[ -n $PRIORITY || -n $MDN || -n $CERT || -n $PASSPHRASE || -n $SMTP || -n $USERNAME || -n $PASSWORD || -n $STARTTLS ]] && ! [[ -n $FROMEMAIL && -n $SMTP ]]; then
	echo -e "Warning: One or more of the options you set requires that you also provide an external SMTP server. Try '$0 -h' for more information.\n"
fi

if [[ ${#TOEMAILS[@]} -eq 0 && ${#CCEMAILS[@]} -eq 0 && ${#BCCEMAILS[@]} -eq 0 ]]; then
	echo "Error: One or more To, CC or BCC e-mail addresses are required." >&2
	exit 1
fi

if ((${#ATTACHMENTS[@]})); then
	TOTAL=0
	table=''
	for i in "${ATTACHMENTS[@]}"; do
		if [[ -z $i || ! -r $i ]]; then
			echo "Error: Cannot read '$i' file." >&2
			exit 1
		fi
	done

	if [[ -n $ZIPFILE ]]; then
		if [[ -e $ZIPFILE ]]; then
			echo "Error: File '$ZIPFILE' already exists." >&2
			exit 1
		fi

		trap 'rm -- "$ZIPFILE"' EXIT
		zip -q "$ZIPFILE" -- "${ATTACHMENTS[@]}"

		ATTACHMENTS=("$ZIPFILE")
	fi

	echo "Attachments:"
	for i in "${ATTACHMENTS[@]}"; do
		SIZE=$(du -b -- "$i" | awk '{ print $1 }')
		((TOTAL += SIZE))
		table+=$(printf '%s\t%s\t%s\n' "$i" "$(numfmt --to=iec-i "$SIZE")B" "$([[ $SIZE -ge 1000 ]] && echo "($(numfmt --to=si "$SIZE")B)" || echo)")
	done
	echo "$table" | column -t -s $'\t'

	echo -e "\nTotal Size:\t$(numfmt --to=iec-i "$TOTAL")B\t$([[ $TOTAL -ge 1000 ]] && echo "($(numfmt --to=si "$TOTAL")B)")\n"
	# du -bch -- "${ATTACHMENTS[@]}"

	if [[ $TOTAL -ge 26214400 ]]; then
		echo -e "Warning: The total size of all attachments is greater than 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Send: https://send.vis.ee/ (formerly Firefox Send) or transfer.sh: https://transfer.sh\n"
	fi
fi

# Adapted from: https://github.com/mail-in-a-box/mailinabox/blob/master/setup/network-checks.sh
if ! [[ -n $FROMEMAIL && -n $SMTP ]] && ! nc -z -w5 aspmx.l.google.com 25; then
	echo -e "Warning: Could not reach Google's mail server on port 25. Port 25 seems to be blocked by your network. You will need to provide an external SMTP server in order to send e-mails.\n"
fi

# encoded-word <text>
encoded-word() {
	# ASCII
	RE='^[] !"#$%&'\''()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\^_`abcdefghijklmnopqrstuvwxyz{|}~-]*$' # '^[ -~]*$' # '^[[:ascii:]]*$'
	if [[ -n $SMTPUTF8 || $1 =~ $RE ]]; then
		echo "$1"
	else
		echo "=?utf-8?B?$(echo -n "$1" | base64 -w 0)?="
	fi
}

TOADDRESSES=("${TOEMAILS[@]}")
TONAMES=("${TOEMAILS[@]}")
CCADDRESSES=("${CCEMAILS[@]}")
CCNAMES=("${CCEMAILS[@]}")
BCCADDRESSES=("${BCCEMAILS[@]}")
FROMADDRESS=$FROMEMAIL
FROMNAME=$FROMEMAIL

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"
RE='^(([[:print:]]{1,64}@[-.[:alnum:]]{4,254})|([[:print:]]*) *<([[:print:]]{1,64}@[-.[:alnum:]]{4,254})>)$'
for i in "${!TOADDRESSES[@]}"; do
	if [[ ${TOADDRESSES[i]} =~ $RE ]]; then
		TOADDRESSES[i]=${BASH_REMATCH[2]:-${BASH_REMATCH[4]}}
		TONAMES[i]=${BASH_REMATCH[2]:-$(encoded-word "${BASH_REMATCH[3]}")<${BASH_REMATCH[4]}>}
	fi
done

for i in "${!CCADDRESSES[@]}"; do
	if [[ ${CCADDRESSES[i]} =~ $RE ]]; then
		CCADDRESSES[i]=${BASH_REMATCH[2]:-${BASH_REMATCH[4]}}
		CCNAMES[i]=${BASH_REMATCH[2]:-$(encoded-word "${BASH_REMATCH[3]}")<${BASH_REMATCH[4]}>}
	fi
done

for i in "${!BCCADDRESSES[@]}"; do
	if [[ ${BCCADDRESSES[i]} =~ $RE ]]; then
		BCCADDRESSES[i]=${BASH_REMATCH[2]:-${BASH_REMATCH[4]}}
	fi
done

if [[ -n $FROMADDRESS ]] && [[ $FROMADDRESS =~ $RE ]]; then
	FROMADDRESS=${BASH_REMATCH[2]:-${BASH_REMATCH[4]}}
	FROMNAME=${BASH_REMATCH[2]:-$(encoded-word "${BASH_REMATCH[3]}")<${BASH_REMATCH[4]}>}
fi

# E-mail address regular expressions
RE1='^.{6,254}$'
RE2='^.{1,64}@'
# RE3='^[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+(\.[[:alnum:]!#$%&'\''*+/=?^_`{|}~-]+)*@([[:alnum:]_]([[:alnum:]_-]{0,61}[[:alnum:]_])?\.)+(xn--[[:alnum:]-]{0,58}[[:alnum:]]|[[:alpha:]]{2,63})$'
RE3='^(([^][:space:]@"(),:;<>[\\.]|\\[^():;<>.])+|"([^"\\]|\\.)+")(\.(([^][:space:]@"(),:;<>[\\.]|\\[^():;<>.])+|"([^"\\]|\\.)+"))*@([[:alnum:]_]([[:alnum:]_-]{0,61}[[:alnum:]_])?\.)+(xn--[[:alnum:]-]{0,58}[[:alnum:]]|[[:alpha:]]{2,63})$'
for email in "${TOADDRESSES[@]}"; do
	if ! [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then
		echo "Error: '$email' is not a valid e-mail address." >&2
		exit 1
	fi
done

for email in "${CCADDRESSES[@]}"; do
	if ! [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then
		echo "Error: '$email' is not a valid e-mail address." >&2
		exit 1
	fi
done

for email in "${BCCADDRESSES[@]}"; do
	if ! [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then
		echo "Error: '$email' is not a valid e-mail address." >&2
		exit 1
	fi
done

if [[ -n $FROMADDRESS ]] && ! [[ $FROMADDRESS =~ $RE1 && $FROMADDRESS =~ $RE2 && $FROMADDRESS =~ $RE3 ]]; then
	echo "Error: '$FROMADDRESS' is not a valid e-mail address." >&2
	exit 1
fi

if [[ -n $CERT ]]; then
	if ! command -v openssl >/dev/null; then
		echo "Error: OpenSSL is not installed." >&2
		exit 1
	fi

	if [[ ! -r $CERT && ! -f $CLIENTCERT ]]; then
		echo "Error: '$CERT' certificate file does not exist." >&2
		exit 1
	fi

	if [[ ! -s $CLIENTCERT ]]; then
		echo -e "Saving the client certificate from '$CERT' to '$CLIENTCERT'"
		echo -e "Please enter the password when prompted.\n"
		if ! openssl pkcs12 -in "$CERT" -out "$CLIENTCERT" -clcerts -nodes; then
			echo "Error saving the client certificate. Trying again in legacy mode." >&2
			openssl pkcs12 -in "$CERT" -out "$CLIENTCERT" -clcerts -nodes -legacy
		fi
	fi

	# if ! output=$(openssl verify -verify_email "$FROMADDRESS" "$CLIENTCERT" 2>/dev/null); then
		# echo "Error verifying the S/MIME Certificate: $output" >&2
		# exit 1
	# fi

	if aissuer=$(openssl x509 -in "$CLIENTCERT" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq); then
		issuer=$(echo "$aissuer" | awk -F= '/organizationName=/ { print $2 }')
		if [[ -z $issuer ]]; then
			issuer=$(echo "$aissuer" | awk -F= '/commonName=/ { print $2 }')
		fi
	else
		issuer=''
	fi
	date=$(openssl x509 -in "$CLIENTCERT" -noout -enddate | awk -F= '/notAfter=/ { print $2 }')
	if openssl x509 -in "$CLIENTCERT" -noout -checkend 0 >/dev/null; then
		sec=$(($(date -d "$date" +%s) - NOW))
		if [[ $((sec / 86400)) -lt $WARNDAYS ]]; then
			echo -e "Warning: The S/MIME Certificate ${issuer:+from “$issuer” }expires in less than $WARNDAYS days ($(date -d "$date")).\n"
		fi
	else
		echo "Error: The S/MIME Certificate ${issuer:+from “$issuer” }expired $(date -d "$date")." >&2
		exit 1
	fi
fi

if [[ -n $PASSPHRASE ]]; then
	if ! command -v gpg >/dev/null; then
		echo "Error: GNU Privacy Guard is not installed." >&2
		exit 1
	fi

	if ! echo "$PASSPHRASE" | gpg --pinentry-mode loopback --batch -o /dev/null -ab -u "$FROMADDRESS" --passphrase-fd 0 <(echo); then
		echo "Error: A PGP key pair does not yet exist for '$FROMADDRESS' or the passphrase was incorrect." >&2
		exit 1
	fi

	date=$(gpg -k --with-colons "$FROMADDRESS" | awk -F: '/^pub/ { print $7 }')
	if [[ -n $date ]]; then
		date=$(echo "$date" | head -n 1)
		sec=$((date - NOW))
		fingerprint=$(gpg --fingerprint --with-colons "$FROMADDRESS" | awk -F: '/^fpr/ { print $10 }' | head -n 1)
		if [[ $sec -gt 0 ]]; then
			if [[ $((sec / 86400)) -lt $WARNDAYS ]]; then
				echo -e "Warning: The PGP key pair for '$FROMADDRESS' with fingerprint $fingerprint expires in less than $WARNDAYS days ($(date -d "@$date")).\n"
			fi
		else
			echo "Error: The PGP key pair for '$FROMADDRESS' with fingerprint $fingerprint expired $(date -d "@$date")." >&2
			exit 1
		fi
	fi
fi

if [[ -n $CERT && -n $PASSPHRASE ]]; then
	echo -e "Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n"
fi

# Send e-mail, with optional message and attachments
# Supports Unicode characters in subject, message and attachment filename
# send <subject> [message] [attachment(s)]...
send() {
	local boundary signature lang=${LANG%.*}
	if [[ -n $SEND ]]; then
		if [[ -n $TIME ]]; then
			sleep -- "$TIME"
		fi
		if [[ -n $FROMADDRESS && -n $SMTP ]]; then
			{
				echo -n "User-Agent: Send Msg CLI
From: $FROMNAME
$(if [[ ${#TONAMES[@]} -eq 0 && ${#CCNAMES[@]} -eq 0 ]]; then echo "To: undisclosed-recipients: ;
"; else [[ -n $TONAMES ]] && echo "To: ${TONAMES[0]}$([[ ${#TONAMES[@]} -gt 1 ]] && printf ', %s' "${TONAMES[@]:1}")
"; fi)$([[ -n $CCNAMES ]] && echo "Cc: ${CCNAMES[0]}$([[ ${#CCNAMES[@]} -gt 1 ]] && printf ', %s' "${CCNAMES[@]:1}")
")Subject: $(encoded-word "${1@E}")
Date: $(if [[ -n $UTC ]]; then date -Rud "@$((${EPOCHSECONDS:-$(date +%s)} / 60 * 60))"; else date -R; fi)
${PRIORITY:+X-Priority: $PRIORITY
}${MDN:+Disposition-Notification-To: $FROMNAME
}"
				if [[ $# -ge 3 ]]; then
					boundary="MULTIPART-MIXED-BOUNDARY"
					echo "Content-Type: multipart/mixed; boundary=\"${boundary}\"

--${boundary}
Content-Type: text/plain; charset=UTF-8
${CONTENTLANG:+$([[ ${#lang} -ge 2 ]] && echo "Content-Language: ${lang/_/-}
")}Content-Transfer-Encoding: $(if [[ -n $BODY8BITMIME ]]; then echo "8bit"; else echo "base64"; fi)
"
					if [[ -n $BODY8BITMIME ]]; then
						echo -e "$2"
					else
						echo -e -n "$2" | base64
					fi
					echo
					for i in "${@:3}"; do
						echo "--${boundary}
Content-Type: $(file --mime-type -- "$i" | sed -n 's/^.\+: //p')
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename*=utf-8''$(curl -Gs -w '%{url_effective}
' --data-urlencode "$(basename -- "$i")" "" | sed -n 's/\/?//p')
"
						base64 -- "$i"
						echo
					done
					echo "--${boundary}--"
				else
					echo "Content-Type: text/plain; charset=UTF-8
${CONTENTLANG:+$([[ ${#lang} -ge 2 ]] && echo "Content-Language: ${lang/_/-}
")}Content-Transfer-Encoding: $(if [[ -n $BODY8BITMIME ]]; then echo "8bit"; else echo "base64"; fi)
"
					if [[ -n $BODY8BITMIME ]]; then
						echo -e "$2"
					else
						echo -e -n "$2" | base64
					fi
				fi | if [[ -n $CERT ]]; then
					openssl cms -sign -signer "$CLIENTCERT"
				elif [[ -n $PASSPHRASE ]]; then
					boundary="----MULTIPART-SIGNED-BOUNDARY"
					echo "MIME-Version: 1.0
Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha1; boundary=\"${boundary}\"

--${boundary}"
					tee >(
						signature=$(echo "$PASSPHRASE" | gpg --pinentry-mode loopback --batch -o - -ab -u "$FROMADDRESS" --passphrase-fd 0 <(sed 's/$/\r/'))
						echo "
--${boundary}
Content-Type: application/pgp-signature; name=\"signature.asc\"
Content-Disposition: attachment; filename=\"signature.asc\"

$signature

--${boundary}--"
					)
					wait
				else
					echo "MIME-Version: 1.0"
					cat
				fi
			} | eval curl -sS${VERBOSE:+v} ${STARTTLS:+--ssl-reqd} "${SMTP@Q}" --mail-from "${FROMADDRESS@Q}" $(printf -- '--mail-rcpt %s ' "${TOADDRESSES[@]@Q}" "${CCADDRESSES[@]@Q}" "${BCCADDRESSES[@]}") -T - -u "${USERNAME@Q}:${PASSWORD@Q}"
		else
			{
				echo -e "$2"
				[[ $# -ge 3 ]] && for i in "${@:3}"; do uuencode -- "$i" "$(basename -- "$i")"; done
			} | eval mail ${FROMADDRESS:+-r ${FROMADDRESS@Q}} $([[ -n $CCADDRESSES ]] && printf -- '-c %s ' "${CCADDRESSES[@]@Q}" || echo) $([[ -n $BCCADDRESSES ]] && printf -- '-b %s ' "${BCCADDRESSES[@]@Q}" || echo) -s "${1@Q}" -- "$([[ ${#TOADDRESSES[@]} -eq 0 ]] && echo '"undisclosed-recipients: ;"' || printf -- '%s ' "${TOADDRESSES[@]@Q}")"
		fi
	fi
}

send "$SUBJECT" "$MESSAGE" "${ATTACHMENTS[@]}"

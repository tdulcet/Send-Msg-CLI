#!/usr/bin/env python3

import sys
import getopt
import datetime

'''The purpose of this file is to parse all flags given on the cmdline.
   Skipping to the bottom main function is where the control-flow begins.

'''
#TODO\s:
'''
1. Switch to argparse? Argparse enables the ability to output a specific help message
  rather than the entire help menu.
'''

###Variables

# TODO -- I want to rework the way that I indicate an email is being sent... like an "(-e,--email)" flag?
'''
# Send e-mails
# Comment this out to temporally disable
SEND=1
'''
# TODO -- do I need to enable a default for ZIPFILE ? ( "attachments.zip" as it is in the bash script )
VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"Normal","CERT":"cert.p12","CLIENTCERT":"cert.pem","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":"1","NOW":datetime.datetime.now().strftime("%A, %B %d. %Y %I:%M%p"),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[]}

# Note, I did not use "toaddress",but rather the already existing "toemails" as its equivalent (I think)
# TODO -- get rid of?
LOPTIONS={"-s":"--subject", "-m":"--message","-a":"--attachments", "-t":"--toemails", "-c":"--ccemails", "-b":"--bccemails", "-f":"--fromemail", "-S":"--smtp", "-u":"--username", "-p":"--password", "-P":"--priority", "-C":"--certificate", "-k":"--passphrase", "-z":"--zipfile", "-d":"--dryrun", "-V":"--verbose", "-h":"--help", "-v":"--version"}
# TODO -- long option naming like "bcc-emails" is non-sensical as it only takes one at a time...
'''
TOADDRESSES=( "${TOEMAILS[@]}" )
TONAMES=( "${TOEMAILS[@]}" )
CCADDRESSES=( "${CCEMAILS[@]}" )
CCNAMES=( "${CCEMAILS[@]}" )
BCCADDRESSES=( "${BCCEMAILS[@]}" )
FROMADDRESS=$FROMEMAIL
FROMNAME=$FROMEMAIL
'''

# Output usage
# usage <program name>
# TODO -- add long option flags
def usage():
    print("Usage:  $1 <OPTION(S)>... -s <subject>\n"+
    "or:     $1 <OPTION>\n"+
    "One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway#Email_clients). All the options can also be set by opening the script in an editor and setting the variables at the top. See examples below.\n"+

    "Options:\n"+
        "-s <subject>    Subject\n"+
                            "Escape sequences are expanded. Supports Unicode characters.\n"+
        "-m <message>    Message body\n"+
                            "Escape sequences are expanded. Supports Unicode characters.\n"+
        "-a <attachment> Attachment filename\n"+
                            "Use multiple times for multiple attachments. Supports Unicode characters in filename.\n"+
        "-t <To address> To e-mail address\n"+
                            "Use multiple times for multiple To e-mail addresses.\n"+
        "-c <CC address> CC e-mail address\n"+
                            "Use multiple times for multiple CC e-mail addresses.\n"+
        "-b <BCC address>BCC e-mail address\n"+
                            "Use multiple times for multiple BCC e-mail addresses.\n"+
        "-f <From address>From e-mail address\n"+

        "-S <SMTP server>SMTP server\n"+
                            "Supported protocols: \"smtp\" and \"smtps\". Requires From e-mail address. Use \"smtp://localhost\" if running a mail server on this device.\n"+
        "-u <username>   SMTP server username\n"+
        "-p <password>   SMTP server password\n"+
        "-P <priority>   Priority\n"+
                            "Supported priorities: \"5 (Lowest)\", \"4 (Low)\", \"Normal\", \"2 (High)\" and \"1 (Highest)\". Requires SMTP server.\n"+
        "-C <certificate>S/MIME Certificate filename for digitally signing the e-mails\n"+
                            "It will ask you for the password the first time you run the script with this option. Requires SMTP server.\n"+
        "-k <passphrase> PGP secret key passphrase for digitally signing the e-mails with PGP/MIME\n"+
                            "Requires SMTP server.\n"+
        "-z <zipfile>    Compress attachment(s) with zip\n"+
        "-d              Dry run, do not send the e-mail\n"+
        "-V              Verbose, show the client-server communication\n"+
                            "Requires SMTP server.\n"+

        "-h              Display this help and exit\n"+
        "-v              Output version information and exit\n"+

    "Examples:\n"+
        "Send e-mail\n"+
        "$ $1 -s \"Example\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message and single attachment\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example.txt -t \"Example <example@example.com>\"\n"+

        "Send e-mail with message and multiple attachments\n"+
        "$ $1 -s \"Example\" -m \"This is an example"'!'"\" -a example1.txt -a example2.txt -t \"Example <example@example.com>\"\n"+

        "Send e-mail to a CC address\n"+
        "$ $1 -s \"Example\" -t \"Example 1 <example1@example.com>\" -c \"Example 2 <example2@example.com>\"\n"+

        "Send e-mail with a From address\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail with an external SMTP server\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -t \"Example <example@example.com>\"\n"+

        "Send high priority e-mail\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -P \"1 (Highest)\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail digitally signed with an S/MIME Certificate\n"+
        "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -C \"cert.p12\" -t \"Example <example@example.com>\"\n"+

        "Send e-mail digitally signed with PGP/MIME"+ "$ $1 -s \"Example\" -f \"Example <example@example.com>\" -S \"smtps://mail.example.com\" -u \"example\" -p \"password\" -k \"passphrase\" -t \"Example <example@example.com>\""+")\n")

def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)

def assign(opts):
    '''assign the correct values to the correct opts'''
    for opt, arg in opts:
        if opt in ("-a", "--attachments"):
            VARS["ATTACHMENTS"].append(arg)
        elif opt in ("-b", "--bccemails"):
            VARS["BCCEMAILS"].append(arg)
        elif opt in ("-c", "--ccemails"):
            VARS["CCEMAILS"].append(arg)
        elif opt in ("-d", "--dryrun"):
            pass # TODO
        elif opt in ("-f", "--fromemail"):
            VARS["FROMEMAIL"] = arg
        elif opt in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif opt in ("-k", "--passphrase"):
            VARS["PASSPHRASE"]=arg
        elif opt in ("-m", "--message"):
            VARS["MESSAGE"]=arg
        elif opt in ("-p", "--password"):
            VARS["PASSWORD"]=arg
        elif opt in ("-s", "--subject"):
            VARS["SUBJECT"]=arg
        elif opt in ("-t", "--toemails"):
            VARS["TOEMAILS"].append(arg)
        elif opt in ("-u", "--username"):
            VARS["USERNAME"]= arg
        elif opt in ("-v", "--version"):
            print("Send Msg CLI 1.0\n")
            sys.exit(0)
        elif opt in ("-z", "--zipfile"):
            VARS["ZIPFILE"]= arg
        elif opt in ("-C", "--cert"):
            VARS["CERT"]= arg
        elif opt in ("-P", "--priority"):
            VARS["PRIORITY"]= arg
        elif opt in ("-S", "--smtp"):
            VARS["PRIORITY"]= arg
        elif opt in ("-V", "--VERBOSE"):
            VARS["VERBOSE"]= arg

def parse(argv):
    '''Find the correct variable to assign the opt to.'''
    # Parsing. Erroneous flags throw exception.
    try:
        # TODO -- "passphrase" does not match with variable 'k'. Why not use "key"? Ask Teal
        opts, args = getopt.getopt(argv,"a:b:c:df:hk:m:p:s:t:u:vz:C:P:S:V",
                ["attachments=", "bccemails=", "ccemails=", "dryrun=", "fromemail=", "help",
                    "passphrase=", "subject=", "toaddress=", "username=", "version", "zipfile=",
                    "cert=", "priority=", "smtp=", "verbose="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    assign(opts)

def args_check():
    '''Does a number of checks: whether something is present, including regex on the input'''
    # Check if Linux OS
      # https://stackoverflow.com/questions/5971312/how-to-set-environment-variables-in-python
    CMD = 'echo $%s' % "OSTYPE"
    p = subprocess.Popen(CMD, stdout=subprocess.PIPE, shell=True, executable='/bin/bash')
    error_exit("linux" in p.stdout.readlines()[0].strip().decode("utf-8"),"Error: This script must be run on Linux.")

    # Check if user put in correct args
    if not VARS["SUBJECT"]:
        error_exit(True, "Error: A subject is required")

    if VARS["PRIORITY"] or VARS["CERT"] or VARS["PASSPHRASE"] or VARS["SMTP"] or VARS["USERNAME"]
        or VARS["PASSWORD"] and ((VARS["FROMEMAIL"] and VARS "SMTP"]) == False):
            error_exit(True, "Warning: One or more of the options you set requires that you also provide an external SMTP server. Try '$0 -h' for more information.\n")

    if not VARS["TOEMAILS"] and not VARS["CCEMAILS"] and not VARS["BCCEMAILS"]:
        error_exit(True, "Error: One or more To, Cc, or BCC e-mail addresses are required.")

    if VARS["ATTACHMENTS"]
        TOTAL=0
        table=''
        for attachment in VARS["ATTACHMENTS"]:
            if not attachment or not (os.exists(attachment) and os.access(attachment, os.R_OK)):
                error_exit(True, f'Error: Cannot read {attachment} file.')

        zip_file = VARS["ZIPFILE"]
        if len(zip_file) > 0:
            if os.exists(zip_file):
                error_exit(True, f'Error: File {zip_file} already exists.')

            os.system("zip -q " + zip_file + " " + " ".join(VARS["ATTACHMENTS"]))
            os.system("trap 'rm " + zip_file + "\' EXIT") # if the user does not add a ".zip" to the zip ending, the trap will not work as the zip CMD adds in a .zip (talk to Teal about this... we need a check for it I think).

            VARS["ATTACHMENTS"].append(zip_file)

        # TODO # Creating something to do with attachments
        for attachment in VARS["ATTACHMENTS"]:
            pass



        if TOTAL >= 26214400:
            error_exit(True, "Warning: The total size of all attachments is greater than 25 MiB. The message may     be rejected by your or the recipient's mail server. You may want to upload large files to an external stor    age service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")

    if not (VARS["FROMEMAIL"] and VARS["SMTP"]) and not os.system("nc -z -w5 aspmx.l.google.com 25"):
        error_exit(True, "Warning: Could not reach Google's mail server on port 25. Port 25 seems to be blocked by y    our network. You will need to provide an external SMTP server in order to send e-mails.\n")

def encoded_word(text):
    # ASCII
    # TODO -- did I do this Regex right? (I had to add two backslashes
    RE=r'^[] !"#$%&\'\'\'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\^_`abcdefghijklmnopqrstuvwxyz{|}~-]*$' # '^[ -~]*$' # '^[[:ascii:]]*$'
    if re.match(text, RE):
        print(text)
    else
        print(subprocess.check_output("echo \"=?utf-8?B?$(echo \""+text"\" | base64 -w 0)?=\"", shell=True).decode().strip("\n"))

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"
# TODO: make a function

def attachments():
    # TODO -- this declares a global variable for the the rest of the program, but its not very readable
    global TOADDRESSES
    global TONAMES
    global CCADDRESSES
    global CCNAMES
    global BCCADDRESSES
    global FROMADDRESS
    global FROMNAME

    TOADDRESSES=VARS["TOEMAILS"]
    TONAMES=VARS["TOEMAILS"]
    CCADDRESSES=VARS["CCEMAILS"]
    CCNAMES=VARS["CCEMAILS"]
    BCCADDRESSES=VARS["BCCEMAILS"]
    FROMADDRESS=VARS["FROMEMAIL"]
    FROMNAME=VARS["FROMEMAIL"]

    # TODO -- skipped over this...come back to it
    RE=r'^([[:graph:]]{1,64}@[-.[:alnum:]]{4,254})|(([[:print:]]*) *<([[:graph:]]{1,64}@[-.[:alnum:]]{4,254})>)$'
    for i in range(len(TOADDRESSES)):
        if re.match(TOADDRESSES[i], RE):
            # TODO -- find a way to convert the idea of bash_rematch to Python (search re library)
                # https://www.linuxjournal.com/content/bash-regular-expressions
            TOADDRESSES[i] =

    for i in CCADDRESSES:

    for i in BCCADDRESSES:

    for i in FROMADDRESS:

def email_checks():
    RE1=r'^.{6,254}$'
    RE2=r'^.{1,64}@'
    # TODO -- fix RE3 to fit in Python3
    RE3=r'^[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+(\.[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+)*@((xn--)?[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]\.)+(xn--)?[a-zA-Z]{2,63}$'
    for email in TOADDRESSES:
        if not (re.match(imail, RE1) and re.match(email, RE2) and re.match(email, $RE3)):
            error_exit(True, "Error: \""+email+"\" is not a valid e-mail address.")

    for email in CCADDRESSES:
        if not (re.match(email,RE1) and re.match(email,RE2) and re.match(email,RE3)):
            error_exit(True, "Error: \""+email+"\" is not a valid e-mail address.")

    for email in BCCADDRESSES:
        if not (re.match(email, RE1) and re.match(email, RE2) and re.match(email, RE3)):
            error_exit(True, "Error: \""+email+"\" is not a valid e-mail address.")

    if len(FROMADDRESS) > 0 and not (re.match(FROMADDRESS, RE2) and re.match(FROMADDRESS, RE2) and re.match(FROMADDRESS, RE3)):
        error_exit(True, "Error: \""+FROMADDRESS+"\" is not a valid e-mail address."

#TODO -- check all os.system conversions on cmdline and in the bash script
#TODO -- Ask Teal -- do you want to return standard output too? If the command fails it will just return a null string which will not trigger the if condition.

def cert_checks()
    if len(VARS["CERT"]) > 0:
        if not os.exists(VARS["CERT"]) and os.access(VARS["CERT"], os.R_OK) not os.exists(VARS["CLIENTCERT"]):
            error_exit(True, "Error: \""+CERT+"\" certificate file does not exist.")

            if not os.exists(VARS["CLIENTCERT"]):
                print("Saving the client certificate from \""+VARS["CERT"]+"\" to \""+VARS["CLIENTCERT"]+"\"")
                print("Please enter the password when prompted.\n")
                os.system("openssl pkcs12 -in "+VARS["CERT"]+" -out "+VARS["CLIENTCERT"]+" -clcerts -nodes")

            # TODO -- Teal, can/should I delete this commented out code?
            # if ! output=$(openssl verify -verify_email "$FROMADDRESS" "$CLIENTCERT" 2>/dev/null); then
                    # echo "Error verifying the S/MIME Certificate: $output" >&2
                    # exit 1
            # fi

            if aissuer=subprocess.check_output("$(openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq);", shell=True).decode().strip("\n"):
            issuer=subprocess.check_output("$(echo \""+aissuer+"\" | awk -F'=' '/commonName=/ { print $2 }')", shell=True).decode().strip("\n")
        else
            issuer=''

        date=subprocess.check_output("$(openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -enddate | awk -F'=' '/notAfter=/ { print $2 }')", shell=True).decode().strip("\n")
        if subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -checkend 0 > /dev/null;", shell=True).decode().strip("\n"):
            sec=subprocess.check_output("$(( $(date -d \""+date+"\" +%s) - $(date -d \""+NOW+"\" +%s) ))", shell=True).decode().strip("\n")
            if subprocess.check_output("$(( sec / 86400 )) -lt "+VARS["WARNDAYS"], shell=True).decode().strip("\n"):
                # TODO -- I removed the -e flag, is this okay Teal? Using os.system was printing out the flag unfrotunately instead of doing anything with it
                os.system("echo \"Warning: The S/MIME Certificate $([ -n \""+issuer+"\" ] && echo \"from “$issuer” \" || echo)expires in less than $WARNDAYS days ($(date -d \""+date+"\")).\n\"")
        else
            error_exit(True, "Error: The S/MIME Certificate $([[ -n \""+issuer+"\" ]] && echo \"from \""+issuer+"\" \" || echo)expired $(date -d \""+date+"\").\"")

def passphrase_checks():
    if len(VARS["PASSPHRASE"]) > 0:
        if not subprocess.check_output("echo \""+VARS["PASSPHRASE"]+"\" | gpg --pinentry-mode loopback --batch -o /dev/null -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0 <(echo);").decode().strip("\n"):
            error_exit(True, "Error: A PGP key pair does not yet exist for \""+FROMADDRESS+"\" or the passphrase was incorrect.")

        date=subprocess.check_output("$(gpg -k --with-colons \""+FROMADDRESS+"\" | awk -F':' '/^pub/ { print $7 }')").decode().strip("\n")
        if len(date) > 0:
            date=subprocess.check_output("$(echo \"$date\" | head -n 1)").decode().strip("\n")
            sec=subprocess.check_output("$(( date - $(date -d \"$NOW\" +%s) ))").decode().strip("\n")
            fingerprint=subprocess.check_output("$(gpg --fingerprint --with-colons \""+FROMADDRESS+"\" | awk -F':' '/^fpr/ { print $10 }' | head -n 1)").decode().strip("\n")
            if len(sec) > 0:
                if subprocess.check_output("$(( sec / 86400 )) -lt $WARNDAYS ]];").decode().strip("\n"):
                    subprocess.run("Warning: The PGP key pair for \""+FROMADDRESS+"\" with fingerprint "+fingerprint+" expires in less than "+VARS["WARNDAYS"]+" days ($(date -d \""+"\n".join(VARS["date"])+"\")).\n", shell=True)
            else
                subprocess.run("Error: The PGP key pair for \""+FROMADDRESS+"\" with fingerprint "+fingerprint+" expired $(date -d \""+"\n".join(VARS["date"])+"\").",shell=True)
                sys.exit(1)

    if len(VARS["CERT"] and len("PASSPHRASE") > 0:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")

#TODO
# Send e-mail, with optional message and attachments
# Supports Unicode characters in subject, message and attachment filename
# send <subject> [message] [attachment(s)]...
def send():
    local headers message amessage
    if len(VARS["SEND"]) > 0:
        if len(FROMADDRESS) > 0 and len(VARS["SMTP"]) > 0:
        # TODO -- stopped here
            headers=subprocess.check_output("$([ -n \""+VARS["PRIORITY"]+"\" ] && echo \"X-Priority: "+VARS["PRIORITY"]+"\n\")From: "+VARS["FROMNAME"]+"\n$(if [ \""+TONAMES+"\" -eq 0 && \""+CCNAMES"\" -eq 0 ]; then echo \"To: undisclosed-recipients: ;\n\"; else [ -n \""+TONAMES+"\" ] && echo \"To: ${TONAMES[0]}$([[ "${#TONAMES[@]}" -gt 1 ]] && printf ', %s' "${TONAMES[@]:1}")\n"; fi)$([[ -n "$CCNAMES" ]] && echo "Cc: ${CCNAMES[0]}$([[ "${#CCNAMES[@]}" -gt 1 ]] && printf ', %s' "${CCNAMES[@]:1}")\n")Subject: $(encoded-word "$1")\nDate: $(date -R)\n"
            if [[ "$#" -ge 3 ]]; then
                    message="Content-Type: multipart/mixed; boundary=\"MULTIPART-MIXED-BOUNDARY\"\n\n--MULTIPART-MIXED-BOUNDARY\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n$2\n$(for i in "${@:3}"; do echo "--MULTIPART-MIXED-BOUNDARY\nContent-Type: $(file --mime-type "$i" | sed -n 's/^.\+: //p')\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename*=utf-8''$(curl -Gs -w "%{url_effective}\\n" --data-urlencode "$(basename "$i")" "" | sed -n 's/\/?//p')\n\n$(base64 "$i")\n"; done)--MULTIPART-MIXED-BOUNDARY--"
            else
                    message="Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n$2"
            fi
            if [[ -n "$CERT" ]]; then
                    echo -e "${headers}$(echo -e "$message" | openssl cms -sign -signer "$CLIENTCERT")"
            elif [[ -n "$PASSPHRASE" ]]; then
                    amessage=$(echo -e "$message")
                    echo -e -n "${headers}MIME-Version: 1.0\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha1; boundary=\"----MULTIPART-SIGNED-BOUNDARY\"\n\n------MULTIPART-SIGNED-BOUNDARY\n"
                    echo -n "$amessage"
                    echo -e "\n------MULTIPART-SIGNED-BOUNDARY\nContent-Type: application/pgp-signature; name=\"signature.asc\"\nContent-Disposition: attachment; filename=\"signature.asc\"\n\n$(echo "$PASSPHRASE" | gpg --pinentry-mode loopback --batch -o - -ab -u "$FROMADDRESS" --passphrase-fd 0 <(echo -n "${amessage//$'\n'/$'\r\n'}"))\n\n------MULTIPART-SIGNED-BOUNDARY--"
            else
                    echo -e "${headers}MIME-Version: 1.0\n$message"
            fi | eval curl -sS"$([[ -n "$VERBOSE" ]] && echo "v" || echo)" "$SMTP" --mail-from "$FROMADDRESS" $(printf -- '--mail-rcpt "%s" ' "${TOADDRESSES[@]}" "${CCADDRESSES[@]}" "${BCCADDRESSES[@]}") -T - -u "$USERNAME:$PASSWORD"
    else
            { echo -e "$2"; [[ "$#" -ge 3 ]] && for i in "${@:3}"; do uuencode "$i" "$(basename "$i")"; done; } | eval mail $([[ -n "$FROMADDRESS" ]] && echo "-r \"$FROMADDRESS\"" || echo) $([[ -n "$CCADDRESSES" ]] && printf -- '-c "%s" ' "${CCADDRESSES[@]}" || echo) $([[ -n "$BCCADDRESSES" ]] && printf -- '-b "%s" ' "${BCCADDRESSES[@]}" || echo) -s "\"$1\"" -- "$([[ "${#TOADDRESSES[@]}" -eq 0 ]] && echo "\"undisclosed-recipients: ;\"" || printf -- '"%s" ' "${TOADDRESSES[@]}")"

def main(argv):
    parse(argv)
    args_check()
    email_checks()
    cert_checks()
    passphrase_checks()
    send(VARS["SUBJECT"], VARS["MESSAGE"], VARS["ATTACHMENTS"])

if __name__=="__main__":
    if len(sys.argv) == 0:
        usage()
        sys.exit(1)

    main(sys.argv[1:])

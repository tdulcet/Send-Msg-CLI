#!/usr/bin/env python3

import sys, os, socket, re
import getopt
import datetime
import subprocess

sys.path.append(os.environ["PWD"]) # allows "from" to be used (FIXME and the path of this module permanently to the environment so Python can search there and not have this line here
from send import send # how we send emails
import usage

'''The purpose of this file is to parse all flags given on the cmdline.
   Skipping to the bottom main function is where the control-flow begins.
'''

###Variables###

VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"3","CERT":"","CLIENTCERT":"","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":0,"NOW":datetime.datetime.now().strftime("%A, %B %d. %Y %I:%M%p"),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[], "DRYRUN": False}
CONFIG_FILE="~/.sendmsg"

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
            VARS["DRYRUN"] = True
        elif opt in ("-e", "--examples"):
            usage.examples()
            sys.exit(0)
        elif opt in ("-f", "--fromemail"):
            VARS["FROMEMAIL"] = arg
        elif opt in ("-h", "--help"):
            usage.usage()
            sys.exit(0)
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
            VARS["ZIPFILE"]= arg+".zip"
        elif opt in ("-C", "--cert"):
            VARS["CERT"]= arg
        elif opt in ("-P", "--priority"):
            VARS["PRIORITY"]= arg
        elif opt in ("-S", "--smtp"):
            VARS["SMTP"]= arg
        elif opt in ("-V", "--VERBOSE"):
            VARS["VERBOSE"]= arg

# TODO
def configuration_assignment():
    '''If a user decides, they may work from a configuration file. If the file has something in it
       and the user does not specify a necessary flag (e.g., -f), then the program will use this file
       to fill in the blanks
    '''
    if not os.path.exists(CONFIG_FILE):
        with open(os.path.expanduser(CONFIG_FILE), "w") as f1:
            # make file with appropriate fields
            pass

    with open(os.path.expanduser(CONFIG_FILE), "r") as f1:
        # read from config file
        pass

    pass

def parse(argv):
    '''Find the correct variable to assign the opt to.'''
    # Parsing. Erroneous flags throw exception.
    try:
        # TODO -- "passphrase" does not match with variable 'k'. Why not use "key"? Ask Teal
        opts, args = getopt.getopt(argv,"a:b:c:def:hk:m:p:s:t:u:vz:C:P:S:V",
                ["attachments=", "bccemails=", "ccemails=", "dryrun=", "examples","fromemail=", "help",
                    "passphrase=", "subject=", "toaddress=", "username=", "version", "zipfile=",
                    "cert=", "priority=", "smtp=", "verbose="])
    except getopt.GetoptError:
        print(error)
        usage()
        sys.exit(2)
    assign(opts)


def attachment_work():
    if VARS["ATTACHMENTS"]:
        TOTAL=0
        table=''
        for attachment in VARS["ATTACHMENTS"]:
            if not attachment or not (os.path.exists(attachment) and os.access(attachment, os.R_OK)): # [-r ..] in bash
                error_exit(True, f'Error: Cannot read {attachment} file.')

        zip_file = VARS["ZIPFILE"]
        if len(zip_file) > 0:
            if os.path.exists(zip_file):
                error_exit(True, f'Error: File {zip_file} already exists.')

            os.system("zip -q " + zip_file + " " + " ".join(VARS["ATTACHMENTS"]))
            VARS["ATTACHMENTS"] = [zip_file]

        # checking if attachment size are > 25 MB
        print("Attachments:")
        for attachment in VARS["ATTACHMENTS"]:
            SIZE=subprocess.check_output("du -b \""+attachment+"\" | awk '{ print $1 }'", shell=True).decode().strip("\n")
            TOTAL +=int(SIZE)
            table+=attachment+"\t$(numfmt --to=iec-i \""+SIZE+"\")B$([ "+SIZE+" -ge 1000 ] && echo \"\t($(numfmt --to=si \""+SIZE+"\")B)\" || echo)\n"
        os.system("echo \""+table+"\" | column -t -s '\t'")
        os.system("echo \"\nTotal Size:\t$(numfmt --to=iec-i \""+str(TOTAL)+"\")B$([ "+str(TOTAL)+" -ge 1000 ] && echo \" ($(numfmt --to=si \""+str(TOTAL)+"\")B)\")\n\"")
        if TOTAL >= 26214400:
            error_exit(True, "Warning: The total size of all attachments is greater than or equal to 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"
def email_checks():
    TOADDRESSES=VARS["TOEMAILS"]
    TONAMES=VARS["TOEMAILS"]
    CCADDRESSES=VARS["CCEMAILS"]
    CCNAMES=VARS["CCEMAILS"]
    BCCADDRESSES=VARS["BCCEMAILS"]
    FROMADDRESS=VARS["FROMEMAIL"]
    FROMNAME=VARS["FROMEMAIL"]
    RE=re.compile('(?:"?([^"]*)"?\s)?(?:<?(.+@[^>]+)>?)') # https://regex101.com/r/dR8hL3/1

    # Note: we do not need to split up the name and email address (email library accepts "name <email>" pattern). Only check if the email is valid.
    try:
        for i in range(0, len(TOADDRESSES)):
            result = RE.match(TOADDRESSES[i])
            if result:
                TOADDRESSES[i] = result.group(2)
            else:
                error_exit(True, "Error: \""+TOADDRESSES[i]+"\" is not a valid e-mail address.")

        for i in range(0, len(CCADDRESSES)):
            result = RE.match(CCADDRESSES[i])
            if result:
                CCADDRESSES[i]=result.group(2)
            else:
                error_exit(True, "Error: \""+CCADDRESSES[i]+"\" is not a valid e-mail address.")

        for i in range(0, len(BCCADDRESSES)):
            result = RE.match(BCCADDRESSES[i])
            if result:
                BCCADDRESSES[i]=result.group(2)
            else:
                error_exit(True, "Error: \""+BCCADDRESSES[i]+"\" is not a valid e-mail address.")

        if len(FROMADDRESS)>0:
            result = RE.match(FROMADDRESS)
            if result:
                FROMADDRESS=result.group(2)
            else:
                error_exit(True, "Error: \""+FROMADDRESS+"\" is not a valid e-mail address.")

        print(VARS["TOEMAILS"])
    except Exception as error:
        error_exit(True, error)

#TODO -- Ask Teal -- do you want to return standard output too? If the command fails it will just return a null string which will not trigger the if condition.
def cert_checks():
    if len(VARS["CERT"]) > 0:
        if not os.path.exists(VARS["CERT"]) and os.access(VARS["CERT"], os.R_OK) and not os.path.exists(VARS["CLIENTCERT"]):
            error_exit(True, "Error: \""+CERT+"\" certificate file does not exist.")

        if not os.path.exists(VARS["CLIENTCERT"]):
            print("Saving the client certificate from \""+VARS["CERT"]+"\" to \""+VARS["CLIENTCERT"]+"\"")
            print("Please enter the password when prompted.\n")
            os.system("openssl pkcs12 -in "+VARS["CERT"]+" -out "+VARS["CLIENTCERT"]+" -clcerts -nodes")

        # TODO -- Teal, can/should I delete this commented out code?
        # if ! output=$(openssl verify -verify_email "$FROMADDRESS" "$CLIENTCERT" 2>/dev/null); then
                # echo "Error verifying the S/MIME Certificate: $output" >&2
                # exit 1
        # fi

        aissuer=subprocess.check_output("$(openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq);", shell=True).decode().strip("\n")
        if aissuer:
            issuer=subprocess.check_output("$(echo \""+aissuer+"\" | awk -F'=' '/commonName=/ { print $2 }')", shell=True).decode().strip("\n")
        else:
            issuer=''

        date=subprocess.check_output("$(openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -enddate | awk -F'=' '/notAfter=/ { print $2 }')", shell=True).decode().strip("\n")
        if subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -checkend 0 > /dev/null;", shell=True).decode().strip("\n"):
            sec=subprocess.check_output("$(( $(date -d \""+date+"\" +%s) - $(date -d \""+NOW+"\" +%s) ))", shell=True).decode().strip("\n")
            if subprocess.check_output("$(( sec / 86400 )) -lt "+VARS["WARNDAYS"], shell=True).decode().strip("\n"):
                print("echo \"Warning: The S/MIME Certificate $([ -n \""+issuer+"\" ] && echo \"from “$issuer” \" || echo)expires in less than "+VARS["WARNDAYS"]+" days "+ subprocess.check_output("($(date -d \""+date+"\")).\n\"").decode())
        else:
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
            else:
                subprocess.run("Error: The PGP key pair for \""+FROMADDRESS+"\" with fingerprint "+fingerprint+" expired $(date -d \""+"\n".join(VARS["date"])+"\").",shell=True)
                sys.exit(1)

    if len(VARS["CERT"]) > 0 and len(VARS["PASSPHRASE"]) > 0:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")

def main(argv):
    # parsing
    parse(argv)

    # checks
    email_checks()
    attachment_work()
    cert_checks()
    passphrase_checks()

    # sending
    if not VARS["DRYRUN"]:
        send(VARS["SUBJECT"], VARS["MESSAGE"], VARS["USERNAME"], VARS["PASSWORD"], VARS["TOEMAILS"], VARS["CCEMAILS"], VARS["BCCEMAILS"], VARS["NOW"], VARS["ATTACHMENTS"], VARS["PRIORITY"], VARS["SMTP"], VARS["VERBOSE"])
        if VARS["ZIPFILE"]:
            print(VARS["ZIPFILE"])
            os.system("trap 'rm " + VARS["ZIPFILE"] + "\' EXIT")

if __name__=="__main__":
    if len(sys.argv) == 0:
        usage()
        sys.exit(1)

    main(sys.argv[1:])

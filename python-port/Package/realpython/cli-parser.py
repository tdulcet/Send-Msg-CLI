#!/usr/bin/env python3

import sys
import getopt
import datetime
import socket

sys.path.append(os.environ["PWD"]) # allows "from" to be used (FIXME and the path of this module permanently to the environment so Python can search there and not have this line here
from send import Send # how we send emails
import usage

# TODOS
'''
1. Delete (or implement functionality for) Verbose flag?
'''

'''The purpose of this file is to parse all flags given on the cmdline.
   Skipping to the bottom main function is where the control-flow begins.
'''

###Variables
VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"Normal","CERT":"cert.p12","CLIENTCERT":"cert.pem","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":"1","NOW":datetime.datetime.now().strftime("%A, %B %d. %Y %I:%M%p"),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[], "DRYRUN": False}

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
        elif opt in ("-f", "--fromemail"):
            VARS["FROMEMAIL"] = arg
        elif opt in ("-h", "--help"):
            usage()
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

def attachment_checks():
    if VARS["ATTACHMENTS"]:
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

        '''
        # TODO # Creating something to do with attachments
        for attachment in VARS["ATTACHMENTS"]:
            pass



        if TOTAL >= 26214400:
            error_exit(True, "Warning: The total size of all attachments is greater than 25 MiB. The message may     be rejected by your or the recipient's mail server. You may want to upload large files to an external stor    age service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")
        '''

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"

def email_checks():
    RE1=r'^.{6,254}$'
    RE2=r'^.{1,64}@'
    # TODO -- fix RE3 to fit in Python3
    RE3 = r'^.{1,64}@'
    ##RE3=r'^[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+(\.[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+)*@((xn--)?[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]\.)+(xn--)?[a-zA-Z]{2,63}$'
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
                #TODO -- delete
                #os.system("echo \"Warning: The S/MIME Certificate $([ -n \""+issuer+"\" ] && echo \"from “$issuer” \" || echo)expires in less than $WARNDAYS days ($(date -d \""+date+"\")).\n\"")
                print("echo \"Warning: The S/MIME Certificate $([ -n \""+issuer+"\" ] && echo \"from “$issuer” \" || echo)expires in less than "+VARS["WARNDAYS"]+" days "+ subprocess.check_output("($(date -d \""+date+"\")).\n\"").decode())
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

def main(argv):
    # parsing
    parse(argv)

    # checks
    email_checks()
    attachment_checks()
    cert_checks()
    passphrase_checks()

    # sending
    if not VARS["DRYRUN"]:
        send(VARS["SUBJECT"], VARS["MESSAGE"], VARS["USERNAME"], VARS["PASSWORD"], VARS["TOEMAILS"], VARS["BCCEMAILS"], VARS["NOW"], VARS["ATTACHMENTS"])

if __name__=="__main__":
    if len(sys.argv) == 0:
        usage()
        sys.exit(1)

    main(sys.argv[1:])

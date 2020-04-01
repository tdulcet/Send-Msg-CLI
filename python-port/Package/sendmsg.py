#!/usr/bin/env python3

import sys, os, socket, re
import getopt
import datetime, time
import subprocess

sys.path.append(os.environ["PWD"]) # allows "from" to be used (FIXME and the path of this module permanently to the environment so Python can search there and not have this line here
from send import send # how we send emails
import usage, configuration

'''The purpose of this file is to parse all flags given on the cmdline.
   Skipping to the bottom main function is where the control-flow begins.
'''

###Variables###

#VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"3","CERT":"","CLIENTCERT":"cert.pem","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":0,"NOW":datetime.datetime.now().strftime("%b %d %H:%M:%S %Y %Z"),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[], "DRYRUN": False}
VARS={"TOEMAILS":[],"CCEMAILS":[],"BCCEMAILS":[],"FROMEMAIL":'',"SMTP":'',"USERNAME":'',"PASSWORD":'',"PRIORITY":"3","CERT":"","CLIENTCERT":"cert.pem","PASSPHRASE":'',"WARNDAYS":"3","ZIPFILE":'',"VERBOSE":0,"NOW":time.strftime("%b %d %H:%M:%S %Y %Z", time.gmtime()),"SUBJECT":'',"MESSAGE":'',"ATTACHMENTS":[], "DRYRUN": False}

CONFIG_FILE="~/.sendmsg.ini"

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
        elif opt in ("-g", "--gateways"):
            usage.carriers()
            sys.exit(0)
        elif opt in ("-h", "--help"):
            usage.usage()
            sys.exit(0)
        elif opt in ("-k", "--passphrase"):
            VARS["PASSPHRASE"]=arg
        elif opt in ("-m", "--message"):
            VARS["MESSAGE"]=arg
        elif opt in ("-p", "--password"):
            VARS["PASSWORD"]=arg
        elif opt in ("--config"):
            # make config file with appropriate fields if file does not exist
            if not os.path.exists(os.path.expanduser(CONFIG_FILE)):
                print(f'Creating configuration file on path {CONFIG_FILE}....')
                with open(os.path.expanduser(CONFIG_FILE), "w") as f1:
                    f1.write("[email]\nsmtp =\nusername =\npassword =")
            configuration.config_email()
            sys.exit(0)
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


def configuration_assignment():
    '''If a user decides, they may work from a configuration if the user does not specify a necessary
       flag (e.g., -u). If the config file is empty, an error will be thrown.
    '''
    print("SMTP, Username or Password not set not typed on CMDline. Checking configfile...")
    # make file with appropriate fields if file does not exist
    if not VARS["SMTP"] or not VARS["USERNAME"] or not VARS["PASSWORD"]:
        if not os.path.exists(os.path.expanduser(CONFIG_FILE)):
            error_exit(True, "SMTP, Username or Password not set in config file and not typed on CMDline. Please include the -S, -u, or -p flags or use the following command to set the config file: `sendmsg --config`")
        else:
            VARS["SMTP"], VARS["USERNAME"], VARS["PASSWORD"] = configuration.send_mail()

def parse_assign(argv):
    '''Find the correct variable to assign the opt to.'''
    # Parsing. Erroneous flags throw exception.
    try:
        opts, args = getopt.getopt(argv,"a:b:c:def:ghk:m:p:rs:t:u:vz:C:P:S:V",
                ["attachments=", "bccemails=", "ccemails=", "dryrun=", "examples","fromemail=", "gateways",
                    "help", "passphrase=", "message=", "password=", "config", "subject=", "toaddress=", "username=", "version", "zipfile=",
                    "cert=", "priority=", "smtp=", "verbose="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    assign(opts)

# modified from source: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def convert_bytes(size, byte_type):
   byte_array = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB'] if byte_type == "i" else ['bytes', 'KB', 'MB', 'GB', 'TB']
   div_size = 1024.0 if byte_type == "i" else 1000.0

   for x in byte_array:
       if size < div_size:
           return "%3.1f %s" % (size, x)
       size = round(size / div_size, 1)

   return size

# user codeskyblue from: https://stackoverflow.com/questions/19103052/python-string-formatting-columns-in-line
def format_attachment_output(rows):
    lens = []
    for col in zip(*rows):
        lens.append(max([len(v) for v in col]))
    format = "  ".join(["{:<" + str(l) + "}" for l in lens])
    for row in rows:
        print(format.format(*row))

def attachment_work():
    if VARS["ATTACHMENTS"]:
        TOTAL=0
        rows = []
        for attachment in VARS["ATTACHMENTS"]:
            if not attachment or not (os.path.exists(attachment) and os.access(attachment, os.R_OK)): # [-r ..] in bash
                error_exit(True, f'Error: Cannot read {attachment} file.')

        zip_file = VARS["ZIPFILE"]
        if len(zip_file) > 0:
            if os.path.exists(zip_file):
                error_exit(True, f'Error: File {zip_file} already exists.')

            import zipfile
            with zipfile.ZipFile(zip_file, 'w') as myzip:
                for attachment in VARS["ATTACHMENTS"]:
                    myzip.write(attachment)
            VARS["ATTACHMENTS"] = [zip_file]

        # checking if attachment size are > 25 MB
        print("Attachments:")
        for attachment in VARS["ATTACHMENTS"]:
            SIZE=os.path.getsize(attachment)
            TOTAL +=int(SIZE)
            rows.append((attachment, convert_bytes(int(SIZE), "i"), "("+convert_bytes(int(SIZE), "b")+")"))

        rows.append(("\nTotal Size:", convert_bytes(int(TOTAL),"i"), "("+convert_bytes(int(TOTAL),"b")+")"))
        format_attachment_output(rows)

        if TOTAL >= 26214400:
            error_exit(True, "Warning: The total size of all attachments is greater than or equal to 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"
def email_checks():
    global TOADDRESSES
    global CCADDRESSES
    global BCCADDRESSES
    global FROMADDRESS

    TOADDRESSES=VARS["TOEMAILS"]
    CCADDRESSES=VARS["CCEMAILS"]
    BCCADDRESSES=VARS["BCCEMAILS"]
    FROMADDRESS=VARS["FROMEMAIL"]
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

    except Exception as error:
        error_exit(True, error)

def cert_checks():
    '''Creates the .pem certificate (defined in VARS["CLIENTCERT"]; e.g., cert.pem) with certificate \
       located in VARS["CERT"] (read in from CMDLINE using -C, or --cert)
    '''
    try:
        import smime
    except ImportError as error:
        print("Installing smime dependency")
        p = subprocess.run('pip install smime', shell=True)
        import smime
    except Exception as error:
        misc_check(true, "Unexpected error occured when installing smime Python dependency:\n\n" + error)

    if len(VARS["CERT"]) > 0:
        if not os.path.exists(VARS["CERT"]) and os.access(VARS["CERT"], os.R_OK) and not os.path.exists(VARS["CLIENTCERT"]):
            error_exit(True, "Error: \""+CERT+"\" certificate file does not exist.")

        if not os.path.exists(VARS["CLIENTCERT"]):
            print("Saving the client certificate from \""+VARS["CERT"]+"\" to \""+VARS["CLIENTCERT"]+"\"")
            print("Please enter the password when prompted.\n")
            subprocess.run("openssl pkcs12 -in "+VARS["CERT"]+" -out "+VARS["CLIENTCERT"]+" -clcerts -nodes",shell=True)
        print(VARS["CERT"])
        print(VARS["CLIENTCERT"])

        aissuer=subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq;", shell=True).decode().strip("\n")
        print("Aissuer " + str(aissuer))
        if aissuer:
            #issuer=subprocess.check_output("echo \""+aissuer+"\" | awk -F'=' '/commonName=/ { print $2 }'", shell=True).decode().strip("\n")
            #print(aissuer.split("/"))

            for line in aissuer.split("commonName="):
                print("LINE: " + line)
                issuer=line
            print("issuer " + issuer)
        else:
            issuer=''

        date=subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -enddate | awk -F'=' '/notAfter=/ { print $2 }'", shell=True).decode().strip("\n")
        print("Date1 : " + date)
        date=subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -enddate -nameopt multiline,-align,-esc_msb,utf8,-space_eq;", shell=True).decode().strip("\n")
        if date.split("notAfter="):
            print("YES A DATE " + date)
            for line in date.split("notAfter="):
                print("LINE: " + line)
                date=line
        else:
            date=""

        print("Date12 : " + date)
        #if subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -checkend 0 > /dev/null;", shell=True).decode().strip("\n"): # TODO -- talk to Teal. I had to remove the > /dev/null to get any output ("Certificate will not expire" specifically...). Maybe change to comapre to this output?
        if subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -checkend 0", shell=True).decode().strip("\n"):
            print("HERE")
            print(date)
            #date = "Mar 31 22:46:20 2021 GMT"
            print(time.mktime(datetime.datetime.strptime(VARS["NOW"], "%b %d %H:%M:%S %Y %Z").timetuple()))
            sec1=subprocess.check_output("date -d \""+date+"\" +%s", shell=True).decode().strip("\n")
            print("sec1: " +str(sec1))
            # TODO -- fix VARS["NOW"] command
            sec2 =subprocess.check_output("date -d \""+VARS["NOW"]+"\" +%s", shell=True).decode().strip("\n")
            print("sec2: " +str(sec2))
            sec = int(sec1)-int(sec2)
            print("SEC: " + str(sec))

            if sec / 86400 < int(VARS["WARNDAYS"]):
                print("echo \"Warning: The S/MIME Certificate $([ -n \""+issuer+"\" ] && echo \"from “$issuer” \" || echo)expires in less than "+VARS["WARNDAYS"]+" days "+ subprocess.check_output("($(date -d \""+date+"\")).\n\"").decode())
        else:
            error_exit(True, "Error: The S/MIME Certificate $([[ -n \""+issuer+"\" ]] && echo \"from \""+issuer+"\" \" || echo)expired $(date -d \""+date+"\").\"")

def passphrase_checks():

    if len(VARS["PASSPHRASE"]) > 0:
        if not subprocess.check_output("echo \""+VARS["PASSPHRASE"]+"\" | gpg --pinentry-mode loopback --batch -o /dev/null -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0 <(echo)", shell=True).decode().strip("\n"):
            error_exit(True, "Error: A PGP key pair does not yet exist for \""+FROMADDRESS+"\" or the passphrase was incorrect.")

        date=subprocess.check_output("$(gpg -k --with-colons \""+FROMADDRESS+"\" | awk -F':' '/^pub/ { print $7 }')").decode().strip("\n")
        if len(date) > 0:
            date=subprocess.check_output("$(echo \"$date\" | head -n 1)").decode().strip("\n")
            sec=subprocess.check_output("$(( date - $(date -d \"$NOW\" +%s) ))").decode().strip("\n")
            fingerprint=subprocess.check_output("$(gpg --fingerprint --with-colons \""+FROMADDRESS+"\" | awk -F':' '/^fpr/ { print $10 }' | head -n 1)", shell=True).decode().strip("\n")
            if len(sec) > 0:
                if subprocess.check_output("$(( sec / 86400 )) -lt $WARNDAYS ]];", shell=True).decode().strip("\n"):
                    subprocess.run("Warning: The PGP key pair for \""+FROMADDRESS+"\" with fingerprint "+fingerprint+" expires in less than "+VARS["WARNDAYS"]+" days ($(date -d \""+"\n".join(VARS["date"])+"\")).\n", shell=True)
            else:
                subprocess.run("Error: The PGP key pair for \""+FROMADDRESS+"\" with fingerprint "+fingerprint+" expired $(date -d \""+"\n".join(VARS["date"])+"\").",shell=True)
                sys.exit(1)

    if len(VARS["CERT"]) > 0 and len(VARS["PASSPHRASE"]) > 0:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")

def main(argv):
    # parsing/assignment
    parse_assign(argv)
    configuration_assignment() # use default configuration if nothing was put on the CMDline

    # email checks
    email_checks()
    attachment_work()

    # Cert checks
    from shutil import which
    if which("openssl") is not None and which("gpg") is not None: # USE commands
        cert_checks()
        passphrase_checks()
    else: # TODO -- use third party libraries to do .pem creation and signing of email messages
        pass

    # sending
    if not VARS["DRYRUN"]:
        send(VARS["SUBJECT"], VARS["MESSAGE"], VARS["USERNAME"], VARS["PASSWORD"], VARS["TOEMAILS"], VARS["CCEMAILS"], VARS["BCCEMAILS"], VARS["NOW"], VARS["ATTACHMENTS"], VARS["PRIORITY"], VARS["SMTP"], VARS["VERBOSE"])
        if VARS["ZIPFILE"]:
            os.remove(VARS["ZIPFILE"])

if __name__=="__main__":
    if len(sys.argv) == 0:
        usage()
        sys.exit(1)

    main(sys.argv[1:])
    print("Message sent")

#!/usr/bin/env python3

import sys, os
import re
import getopt
import datetime, time
import subprocess
import codecs # for decode escapes
from shutil import which # discover if OpenSSL and/or gpg are in the system
import atexit

#sys.path.append(os.environ["PWD"]) # allows "from" to be used (FIXME and the path of this module permanently to the environment so Python can search there and not have this line here
from send import sendEmail # how we send emails
import usage, configuration

'''The purpose of this file is to
   1. parse all flags given on the cmdline.
   2. do checks to see if those files are valid
   3. handle escape characters appropriately
'''

# Default Variables

VARS={"TOEMAILS":[],
        "CCEMAILS":[],
        "BCCEMAILS":[],
        "FROMEMAIL":'',
        "SMTP":'',
        "USERNAME":'',
        "PASSWORD":'',
        "PRIORITY":"",
        "PORT":0,
        "CERT":'',
        "CLIENTCERT":"cert.pem",
        "PASSPHRASE":'',
        "WARNDAYS":"3",
        "ZIPFILE":'',
        "VERBOSE":False,
        "NOW":time.strftime("%b %d %H:%M:%S %Y %Z", time.gmtime()),
        "SUBJECT":'',
        "MESSAGE":'',
        "ATTACHMENTS":[],
        "SMIME": '',
        "PGP": '',
        "DRYRUN": False}

# Stores default SMTP server, username, password if `--config` option is set.
CONFIG_FILE="~/.sendmsg.ini"

# ESCAPE_SEQUENCE_RE and decode_escapes credit -- https://stackoverflow.com/a/24519338/8651748
ESCAPE_SEQUENCE_RE = re.compile(r'''(\\U[0-9a-fA-F]{8}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\N\{[^}]+\}|\\[\\'"abfnrtv])''', re.UNICODE)

def zero_pad(message):
    '''zero_pad unicode characters (\ u and \ U) and octals, since python doesn't support this'''
    new_string = ""
    start_index = 0
    inner_start_index = 0
    end = 0
    while start_index < len(message):
        for i in range(start_index, len(message)):
            count = 0 # track number of unicode characters
            begin_index = 0 # index where we found a match
            new_string += message[i] # regularly adding to our
            if message[i] == "\\" and (message[i+1] == "u" or message[i+1] == "U" or message[i+1] == "x"): # two cases of < 4 digit unicode characters (in binary or hex)
                new_string += message[i+1] # u, U, or x
                i+=2
                begin_index = i
                inner_start_index += i
                start_index = i
                for j in range(inner_start_index, len(message)-1):
                    if count >= 5: # we have a 4 or 8 sized unicode (e.g., \u0000), don't zero-pad
                        break
                    if message[j] != ' ' and message[j] != '\\':
                        count+=1
                    if message[j] == ' ' or message[j] == '\\': # \\ = start of new unicode
                        #print(f'Count {count}')
                        #print("CURRENT STRING: " + new_string)

                        # Zero pad
                        for k in range(0, 4-count):
                            new_string +='0'
                            print(new_string)

                        # add back in characters
                        for k in range(0, count):
                            new_string+=message[begin_index]
                            begin_index +=1
                            print(new_string)
                        #new_string += ' '
                        start_index += count
                        end = i
                        break
                break
                count = 0
            else:
                end+=1
            start_index += 1
    print()
    print("NEW_STRING")
    print(new_string)
    #sys.exit()
    return new_string

def decode_escapes(s):
    def decode_match(match):
        return codecs.decode(match.group(0), 'unicode-escape')

    return ESCAPE_SEQUENCE_RE.sub(decode_match, s)

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
            if not VARS["FROMEMAIL"]:
                VARS["FROMEMAIL"] = arg
            else:
                error_exit(True, "Only one 'from' address must be specified as.")
        elif opt in ("-g", "--gateways"):
            usage.carriers()
            sys.exit(0)
        elif opt in ("-h", "--help"):
            usage.usage()
            sys.exit(0)
        elif opt in ("-k", "--passphrase"):
            VARS["PASSPHRASE"]=arg
        elif opt in ("-m", "--message"):
            VARS["MESSAGE"] = zero_pad(arg)
            VARS["MESSAGE"] = decode_escapes(VARS["MESSAGE"])
            print(VARS["MESSAGE"])
            print("HERE")
            #sys.exit()
        elif opt in ("-p", "--password"):
            VARS["PASSWORD"]=arg
        elif opt in ("--config"):
            # make config file with appropriate fields if file does not exist
            configuration.config_email()
            print("Configuration file successfully set\n")
            sys.exit(0)
        elif opt in ("-s", "--subject"):
            VARS["SUBJECT"] = decode_escapes(arg)
        elif opt in ("-t", "--toemails"):
            VARS["TOEMAILS"].append(arg)
        elif opt in ("-u", "--username"):
            VARS["USERNAME"]= arg
        elif opt in ("-v", "--version"):
            print("Send Msg CLI 1.0\n")
            sys.exit(0)
        elif opt in ("-z", "--zipfile"):
            if arg.endswith('.zip'):
                VARS["ZIPFILE"]= arg
            else:
                VARS["ZIPFILE"]= arg+".zip"
        elif opt in ("-C", "--cert"):
            VARS["CERT"]= arg
        elif opt in ("-P", "--priority"):
            VARS["PRIORITY"]= arg
        elif opt in ("-S", "--smtp"):
            res = arg.split(":")
            if len(res) > 1:
                VARS["SMTP"] = res[0]
                VARS["PORT"] = res[1]
            else:
                VARS["PORT"] = 0
        elif opt in ("-V", "--VERBOSE"):
            VARS["VERBOSE"]= True

def configuration_assignment():
    '''If a user decides, they may work from a configuration if the user does not specify a necessary
       flag (e.g., -u). If the config file is empty, an error will be thrown.
    '''
    # make file with appropriate fields if file does not exist
    if not VARS["SMTP"] or not VARS["FROMEMAIL"] or not VARS["USERNAME"] or not VARS["PASSWORD"]:
        if not os.path.exists(os.path.expanduser(CONFIG_FILE)):
            error_exit(True, "Error: SMTP server, From, Username or Password fields not set in config file and not typed on CMDline. Please include the -S, -f, -u, or -p flags or use the following command to set the config file: `sendmsg --config`")
        else:
            print("SMTP server, From, Username or Password fields not typed on CMDline. Checking configfile...\n")
            VARS["SMTP"], VARS["FROMEMAIL"], VARS["USERNAME"], VARS["PASSWORD"] = configuration.return_config()

def parse_assign(argv):
    '''Find the correct variable to assign the arg/opt to.'''
    try:
        opts, args = getopt.getopt(argv,"a:b:c:def:ghk:m:p:rs:t:u:vz:C:P:S:V",
                ["attachments=", "bccemails=", "ccemails=", "dryrun", "examples","fromemail=", "gateways",
                    "help", "passphrase=", "message=", "password=", "config", "subject=", "toaddress=", "username=", "version", "zipfile=",
                    "cert=", "priority=", "smtp=", "verbose"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    assign(opts)

# modified from source: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def convert_bytes(size, byte_type):
    '''Calculates how large an attachment in two ways -- iB and B'''
    byte_array = ['Bytes', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
    div_size = 1024.0 if byte_type == "i" else 1000.0

    for x in byte_array:
        if size < div_size:
            import locale
            locale.setlocale(locale.LC_ALL, '')
            unit = x + ('' if x == 'Bytes' else ('i' if byte_type == 'i' else '') + 'B')
            return f'{size:,.1f}{unit}'
        size = round(size / div_size, 1)

    return size

# user codeskyblue from: https://stackoverflow.com/questions/19103052/python-string-formatting-columns-in-line
def format_attachment_output(rows):
    '''Spaces the printing of attachments based on largest length. A replacement for the column cmd.
       Also used for printing out our help menus found in usage.py.
    '''
    lens = []
    for col in zip(*rows):
        lens.append(max([len(v) for v in col]))
    format = "  ".join(["{:<" + str(l) + "}" for l in lens])
    for row in rows:
        print(format.format(*row).strip('\n'))

def attachment_work():
    '''Zips files to send in msg if user specifies the '-z' flag. Will also calculate size of attachments
       and warn user if size is large.
    '''
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
            atexit.register(lambda x: os.remove(x), zip_file)
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
            print("Warning: The total size of all attachments is greater than or equal to 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")

def email_work():
    '''Get e-mail address(es): "Example <example@example.com>" -> "example@example.com". Also check for
       valid email addresses. Note: We don't need to separate name and email address, since the email
       library will do this parsing on its own.
    '''
    global FROMADDRESS
    FROMADDRESS=VARS["FROMEMAIL"]
    #RE=re.compile('(?:"?([^"]*)"?\s)?(?:<?(.+@[^>]+)>?)') # https://regex101.com/r/dR8hL3/1 # TODO -- needs a check for a '.'. The current one doesn't work on, for example, 'danc2@pdxedu'. But this parses "Example <email@example.com>" correctly.)
    RE=re.compile('(?:"?([^"]*)"?\s)?[%<a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.>]+')
    #RE=re.compile('(?:"?([^"]*)"?\s)?[<a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.>]+')

    # Check if the email is valid.
    try:
        for i in range(0, len(VARS["TOEMAILS"])):
            result = RE.match(VARS["TOEMAILS"][i])
            if not result:
                error_exit(True, "Error: \""+VARS["TOEMAILS"][i]+"\" is not a valid e-mail address.")

        for i in range(0, len(VARS["CCEMAILS"])):
            result = RE.match(VARS["CCEMAILS"][i])
            if not result:
                error_exit(True, "Error: \""+VARS["CCEMAILS"][i]+"\" is not a valid e-mail address.")

        for i in range(0, len(VARS["BCCEMAILS"])):
            result = RE.match(VARS["BCCEMAILS"][i])
            if not result:
                print("HER")
                error_exit(True, "Error: \""+VARS["BCCEMAILS"][i]+"\" is not a valid e-mail address.")

        if FROMADDRESS:
            result = RE.match(FROMADDRESS)
            #print(result.group(0))
            if result:
                FROMADDRESS=result.group(0) # changes to 1 if using another regex.
            else:
                error_exit(True, "Error: \""+FROMADDRESS+"\" is not a valid e-mail address.")
        else:
            error_exit(True, "Error: Must specify FROM e-mail address.")
    except Exception as error:
        error_exit(True, error)
    sys.exit()

def cert_checks():
    '''Creates the .pem certificate (defined in VARS["CLIENTCERT"]; e.g., cert.pem) with certificate \
       located in VARS["CERT"] (read in from CMDLINE using -C, or --cert)
    '''

    if len(VARS["CERT"]) > 0:
        if which("openssl") is None:
            error_exit(True, "Error: OpenSSL not found. You need this to sign a message with S/MIME")

        if not os.path.exists(VARS["CERT"]) and os.access(VARS["CERT"], os.R_OK) and not os.path.exists(VARS["CLIENTCERT"]):
            error_exit(True, "Error: \""+CERT+"\" certificate file does not exist.")

        if not os.path.exists(VARS["CLIENTCERT"]):
            print("Saving the client certificate from \""+VARS["CERT"]+"\" to \""+VARS["CLIENTCERT"]+"\"")
            print("Please enter the password when prompted.\n")
            subprocess.check_output("openssl pkcs12 -in "+VARS["CERT"]+" -out "+VARS["CLIENTCERT"]+" -clcerts -nodes",shell=True).decode().strip("\n")
        aissuer=subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq;", shell=True).decode().strip("\n")
        print(aissuer)
        if aissuer:
            for line in aissuer.split("commonName="):
                issuer=line
        else:
            issuer=''

        date=subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -enddate -nameopt multiline,-align,-esc_msb,utf8,-space_eq;", shell=True).decode().strip("\n")
        split = date.split("notAfter=")
        if split:
            for line in split:
                date=line
        else:
            date=""

        if subprocess.check_output("openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -checkend 0", shell=True).decode().strip("\n"):
            sec = int(time.mktime(datetime.datetime.strptime(date, "%b %d %H:%M:%S %Y %Z").timetuple()) - time.mktime(datetime.datetime.strptime(VARS["NOW"], "%b %d %H:%M:%S %Y %Z").timetuple()))
            if sec / 86400 < int(VARS["WARNDAYS"]):
                if issuer:
                    print(f'Warning: The S/MIME Certificate from \"{issuer}\" expires in less than ' + VARS["WARNDAYS"]+ f' days {date}')
                else:
                    print(f'Warning: The S/MIME Certificate expires in less than ' + VARS["WARNDAYS"]+ f' days {date}')

        else:
            error = "Error: The S/MIME Certificate from \"{issuer}\" expired {date}" if issuer else "Error: The S/MIME Certificate expired {date}"
            error_exit(True, error)

def passphrase_checks():
    '''Does a number of checks if a user indicated they watn to sign with a GPG key to utilize PGP/MIME'''
    if len(VARS["PASSPHRASE"]) > 0:
        if which("gpg") is None:
            error_exit(True, "Error: GPG not found. You need this to sign a message with PGP/MIME")

        # create file to be written out, then schedule it to be removed if an exit occurs
        with open("temp_message", "w") as f1:
            f1.write(VARS["MESSAGE"])
        atexit.register(lambda x: os.remove(x), 'temp_message')

        # check if GPG key exists
        #if not "BEGIN PGP SIGNATURE" in subprocess.check_output("gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase \""+VARS["PASSPHRASE"]+"\" temp_message", shell=True).decode().strip("\n"):
        p = subprocess.Popen("gpg --pinentry-mode loopback --batch -o - -ab -u \""+FROMADDRESS+"\" --passphrase-fd 0 temp_message", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = p.communicate(bytes(VARS["PASSPHRASE"], "utf-8"))[0].decode()
        #print(stdout)
        if not "BEGIN PGP SIGNATURE" in stdout:
            error_exit(True, "Error: A PGP key pair does not yet exist for \""+FROMADDRESS+"\" or the passphrase was incorrect.")

        # check if GPG key will expire soon or has expired
        date=subprocess.check_output("gpg -k --with-colons \""+FROMADDRESS+"\"", shell=True).decode().strip("\n")
        for line in date.split("\n"):
            if "pub" in line:
                date = line.split(":")[6]
                break

        if len(date) > 0:
            sec = str(int(date) - int(time.mktime(datetime.datetime.strptime(VARS["NOW"], "%b %d %H:%M:%S %Y %Z").timetuple())))
            fingerprint=subprocess.check_output("gpg --fingerprint --with-colons \""+FROMADDRESS+"\"", shell=True).decode().strip("\n")
            for line in fingerprint.split("\n"):
                if "fpr" in line:
                    fingerprint = line.split(":")[9]
                    break

            readable_date = datetime.datetime.fromtimestamp(int(date)).strftime("%b %d %H:%M:%S %Y %Z")
            if len(sec) > 0:
                if int(sec) / 86400 < int(VARS["WARNDAYS"]):
                    print(f'Warning: The PGP key pair for \"{FROMADDRESS}\" with fingerprint {fingerprint} expires in less than ' + VARS["WARNDAYS"] + f' days {readable_date}.\n')
            else:
                error_exit(True,f'Error: The PGP key pair for \"{FROMADDRESS}\" with fingerprint {fingerprint} expired {readable_date}')

    if len(VARS["CERT"]) > 0 and len(VARS["PASSPHRASE"]) > 0:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")

def main(argv):
    # parsing/assignment
    parse_assign(argv)
    configuration_assignment() # use default configuration if nothing was put on the CMDline

    # email checks
    email_work()
    attachment_work()

    # signing checks
    cert_checks()
    passphrase_checks()

    # sending
    #if VARS["PORT"] send(VARS, FROMADDRESS)

    sendEmail(VARS, FROMADDRESS, int(VARS["PORT"]))
    #sendEmail(VARS, FROMADDRESS, PORT=587)

if __name__=="__main__":
    if len(sys.argv) == 1:
        usage.usage()
        sys.exit(1)

    main(sys.argv[1:])

#!/usr/bin/env python

import sys
import os
import re
import getopt
import datetime
import time
import subprocess
import codecs
import atexit
from shutil import which

from .send import sendEmail
from . import usage
from . import configuration

'''Copyright © Daniel Connelly

   The purpose of this file is to
   1. parse all flags given on the cmdline.
   2. do checks to see if those files are valid
   3. handle escape characters appropriately
'''

# Default Variables

VARS = {"TOEMAILS": [],
        "CCEMAILS": [],
        "BCCEMAILS": [],
        "FROMEMAIL": '',
        "SMTP": '',
        "USERNAME": '',
        "PASSWORD": '',
        "FROMADDRESS": '',
        "PRIORITY": '',
        "PORT": 0,
        "CERT": '',
        "CLIENTCERT": 'cert.pem',
        "PASSPHRASE": '',
        "WARNDAYS": 3,
        "ZIPFILE": '',
        "VERBOSE": False,
        "NOW": time.strftime("%b %d %H:%M:%S %Y %Z", time.gmtime()),
        "SUBJECT": '',
        "MESSAGE": '',
        "ATTACHMENTS": [],
        "DRYRUN": False,
        "TIME": 0,
        "NOTIFY": '',
        "LANGUAGE": False,
        "TLS": False,
        "STARTTLS": False}

# Stores default SMTP server, username, password if `--config` option is set.
CONFIG_FILE = "~/.sendpy.ini"

# ESCAPE_SEQUENCE_RE and decode_escapes credit -- https://stackoverflow.com/a/24519338/8651748 and Teal Dulcet
ESCAPE_SEQUENCE_RE = re.compile(
    r'''(\\U[0-9a-fA-F]{8}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\N\{[^}]+\}|\\[\\'"abfnrtv])''')


def zero_pad(message):
    '''zero_pad escape characters (u and U and x) that are < 4 numbers long, since python doesn't support this'''
    new_message = ""
    start_index = 0  # what we begin at for each iteration through our loop
    len_message = len(message)
    RE = re.compile('^[0-9a-fA-F]$')  # matches any hexadecimal char
    while start_index < len_message:
        new_message += message[start_index]
        if start_index + 1 != len_message and message[start_index] == "\\" and (message[start_index+1] == "u" or message[start_index+1] == "U" or message[start_index+1] == "x"):
            esc_char = message[start_index+1]  # u, U, or x
            if esc_char == 'u':
                zero_pad = 4  # amount of zeroes to add
            elif esc_char == 'U':
                zero_pad = 8
            else:  # x
                zero_pad = 2
            count = 0  # track number of escape characters to zero pad
            new_message += esc_char
            start_index += 2  # skip past escaped escape character
            for j in range(start_index, len_message):
                if count > zero_pad:
                    # avoid re-checking the unicode/x string.
                    start_index += zero_pad
                    break
                # reach the end/beginning of new unicode/x string:
                if re.match(RE, message[j]):
                    count += 1
                else:
                    # Zero pad
                    new_message += "0" * (zero_pad-count)

                    # add back in characters
                    for k in range(0, count):
                        new_message += message[start_index]
                        start_index += 1
                    start_index -= 1  # for back-to-back escape sequences
                    break
        start_index += 1
    return new_message


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
            # [-r ..] in bash
            if not arg or not (os.path.exists(arg) and os.access(arg, os.R_OK)):
                error_exit(True, f'Error: Cannot read {arg} file.')
            VARS["ATTACHMENTS"].append(arg)
        elif opt in ("-b", "--bcc"):
            VARS["BCCEMAILS"].append(arg)
        elif opt in ("-c", "--cc"):
            VARS["CCEMAILS"].append(arg)
        elif opt in ("-d", "--dryrun"):
            VARS["DRYRUN"] = True
        elif opt in ("-e", "--examples"):
            usage.examples()
            sys.exit(0)
        elif opt in ("-f", "--from"):
            if not VARS["FROMEMAIL"]:
                VARS["FROMEMAIL"] = arg
            else:
                error_exit(
                    True, "Only one 'from' address must be specified as.")
        elif opt in ("-g", "--gateways"):
            usage.carriers()
            sys.exit(0)
        elif opt in ("-h", "--help"):
            usage.usage()
            sys.exit(0)
        elif opt in ("-k", "--passphrase"):
            VARS["PASSPHRASE"] = arg
        elif opt in ("-l", "--language"):
            VARS["LANGUAGE"] = True
        elif opt in ("-m", "--message"):
            if VARS["NOTIFY"] != '':
                print("Warning: Output from the program named in the `-n, --notify` flag will be sent in addition to the message indicated in the `-m, -message` flag.")
                VARS["MESSAGE"] += "\n"
            VARS["MESSAGE"] += decode_escapes(zero_pad(arg))
        elif opt in ("--message-file"):
            if VARS["MESSAGE"] != '':
                VARS["MESSAGE"] += "\n"
            expanded_file = os.path.expanduser(arg)
            if expanded_file == '-':
                VARS["MESSAGE"] += decode_escapes(zero_pad(sys.stdin.read()))
            elif os.path.exists(expanded_file) and os.access(expanded_file, os.R_OK):
                with open(expanded_file, "r") as f1:
                    VARS["MESSAGE"] += decode_escapes(zero_pad(f1.read()))
            else:
                error_exit(True, "Error: \"" + expanded_file +
                           "\" file does not exist.")
        elif opt in ("-n", "--notify"):
            if VARS["MESSAGE"] != '':
                VARS["MESSAGE"] += "\n"
            p = subprocess.Popen(arg, shell=True, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout = p.communicate()[0].decode()
            VARS["MESSAGE"] += decode_escapes(
                zero_pad(f'\n**OUTPUT**\n{stdout}\n**EXIT CODE**\n{p.returncode}'))
        elif opt in ("-p", "--password"):
            VARS["PASSWORD"] = arg
        elif opt in ("--config"):
            configuration.config_email()
            print("Configuration file successfully set\n")
            sys.exit(0)
        elif opt in ("-s", "--subject"):
            VARS["SUBJECT"] = decode_escapes(zero_pad(arg))
        elif opt in ("--starttls"):
            VARS["STARTTLS"] = True
        elif opt in ("-t", "--to"):
            VARS["TOEMAILS"].append(arg)
        elif opt in ("--tls"):
            VARS["TLS"] = True
        elif opt in ("-u", "--username"):
            VARS["USERNAME"] = arg
        elif opt in ("-v", "--version"):
            print("Send Msg CLI 1.0\n")
            sys.exit(0)
        elif opt in ("-z", "--zipfile"):
            if arg.endswith('.zip'):
                VARS["ZIPFILE"] = arg
            else:
                VARS["ZIPFILE"] = arg+".zip"
        elif opt in ("-C", "--cert"):
            VARS["CERT"] = arg
        elif opt in ("--smtpservers"):
            usage.servers()
            sys.exit(0)
        elif opt in ("-T", "--time"):
            VARS["TIME"] = arg
        elif opt in ("-P", "--priority"):
            VARS["PRIORITY"] = arg
        elif opt in ("-S", "--smtp"):
            res = arg.split(":")
            if len(res) == 2:
                VARS["SMTP"] = res[0]
                VARS["PORT"] = int(res[1])
            elif len(res) > 2:
                error_exit(True, "Extraneous input into -S or --smtp.")
            else:
                VARS["SMTP"] = res[0]
        elif opt in ("-V", "--verbose"):
            VARS["VERBOSE"] = True


def configuration_assignment():
    '''If a user decides, they may work from a configuration if the user does not specify a necessary
       flag (e.g., -u). If the config file is empty, an error will be thrown.
    '''
    # make file with appropriate fields if file does not exist
    if not VARS["SMTP"] or not VARS["FROMEMAIL"] or not VARS["USERNAME"]:
        if not os.path.exists(os.path.expanduser(CONFIG_FILE)):
            error_exit(True, "Error: SMTP server, From, Username or Password fields not set in config file and not typed on CMDline. Please include the -S, -f, or -u, flags or use the following command to set the config file: `sendpy --config`")
        else:
            print("SMTP server, From, or Username fields not typed on CMDline. \n\nAttempting to send msg with configuration file credentials...\n")
            VARS["SMTP"], VARS["PORT"], VARS["FROMEMAIL"], VARS["USERNAME"], VARS["PASSWORD"] = configuration.return_config()


def parse_assign(argv):
    '''Find the correct variable to assign the arg/opt to.'''
    try:
        opts, args = getopt.getopt(argv, "a:b:c:def:ghk:lm:n:p:rs:t:u:vz:C:P:S:T:V",
                                   ["attachments=", "bcc=", "cc=", "cert=", "config", "dryrun", "examples", "from=", "gateways",
                                    "help", "language", "message=", "message-file=", "notify", "passphrase=", "password=", "priority=", "smtp=", "starttls",
                                    "smtpservers", "subject=", "time", "to=", "tls", "username=", "verbose", "version", "zipfile="])
    except getopt.GetoptError:
        usage.usage()
        sys.exit(2)
    assign(opts)
    if VARS["TLS"] and VARS["STARTTLS"]:
        error_exit(
            True, "Cannot specify both --tls and --starttls option. Please choose one and try again.")

# modified from source: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python


def convert_bytes(size, byte_type):
    '''Calculates how large an attachment in two ways -- iB and B'''
    byte_array = ['Bytes', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
    div_size = 1024.0 if byte_type == "i" else 1000.0
    import locale

    for x in byte_array:
        if size < div_size:
            locale.setlocale(locale.LC_ALL, '')
            unit = x + \
                ('' if x == 'Bytes' else ('i' if byte_type == 'i' else '') + 'B')
            return f'{size:,.1f}{unit}'
        size /= div_size

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
       and warn user if size is large. Will also strip the path and just use the basename (filename).
    '''
    if VARS["ATTACHMENTS"]:
        TOTAL = 0
        rows = []

        zip_file = VARS["ZIPFILE"]
        if zip_file:
            if os.path.exists(zip_file):
                error_exit(True, f'Error: File {zip_file} already exists.')

            import zipfile
            with zipfile.ZipFile(zip_file, 'w') as myzip:
                for attachment in VARS["ATTACHMENTS"]:
                    myzip.write(attachment, os.path.basename(attachment))
            atexit.register(lambda x: os.remove(x), zip_file)
            VARS["ATTACHMENTS"] = [zip_file]

        # printing in a nice row; checking if total attachment size is >= 25 MB
        for attachment in VARS["ATTACHMENTS"]:
            SIZE = os.path.getsize(attachment)
            TOTAL += int(SIZE)
            rows.append((os.path.basename(attachment), convert_bytes(
                int(SIZE), "i"), "" if SIZE < 1000 else "("+convert_bytes(int(SIZE), "b")+")"))

        rows.append(("\nTotal Size:", " " + convert_bytes(TOTAL, "i"),
                     "" if TOTAL < 1000 else " " + "("+convert_bytes(int(TOTAL), "b")+")"))
        print("Attachments:")
        format_attachment_output(rows)

        if TOTAL >= 26214400:
            print("Warning: The total size of all attachments is greater than or equal to 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Firefox Send: https://send.firefox.com or transfer.sh: https://transfer.sh\n")


def email_work():
    '''Check for valid email addresses.
       Split 'From' e-mail address into name (if one is given) and email: "Example <example@example.com>" -> "Example", "example@example.com".
       Credit for a superior regex goes to Teal Dulcet.
    '''
    if not VARS["SUBJECT"]:
        error_exit(
            True, "No 'Subject' indicated. Please use the '-s' or '--subject' flag.")

    if not VARS["TOEMAILS"] and not VARS["BCCEMAILS"] and not VARS["CCEMAILS"]:
        error_exit(
            True, "No 'To' or 'BCC' email supplied. Please enter one or both.")

    VARS["FROMADDRESS"] = VARS["FROMEMAIL"]

    RE = re.compile(
        r'^((.{1,64}@[\w.-]{4,254})|(.*) *<(.{1,64}@[\w.-]{4,254})>)$')
    RE1 = re.compile(r'^.{6,254}$')
    RE2 = re.compile(r'^.{1,64}@')
    RE3 = re.compile(
        r'^(([^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"([^"\\]|\\.)+")(\.(([^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"([^"\\]|\\.)+"))*@((xn--)?[^\W_]([\w-]{0,61}[^\W_])?\.)+(xn--)?[^\W\d_]{2,63}$')

    # Check if the email is valid.
    try:
        for i in range(0, len(VARS["TOEMAILS"])):
            temp = VARS["TOEMAILS"][i]
            result = RE.match(temp)
            if result:
                temp = result.group(2) if result.group(2) else result.group(4)
            if not (RE1.match(temp) and RE2.match(temp) and RE3.match(temp)):
                error_exit(True, "Error: \""+temp +
                           "\" is not a valid e-mail address.")

        for i in range(0, len(VARS["CCEMAILS"])):
            temp = VARS["CCEMAILS"][i]
            result = RE.match(temp)
            if result:
                temp = result.group(2) if result.group(2) else result.group(4)
            if not (RE1.match(temp) and RE2.match(temp) and RE3.match(temp)):
                error_exit(True, "Error: \""+temp +
                           "\" is not a valid e-mail address.")

        for i in range(0, len(VARS["BCCEMAILS"])):
            temp = VARS["BCCEMAILS"][i]
            result = RE.match(temp)
            if result:
                temp = result.group(2) if result.group(2) else result.group(4)
            if not (RE1.match(temp) and RE2.match(temp) and RE3.match(temp)):
                error_exit(True, "Error: \""+temp +
                           "\" is not a valid e-mail address.")

        if VARS["FROMADDRESS"]:
            result = RE.match(VARS["FROMADDRESS"])
            if result:
                VARS["FROMADDRESS"] = result.group(
                    2) if result.group(2) else result.group(4)
            if not RE1.match(VARS["FROMADDRESS"]) or not RE2.match(VARS["FROMADDRESS"]) or not RE3.match(VARS["FROMADDRESS"]):
                error_exit(
                    True, "Error: \""+VARS["FROMADDRESS"]+"\" is not a valid e-mail address.")
        else:
            error_exit(True, "Error: Must specify FROM e-mail address.")

    except Exception as error:
        print(error)
        sys.exit(1)


def cert_checks():
    '''Creates the .pem certificate (defined in VARS["CLIENTCERT"]; e.g., cert.pem) with certificate \
       located in VARS["CERT"] (read in from CMDLINE using -C, or --cert)
    '''
    if VARS["CERT"]:
        if which("openssl") is None:
            error_exit(
                True, "Error: OpenSSL not found on PATH. Please download OpenSSL and/or add it to the PATH. You need this to sign a message with S/MIME.")

        if not (os.path.exists(VARS["CERT"]) and os.access(VARS["CERT"], os.R_OK)) and not os.path.exists(VARS["CLIENTCERT"]):
            error_exit(True, "Error: \"" +
                       VARS["CERT"]+"\" certificate file does not exist.")

        if not os.path.exists(VARS["CLIENTCERT"]):
            print("Saving the client certificate from \"" +
                  VARS["CERT"]+"\" to \""+VARS["CLIENTCERT"]+"\"")
            print("Please enter the password when prompted.\n")
            subprocess.check_output(
                "openssl pkcs12 -in \""+VARS["CERT"]+"\" -out \""+VARS["CLIENTCERT"]+"\" -clcerts -nodes", shell=True).decode().strip("\n")

        aissuer = subprocess.check_output(
            "openssl x509 -in \""+VARS["CLIENTCERT"]+"\" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq", shell=True).decode().strip("\n")
        date = subprocess.check_output(
            "openssl x509 -in \""+VARS["CLIENTCERT"] + "\" -noout -enddate", shell=True).decode().strip("\r\n")

        if aissuer:
            for line in aissuer.split("commonName="):
                issuer = line
        else:
            issuer = ''

        split = date.split("notAfter=")
        if split:
            for line in split:
                date = line
        else:
            error_exit(True, "No expiration date found in " +
                       VARS["CLIENTCERT"] + " file. You may try re-creating the file by deleting it and running this script again.")

        p = subprocess.Popen("openssl x509 -in \"" + VARS["CLIENTCERT"] + "\" -noout -checkend 0",
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        p.communicate()

        if p != 0:
            sec = int(time.mktime(datetime.datetime.strptime(date, "%b %d %H:%M:%S %Y %Z").timetuple(
            )) - time.mktime(datetime.datetime.strptime(VARS["NOW"], "%b %d %H:%M:%S %Y %Z").timetuple()))
            if sec / 86400 < VARS["WARNDAYS"]:
                print('Warning: The S/MIME Certificate ' +
                      (f'from \"{issuer}\" ' if issuer else '') + 'expires in less than ' + str(VARS["WARNDAYS"]) + f' days ({date})')
        else:
            error_exit(True, f'Error: The S/MIME Certificate ' +
                       (f'from \"{issuer}\" ' if issuer else '') + 'expired {date}')


def passphrase_checks():
    '''Does a number of checks if a user indicated they watn to sign with a GPG key to utilize PGP/MIME'''
    if VARS["PASSPHRASE"]:
        if which("gpg") is None:
            error_exit(
                True, "Error: GPG not found. You need this to sign a message with PGP/MIME")

        # Work from a config file
        if VARS["PASSPHRASE"].lower() == "config":
            VARS["PASSPHRASE"] = configuration.config_pgp()

        # create file to be written out, then schedule it to be removed if an exit occurs
        with open("temp_message", "w") as f1:
            f1.write(" ")
        atexit.register(lambda x: os.remove(x), 'temp_message')

        # check if GPG key exists
        p = subprocess.Popen("gpg --pinentry-mode loopback --batch -o - -ab -u \"" +
                             VARS["FROMADDRESS"]+"\" --passphrase-fd 0 temp_message", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = p.communicate(bytes(VARS["PASSPHRASE"], "utf-8"))[0].decode()
        if p.returncode != 0:
            error_exit(True, stdout + "\n" + "Error: A PGP key pair does not yet exist for \"" +
                       VARS["FROMADDRESS"]+"\" or the passphrase was incorrect.")

        # check if GPG key will expire soon or has expired
        date = subprocess.check_output(
            "gpg -k --with-colons \""+VARS["FROMADDRESS"]+"\"", shell=True).decode().strip("\n")
        for line in date.split("\n"):
            if "pub" in line:
                date = line.split(":")[6]
                break

        if date:
            sec = int(date) - int(time.mktime(datetime.datetime.strptime(
                VARS["NOW"], "%b %d %H:%M:%S %Y %Z").timetuple()))
            fingerprint = subprocess.check_output(
                "gpg --fingerprint --with-colons \""+VARS["FROMADDRESS"]+"\"", shell=True).decode().strip("\n")
            for line in fingerprint.split("\n"):
                if "fpr" in line:
                    fingerprint = line.split(":")[9]
                    break

            readable_date = datetime.datetime.fromtimestamp(
                int(date)).strftime("%b %d %H:%M:%S %Y %Z")
            if sec > 0:
                if sec / 86400 < VARS["WARNDAYS"]:
                    print(f'Warning: The PGP key pair for \"' + VARS["FROMADDRESS"] + f'\" with fingerprint {fingerprint} expires in less than ' + str(
                        VARS["WARNDAYS"]) + f' days {readable_date}.\n')
            else:
                error_exit(True, f'Error: The PGP key pair for \"' +
                           VARS["FROMADDRESS"] + f'\" with fingerprint {fingerprint} expired {readable_date}')

    if VARS["CERT"] and VARS["PASSPHRASE"]:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")


def main(argv):
    # parsing/assignment
    parse_assign(argv)
    # use default configuration if nothing was put on the CMDline
    configuration_assignment()

    # email/email checks
    email_work()
    attachment_work()

    # signing/signing checks
    cert_checks()
    passphrase_checks()

    # sending
    sendEmail(VARS, VARS["PORT"])


if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage.usage()
        sys.exit(1)
    main(sys.argv[1:])

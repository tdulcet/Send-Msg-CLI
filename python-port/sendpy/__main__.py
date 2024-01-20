#!/usr/bin/env python

import argparse
import atexit
import codecs
import locale
import os
import re
import socket
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta
from email.utils import parseaddr
from shutil import which

from . import configuration
from . import usage
from .send import sendEmail

"""Copyright © Daniel Connelly and Teal Dulcet

   The purpose of this file is to
   1. parse all flags given on the cmdline.
   2. do checks to see if those flags are valid
   3. handle escape characters appropriately and call sendEmail()
"""

locale.setlocale(locale.LC_ALL, "")

CLIENTCERT = "cert.pem"
WARNDAYS = 3

parser = argparse.ArgumentParser(
    description="One or more To, CC or BCC e-mail addresses are required. Send text messages by using the mobile providers e-mail to SMS or MMS gateway (see the --gateways option). See examples with the --examples option.")
parser.add_argument("-v", "--version", action="version",
                    version="%(prog)s 1.0.1")
parser.add_argument("-s", "--subject", dest="subject",
                    help="Subject. Escape sequences are expanded. Supports Unicode characters.")
parser.add_argument("-m", "--message", dest="message", default="",
                    help="Message body. Escape sequences are expanded. Supports Unicode characters.")
parser.add_argument("--message-file", dest="message_file",
                    help="Message body from a file or standard input if the filename is '-'.")
parser.add_argument("-a", "--attachment", dest="attachments", action="append", default=[],
                    help="Attachment filename. Use multiple times for multiple attachments. Supports Unicode characters in filename.")
parser.add_argument("-t", "--to", dest="toemails", action="append", default=[],
                    help="To e-mail address. Use multiple times for multiple To e-mail addresses.")
parser.add_argument("-c", "--cc", dest="ccemails", action="append", default=[],
                    help="CC e-mail address. Use multiple times for multiple CC e-mail addresses.")
parser.add_argument("-b", "--bcc", dest="bccemails", action="append", default=[],
                    help="BCC e-mail address. Use multiple times for multiple BCC e-mail addresses.")
parser.add_argument("-f", "--from", dest="fromemail",
                    help="From e-mail address")
parser.add_argument("-S", "--smtp", dest="smtp",
                    help='SMTP server. Optionally include a port with the "hostname:port" syntax. Defaults to port 465 with --ssl/--tls and port 25 otherwise. Use "localhost" if running a mail server on this device.')
parser.add_argument("--tls", action="store_true",
                    dest="tls", help="Use a secure connection with SSL/TLS (Secure Socket Layer/Transport Layer Security)")
parser.add_argument("--starttls", action="store_true", dest="starttls",
                    help="Upgrade to a secure connection with StartTLS")
parser.add_argument("-u", "--username", dest="username",
                    help="SMTP server username")
parser.add_argument("-p", "--password", dest="password",
                    help="SMTP server password. For security, use the --config option instead for it to prompt you for the password and then store in the configuration file.")
parser.add_argument("-P", "--priority", dest="priority", choices=["5 (Lowest)", "4 (Low)", "Normal", "2 (High)", "1 (Highest)"],
                    help='Priority. Supported priorities: "5 (Lowest)", "4 (Low)", "Normal", "2 (High)" and "1 (Highest)"')
parser.add_argument("-r", "--receipt", action="store_true",
                    dest="mdn", help="Request Return Receipt")
parser.add_argument("-C", "--certificate", dest="cert",
                    help="S/MIME Certificate filename for digitally signing the e-mails. It will ask you for the password the first time you run the script with this option.")
parser.add_argument("-k", "--passphrase", dest="passphrase",
                    help="PGP secret key passphrase for digitally signing the e-mails with PGP/MIME. For security, use 'config' for it to prompt you for the passphrase and then store in the configuration file.")
parser.add_argument("-z", "--zip", dest="zipfile",
                    help="Compress attachment(s) with zip")
parser.add_argument("-l", "--language", action="store_true", dest="language",
                    help="Set Content-Language. Uses value of LANG environment variable on Linux.")
parser.add_argument("-U", "--sanitize-date", action="store_true", dest="utc",
                    help="Uses Coordinated Universal Time (UTC) and rounds date down to whole minute.")
parser.add_argument("-T", "--time", dest="time", type=float,
                    help="Time to delay sending of the e-mail")
parser.add_argument("-d", "--dry-run", action="store_true",
                    dest="dryrun", help="Dry run, do not send the e-mail")
parser.add_argument("-n", "--notify", dest="notify",
                    help="Run provided command and then send an e-mail with resulting output and exit code.")
parser.add_argument("-V", "--verbose", dest="verbose", action="count",
                    help="Verbose, show the client-server communication")
parser.add_argument("--config", action="store_true",
                    help="Store the --from, --smtp, --tls, --starttls, --username and --password option values in a '.sendpy.ini' configuration file as defaults for future use. It will prompt for any values that are not provided.")
parser.add_argument("--examples", action="store_true",
                    help="Show example usages of this script and exit")
parser.add_argument("--smtp-servers", action="store_true",
                    help="Show a list of the SMTP servers for common e-mail services, then exit")
parser.add_argument("--gateways", action="store_true",
                    help="Show a list the of SMS and MMS Gateways for common mobile providers in the United States and Canada, then exit")

args = parser.parse_args()

NOW = datetime.now()

escape_sequence_re = re.compile(
    r"\\U[0-9a-fA-F]{1,8}|\\u[0-9a-fA-F]{1,4}|\\x[0-9a-fA-F]{1,2}")
ESCAPE_SEQUENCE_RE = re.compile(
    r"""(\\U[0-9a-fA-F]{8}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\N\{[^}]+\}|\\[\\'"abfnrtv])""")


def zero_pad(match):
    """zero_pad escape characters (u and U and x) that are < 4, < 8, and < 2 numbers long respectively, since python doesn't support this on its own."""
    amatch = match.group()
    azero_pad = 8 if amatch[1] == "U" else 4 if amatch[1] == "u" else 2
    # the unicode character + amount of zeros + the original unicode typed in
    return amatch[:2] + ("0" * (azero_pad - (len(amatch) - 2))) + amatch[2:]


def decode_match(match):
    return codecs.decode(match.group(), "unicode-escape")


def decode_escapes(s):
    """ESCAPE_SEQUENCE_RE and decode_escapes."""
    return ESCAPE_SEQUENCE_RE.sub(
        decode_match, escape_sequence_re.sub(zero_pad, s))


def configuration_assignment():
    """If a user decides, they may work from a configuration if the user does not specify a necessary
    flag (e.g., -u). If the config file is empty, an error will be thrown.
    """
    # make file with appropriate fields if file does not exist
    if not args.smtp or not args.fromemail:
        args.smtp, args.tls, args.starttls, args.fromemail, args.username, args.password = configuration.return_config(
            args)

    if args.tls and args.starttls:
        parser.error("Cannot use both SSL/TLS and StartTLS.")

    host = args.smtp
    port = 0
    res = host.rsplit(":", 1)
    if len(res) == 2:
        host, port = res
        port = int(port)

    if not args.tls and (not port or port == 25):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            # testing connection as computer may not block port 25, but ISP/Cloud provider may.
            if sock.connect_ex(("aspmx.l.google.com", 25)):
                print("Warning: Could not reach Google's mail server on port 25. Port 25 seems to be blocked by your network. You will need to specify a port for the SMTP server in order to send e-mails.\n")

    return host, port


def parse_assign():
    """Find the correct variable to assign the arg/opt to."""
    if args.config:
        configuration.config_email(args)
        print("Configuration file successfully set\n")
        sys.exit(0)

    if args.examples:
        usage.examples(os.path.basename(sys.argv[0]))
        sys.exit(0)

    if args.smtp_servers:
        usage.servers()
        sys.exit(0)

    if args.gateways:
        usage.carriers()
        sys.exit(0)

    if not args.subject:
        parser.error("A subject is required.")

    if not args.toemails and not args.ccemails and not args.bccemails:
        parser.error("One or more To, CC or BCC e-mail addresses are required")

    if args.message:
        args.message = decode_escapes(args.message)

    if args.message_file:
        expanded_file = os.path.expanduser(args.message_file)
        if expanded_file == "-":
            args.message += decode_escapes(sys.stdin.read())
        elif os.path.exists(expanded_file):
            with open(expanded_file, encoding="utf-8") as f:
                args.message += decode_escapes(f.read())
        else:
            parser.error(f"{expanded_file!r} file does not exist.")

    if args.notify:
        with subprocess.Popen(args.notify, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True) as p:
            stdout, _ = p.communicate()
            args.message += f"\n**EXIT CODE**:\n{p.returncode}\n**OUTPUT**:\n{stdout}\n"

    args.subject = decode_escapes(args.subject)

    if args.zipfile and not args.zipfile.endswith(".zip"):
        args.zipfile += ".zip"


suffix_power_char = ["", "K", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q"]


def convert_bytes(number, scale=False):
    """Calculates how large an attachment in two ways -- iB and B."""
    scale_base = 1000 if scale else 1024

    power = 0
    while abs(number) >= scale_base:
        power += 1
        number /= scale_base

    anumber = abs(number)
    anumber += 0.0005 if anumber < 10 else 0.005 if anumber < 100 else 0.05 if anumber < 1000 else 0.5

    if number and anumber < 1000 and power > 0:
        strm = f"{number:.{sys.float_info.dig}g}"

        length = 5 + (number < 0)
        if len(strm) > length:
            prec = 3 if anumber < 10 else 2 if anumber < 100 else 1
            strm = f"{number:.{prec}f}"
    else:
        strm = f"{number:.0f}"
    strm += suffix_power_char[power] if power < len(
        suffix_power_char) else "(error)"

    if not scale and power > 0:
        strm += "i"

    return strm


def attachment_work():
    """Zips files to send in msg if user specifies the '-z' flag. Will also calculate size of attachments
    and warn user if size is large. Will also strip the path and just use the basename (filename).
    """
    if args.attachments:
        total = 0
        rows = []

        for attachment in args.attachments:
            if not attachment or not os.path.exists(attachment):
                parser.error(f"Cannot read {attachment!r} file.")

        if args.zipfile:
            if os.path.exists(args.zipfile):
                parser.error(f"File {args.zipfile!r} already exists.")

            atexit.register(os.remove, args.zipfile)

            with zipfile.ZipFile(args.zipfile, "w") as myzip:
                for attachment in args.attachments:
                    myzip.write(attachment, os.path.basename(attachment))

            args.attachments = [args.zipfile]

        # printing in a nice row; checking if total attachment size is >= 25 MiB
        print("Attachments:")
        for attachment in args.attachments:
            size = os.path.getsize(attachment)
            total += size
            rows.append((attachment, convert_bytes(size, False),
                        f"({convert_bytes(size, True)})" if size >= 1000 else ""))
        usage.format_attachment_output(rows)

        print(
            f"\nTotal Size:\t{convert_bytes(total, False)}\t{f'({convert_bytes(total, True)})' if total >= 1000 else ''}\n")

        if total >= 25 * 1024 * 1024:
            print("Warning: The total size of all attachments is greater than 25 MiB. The message may be rejected by your or the recipient's mail server. You may want to upload large files to an external storage service, such as Send: https://send.vis.ee/ (formerly Firefox Send) or transfer.sh: https://transfer.sh\n")


def email_work():
    """Check for valid email addresses."""
    # RE = re.compile(r"^((.{1,64}@[\w.-]{4,254})|(.*) *<(.{1,64}@[\w.-]{4,254})>)$")
    re1 = re.compile(r"^.{6,254}$")
    re2 = re.compile(r"^.{1,64}@")
    re3 = re.compile(
        r'^(([^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"([^"\\]|\\.)+")(\.(([^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"([^"\\]|\\.)+"))*@((xn--)?[^\W_]([\w-]{0,61}[^\W_])?\.)+(xn--)?[^\W\d_]{2,63}$')

    # Check if the email is valid.
    for toemail in args.toemails:
        # result = RE.match(toemail)
        _, address = parseaddr(toemail)
        temp = address or toemail
        if not (re1.match(temp) and re2.match(temp) and re3.match(temp)):
            parser.error(f"{temp!r} is not a valid e-mail address.")

    for ccemail in args.ccemails:
        # result = RE.match(ccemail)
        _, address = parseaddr(ccemail)
        temp = address or ccemail
        if not (re1.match(temp) and re2.match(temp) and re3.match(temp)):
            parser.error(f"{temp!r} is not a valid e-mail address.")

    for bccemail in args.bccemails:
        # result = RE.match(bccemail)
        _, address = parseaddr(bccemail)
        temp = address or bccemail
        if not (re1.match(temp) and re2.match(temp) and re3.match(temp)):
            parser.error(f"{temp!r} is not a valid e-mail address.")

    # result = RE.match(args.fromemail)
    _, fromaddress = parseaddr(args.fromemail)
    temp = fromaddress or args.fromemail
    if not (re1.match(temp) and re2.match(temp) and re3.match(temp)):
        parser.error(f"{temp!r} is not a valid e-mail address.")

    return fromaddress


def cert_checks():
    """Creates the .pem certificate (defined in CLIENTCERT; e.g., cert.pem) with certificate \
       located in args.cert (read in from CMDLINE using -C, or --cert).
    """
    if args.cert:
        if which("openssl") is None:
            print("Error: OpenSSL is not installed.", file=sys.stderr)
            sys.exit(1)

        if not os.path.exists(args.cert) and not os.path.exists(CLIENTCERT):
            print(
                f"Error: {args.cert!r} certificate file does not exist.", file=sys.stderr)
            sys.exit(1)

        if not (os.path.exists(CLIENTCERT) and os.path.getsize(CLIENTCERT)):
            print(
                f"Saving the client certificate from {args.cert!r} to {CLIENTCERT!r}")
            print("Please enter the password when prompted.\n")
            if subprocess.call(
                    ["openssl", "pkcs12", "-in", args.cert, "-out", CLIENTCERT, "-clcerts", "-nodes"]):
                print(
                    "Error saving the client certificate. Trying again in legacy mode.", file=sys.stderr)
                if subprocess.call(["openssl", "pkcs12", "-in", args.cert,
                                   "-out", CLIENTCERT, "-clcerts", "-nodes", "-legacy"]):
                    sys.exit(1)

        issuer = None
        with subprocess.Popen(["openssl", "x509", "-in", CLIENTCERT, "-noout", "-issuer", "-nameopt", "multiline,-align,-esc_msb,utf8,-space_eq"], stdout=subprocess.PIPE, universal_newlines=True) as p:
            aissuer, _ = p.communicate()
            if p.returncode:
                aissuer = aissuer.splitlines()
                for line in aissuer:
                    if "organizationName=" in line:
                        issuer = line.split("=", 1)[1]
                        break
                else:
                    for line in aissuer:
                        if "commonName=" in line:
                            issuer = line.split("=", 1)[1]
                            break

        adate = subprocess.check_output(
            ["openssl", "x509", "-in", CLIENTCERT, "-noout", "-enddate"], universal_newlines=True).splitlines()
        for line in adate:
            if "notAfter=" in line:
                date = line.split("=", 1)[1]
                break
        date = datetime.strptime(date, "%b %d %H:%M:%S %Y %Z")

        if not subprocess.call(["openssl", "x509", "-in", CLIENTCERT,
                               "-noout", "-checkend", "0"], stdout=subprocess.DEVNULL):
            delta = date - NOW
            warn = timedelta(days=WARNDAYS)
            if delta < warn:
                print(
                    f"Warning: The S/MIME Certificate {f'from “{issuer}” ' if issuer else ''}expires in less than {WARNDAYS} days ({date:%c}).\n")
        else:
            print(
                f"Error: The S/MIME Certificate {f'from “{issuer}” ' if issuer else ''}expired {date:%c}.", file=sys.stderr)
            sys.exit(1)


def passphrase_checks(fromaddress):
    """Does a number of checks if a user indicated they watn to sign with a GPG key to utilize PGP/MIME."""
    if args.passphrase:
        if which("gpg") is None:
            print("Error: GNU Privacy Guard is not installed.", file=sys.stderr)
            sys.exit(1)

        # Work from a config file
        if args.passphrase.lower() == "config":
            args.passphrase = configuration.config_pgp()

        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as f:
            f.write("\n")
            # check if GPG key exists
            with subprocess.Popen(["gpg", "--pinentry-mode", "loopback", "--batch", "-o", os.devnull, "-ab", "-u", fromaddress, "--passphrase-fd", "0", f.name], stdin=subprocess.PIPE, universal_newlines=True) as p:
                p.communicate(args.passphrase)
                if p.returncode:
                    print(
                        f"Error: A PGP key pair does not yet exist for {fromaddress!r} or the passphrase was incorrect.", file=sys.stderr)
                    sys.exit(1)

        # check if GPG key will expire soon or has expired
        adate = subprocess.check_output(
            ["gpg", "-k", "--with-colons", fromaddress], universal_newlines=True).splitlines()
        date = None
        for line in adate:
            if line.startswith("pub"):
                date = line.split(":")[6]
                break

        if date:
            date = datetime.fromtimestamp(int(date))
            afingerprint = subprocess.check_output(
                ["gpg", "--fingerprint", "--with-colons", fromaddress], universal_newlines=True).splitlines()
            for line in afingerprint:
                if line.startswith("fpr"):
                    fingerprint = line.split(":")[9]
                    break

            if date > NOW:
                delta = date - NOW
                warn = timedelta(days=WARNDAYS)
                if delta < warn:
                    print(
                        f"Warning: The PGP key pair for {fromaddress!r} with fingerprint {fingerprint} expires in less than {WARNDAYS} days {date:%c}.\n")
            else:
                print(
                    f"Error: The PGP key pair for {fromaddress!r} with fingerprint {fingerprint} expired {date:%c}.", file=sys.stderr)
                sys.exit(1)

    if args.cert and args.passphrase:
        print("Warning: You cannot digitally sign the e-mails with both an S/MIME Certificate and PGP/MIME. S/MIME will be used.\n")


def main():
    # parsing/assignment
    parse_assign()
    # use default configuration if nothing was put on the CMDline
    host, port = configuration_assignment()

    # email/email checks
    fromaddress = email_work()
    attachment_work()

    # signing/signing checks
    cert_checks()
    passphrase_checks(fromaddress)

    # sending
    sendEmail(args, CLIENTCERT, fromaddress, host, port)


if __name__ == "__main__":
    main()

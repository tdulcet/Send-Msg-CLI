import configparser
import getpass
import os
import re
import sys

"""Copyright © Daniel Connelly and Teal Dulcet

   The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
"""

parser = configparser.ConfigParser()
CONFIG_FILE = os.path.expanduser("~/.sendpy.ini")
parser.read([CONFIG_FILE])

# yes_regex = re.compile(locale.nl_langinfo(locale.YESEXPR))
yes_regex = re.compile(r"^[yY]")
# no_regex = re.compile(locale.nl_langinfo(locale.NOEXPR))
no_regex = re.compile(r"^[nN]")


def config_email(args):
    """Configures or reconfigures settings for send-msg-cli then writes the change to file."""
    section = "Email"
    if not parser.has_section(section):
        parser.add_section(section)

    smtp_server = args.smtp
    while not smtp_server:
        smtp_server = input(
            "SMTP server (hostname and optional port), e.g., 'mail.example.com:465': ")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        while True:
            accept = input(
                "Use a secure connection with SSL/TLS? (y/n): ").strip()
            yes_res = yes_regex.match(accept)
            no_res = no_regex.match(accept)
            if yes_res or no_res:
                break
        tls = bool(yes_res)
        if not tls:
            while True:
                accept = input(
                    "Upgrade to a secure connection with StartTLS? (y/n): ").strip()
                yes_res = yes_regex.match(accept)
                no_res = no_regex.match(accept)
                if yes_res or no_res:
                    break
            starttls = bool(yes_res)
    fromemail = args.fromemail
    while not fromemail:
        fromemail = input(
            "From e-mail address, e.g., 'User <user@example.com>': ")
    username = args.username or input(
        "Optional username for this account, e.g., 'user@example.com': ")
    password = args.password or getpass.getpass(
        "Optional password for this account: ")

    parser.set(section, "smtp", smtp_server)
    if tls:
        parser.set(section, "tls", str(tls))
    if starttls:
        parser.set(section, "starttls", str(starttls))
    parser.set(section, "fromemail", fromemail)
    parser.set(section, "username", username)
    parser.set(section, "password", password)

    with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
        parser.write(configfile)


def config_pgp():
    """Set the pgp passphrase to avoid future typing of the passphrase on the commandline."""
    section = "PGP"
    if not parser.has_section(section):
        parser.add_section(section)

        passphrase = getpass.getpass("PGP secret key passphrase: ")

        parser.set(section, "passphrase", passphrase)

        with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
            parser.write(configfile)

        return passphrase

    return parser.get(section, "passphrase")


def return_config(args):
    """Pull (and check) variables in the .ini file."""
    section = "Email"
    if not parser.has_section(section):
        print("The SMTP server and from e-mail address are not provided and not set in the config file. Please provide the --smtp and --from options or set the config file with the --config option.", file=sys.stderr)
        sys.exit(1)

    smtp_server = args.smtp or parser.get(section, "smtp")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        if parser.has_option(section, "tls"):
            tls = parser.getboolean(section, "tls")
        if parser.has_option(section, "starttls"):
            starttls = parser.getboolean(section, "starttls")
    fromemail = args.fromemail or parser.get(section, "fromemail")
    username = args.username or parser.get(section, "username")
    password = args.password or parser.get(section, "password")

    return smtp_server, tls, starttls, fromemail, username, password

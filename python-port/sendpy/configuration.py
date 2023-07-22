import configparser
import getpass
import locale
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

yes_regex = re.compile(locale.nl_langinfo(locale.YESEXPR))
no_regex = re.compile(locale.nl_langinfo(locale.NOEXPR))


def config_email(args):
    """Configures or reconfigures settings for send-msg-cli then writes the change to file."""
    section = "email"
    if not parser.has_section(section):
        parser.add_section(section)

    smtp_server = args.smtp or input(
        "Enter the SMTP server (e.g., 'mail.example.com:465'): ")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        accept = ""
        while not (yes_regex.search(accept) or no_regex.search(accept)):
            accept = input(
                "Do you want to use a secure connection with SSL/TLS? (y/n): ").strip()
        tls = bool(yes_regex.search(accept))
        if not tls:
            accept = ""
            while not (yes_regex.search(accept) or no_regex.search(accept)):
                accept = input(
                    "Do you want to upgrade to a secure connection with StartTLS? (y/n): ").strip()
            starttls = bool(yes_regex.search(accept))
    fromemail = args.fromemail or input(
        "Enter the From e-mail address (e.g., 'User <user@example.com>'): ")
    username = args.username or input(
        "Enter your username for this account (e.g., 'user@example.com'): ")
    password = args.password or getpass.getpass(
        "Enter your password for this account: ")

    parser.set(section, "smtp", smtp_server)
    parser.set(section, "tls", str(tls))
    parser.set(section, "starttls", str(starttls))
    parser.set(section, "fromemail", fromemail)
    parser.set(section, "username", username)
    parser.set(section, "password", password)

    with open(CONFIG_FILE, "w") as configfile:
        parser.write(configfile)


def config_pgp(args):
    """Set the pgp passphrase to avoid future typing of the passphrase on the commandline."""
    section = "pgp"
    if not parser.has_section(section):
        parser.add_section(section)

        passphrase = getpass.getpass("Enter your PGP secret key passphrase: ")

        parser.set(section, "passphrase", passphrase)

        with open(CONFIG_FILE, "w") as configfile:
            parser.write(configfile)

        return passphrase

    return parser.get(section, "passphrase")


def return_config(args):
    """Pull (and check) variables in the .ini file."""
    section = "email"
    if not parser.has_section(section):
        print("The SMTP server and from e-mail address are not provided and not set in the config file. Please provide the --smtp and --from options or set the config file with the --config option.", file=sys.stderr)
        sys.exit(1)

    smtp_server = args.smtp or parser.get(section, "smtp")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        tls = parser.getboolean(section, "tls")
        starttls = parser.getboolean(section, "starttls")
    fromemail = args.fromemail or parser.get(section, "fromemail")
    username = args.username or parser.get(section, "username")
    password = args.password or parser.get(section, "password")

    return smtp_server, tls, starttls, fromemail, username, password
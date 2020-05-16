import sys
import os
import configparser
import getpass

'''Copyright © Daniel Connelly

   The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
'''

parser = configparser.ConfigParser()
CONFIG_FILE = os.path.expanduser('~/.sendpy.ini')
parser.read(CONFIG_FILE)


def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)


def config_email():
    '''Configures or reconfigures settings for send-msg-cli then writes the change to file'''
    SMTP_SERVER = str(
        input("Enter in the SMTP server you wish to use (e.g., smtp.example.com:465) "))
    FROM = str(input(
        "Enter in your From field for this email (e.g., User <username@example.com>) "))
    USERNAME = str(
        input("Enter in your username for this email (e.g., username@example.com) "))
    PASSWORD = str(getpass.getpass("Enter in your password for this email "))
    section = 'email'
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, 'SMTP', SMTP_SERVER)
    parser.set(section, 'from', FROM)
    parser.set(section, 'username', USERNAME)
    parser.set(section, 'password', PASSWORD)

    with open(CONFIG_FILE, "w") as configfile:
        parser.write(configfile)


def config_pgp():
    '''set the pgp passphrase to avoid future typing of the passphrase on the commandline'''
    section = "pgp"
    option = "passphrase"
    try:
        PGP = parser.get(section, option)
        choice = int(
            (input("1) Use passphrase?\n2) Reset passphrase\n3) Exit\n")))
        if choice == 1:
            return PGP
        elif choice == 2:
            PGP = str(getpass.getpass("Enter in your PGP passphrase: "))
            parser.set(section, 'passphrase', PGP)
            return parser.get(section, option)
        else:
            sys.exit()

    except configparser.NoSectionError:  # section is not created yet
        PGP = str(getpass.getpass(
            "PGP field not set yet. Enter in your PGP passphrase: "))
        parser.add_section(section)
        parser.set(section, 'passphrase', PGP)
        with open(CONFIG_FILE, "w") as configfile:
            parser.write(configfile)
        return parser.get(section, option)
    except Exception as error:
        error_exit(True, error)


def return_config():
    '''Pull (and check) variables in the .ini file'''
    SMTP_SERVER = parser['email']['SMTP']
    FROM = parser['email']['from']
    USERNAME = parser['email']['username']
    PASSWORD = parser['email']['password']
    PORT = 0  # if no port is found, default is 0 (465)
    smtp_port = SMTP_SERVER.split(":")
    if len(smtp_port) == 2:
        SMTP_SERVER = smtp_port[0]
        PORT = int(smtp_port[1])
    error_exit((len(smtp_port) > 2 or len(smtp_port) == 0) or FROM == "" or USERNAME == "",
               "SMTP, Username or Password not set in config file and not typed on CMDline. Please include the '-S', 'f', or '-u' flags, with arguments, or use the following command to set the config file: `sendpy --config`")
    return SMTP_SERVER, PORT, FROM, USERNAME, PASSWORD

import sys, os
import configparser
import getpass

'''The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
'''

parser = configparser.ConfigParser()
CONFIG_FILE = os.path.expanduser('~/.sendmsg.ini')
parser.read(CONFIG_FILE)

def config_email():
    '''Configures or reconfigures settings for send-msg-cli then writes the change to file'''
    SMTP_SERVER = str(input("Enter in the smtp server you wish to use (e.g., smtp.example.com:465) "))
    FROM = str(input("Enter in your From field for this email (e.g., username@example.com) "))
    USERNAME = str(input("Enter in your username for this email (e.g., username@example.com) "))
    PASSWORD = str(getpass.getpass("Enter in your password for this email "))
    section = 'email'
    parser.add_section(section)
    parser.set(section, 'smtp', SMTP_SERVER)
    parser.set(section, 'from', FROM)
    parser.set(section, 'username', USERNAME)
    parser.set(section, 'password', PASSWORD)

    with open(CONFIG_FILE, "w") as configfile:
        parser.write(configfile)

# TODO -- use this
def config_pgp():
    '''set the pgp passphrase to avoid future typing of the passphrase on the commandline'''
    section = "pgp"
    try:
        parser.get(section, option)
        option = str((input("PGP already set. Reset? (Y\\N)"))).upper()
        if option == "Y":
            PGP = str(input("Enter in the email provider you wish to use (e.g., smtp.example.com) "))
        else:
            return
    except:
        print("PGP not set yet... Enter password")
        PGP = str(input("Enter in your PGP passphrase"))
        parser.add_section(section)
        parser.set(section, 'passphrase', pgp)

def return_config():
    '''Pull (and check) variables in the .ini file'''
    SMTP_SERVER = parser['email']['smtp']
    FROM = parser['email']['from']
    USERNAME = parser['email']['username']
    PASSWORD = parser['email']['password']
    error_exit(SMTP_SERVER == "" or FROM == "" or USERNAME == "" or PASSWORD == "", "SMTP, Username or Password not set in config file and not typed on CMDline. Please include the '-S', '-u', or '-p' flags with arguments or use the following command to set the config file: `sendmsg --config`")
    return SMTP_SERVER, FROM, USERNAME, PASSWORD

def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)

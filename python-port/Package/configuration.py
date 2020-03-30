import configparser
import sys, os
import getpass

'''The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
'''

parser = configparser.ConfigParser()
CONFIG_FILE='~/.sendmsg.ini'
parser.read(os.path.expanduser(CONFIG_FILE))

def config_email():
    '''Configures or reconfigures settings for send-msg-cli then writes the change to file'''
    SMTP = str(input("Enter in the email provider you wish to use (e.g., smtp.gmail.com) "))
    USERNAME = str(input("Enter in your username for this email (e.g., example@example.edu) "))
    PASSWORD = str(getpass.getpass("Enter in your password for this email "))
    field = "email" # be careful 'email' does not work...
    parser.set(field, 'smtp', SMTP)
    parser.set(field, 'username', USERNAME)
    parser.set(field, 'password', PASSWORD)

    with open(os.path.expanduser(CONFIG_FILE), "w") as configfile:
        parser.write(configfile)
    print("Configuration file set successfully.")

def send_mail():
    '''Pull (and check) variables in the .ini file'''
    SMTP = parser['email']
    SMTP = parser['email']['smtp']
    USERNAME = parser['email']['username']
    PASSWORD = parser['email']['password']
    error_exit(SMTP == "" or USERNAME == "" or PASSWORD == "", "SMTP, Username or Password not set in config file and not typed on CMDline. Please include the '-S', '-u', or '-p' flags with arguments or use the following command to set the config file: `sendmsg --config`")
    return SMTP, USERNAME, PASSWORD

def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)

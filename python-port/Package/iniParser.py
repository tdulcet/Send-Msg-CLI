import configparser
import sys

config = configparser.ConfigParser()
config.read('.config.ini')

# TODO -- add checks for correct input....? Or let fail?
def config(option):
    '''Configures or reconfigures settings for send-msg-cli then writes the change to file'''
    if option == "EMAIL":
        SMTP = str(input("Enter in the email provider you wish to use (e.g., Google")) # TODO -- lookup table of email addresses with names, checks to see if that email's server exists in our registry ( and a reasonable response if it does not)
        USERNAME = str(input("Enter in your username for this email"))
        PASSWORD = str(input("Enter in your password for this email"))
        config.set('email', 'smtp', SMTP)
        config.set('email', 'username', USERNAME)
        config.set('email', 'password', PASSWORD)

    elif option == "TEXT":
        NUMBER = str(input("Enter in your mobile phone number"))
        CARRIER = str(input("Enter in your mobile carrier"))
        config.set('', 'smtp', SMTP)
        config.set('text', 'number', USERNAME)
        config.set('text', 'carrier', CARRIER)
    else:
        error_exit(True, "Not a valid option. Choose \"EMAIL\" or \"TEXT\"")

    with open(".config.ini", "w") as configfile:
        config.write(configfile)

def send_mail():
    SMTP = config['email']['smtp']
    USERNAME = config['email']['username']
    PASSWORD = config['email']['password']
    return SMTP, USERNAME, PASSWORD

def send_text():
    '''Reads in configuration file for sending a text message'''
    NUMBER = config['text']
    CARRIER = config['email']
    return NUMBER, CARRIER

def error_exit(condition, err):
    '''print an error and exit when one occurs'''
    if condition:
        sys.stderr.write(err)
        sys.exit(1)

def menu():
    '''Read in menu choices, return choice'''
    print("Choose From the Options Below: \n" +
            "1. Reconfigure configuration file.\n" +
            "2. Send e-mail.\n" +
            "3. Send text.\n" +
            "4. Exit.")

    num = int(input())
    if num > 0 and num < 5:
        return num
    else:
        error_exit(True, "Not a correct choice. Choose options 1-4.")

# TODO Add logic here for default configuration.

# Main program

# program input
num = menu()

# program navigation
if num == 1:
    intput(
    config()
elif num == 2:
    send_mail() # TODO -- do something with return values, or just send the message
elif num == 3:
    send_text() # TODO -- do something with return values, or just send the text
elif num == 4:
    sys.exit(0)


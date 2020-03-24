import configparser
import sys

'''The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
'''

config = configparser.ConfigParser()
config.read('.config.ini')

# TODO -- add checks for correct input....? Or let fail?
class Config:
    def config_email(self):
        '''Configures or reconfigures settings for send-msg-cli then writes the change to file'''
        SMTP = str(input("Enter in the email provider you wish to use (e.g., smtps://smtp.gmail.com")) # TODO -- lookup table of email addresses with names, checks to see if that email's server exists in our registry ( and a reasonable response if it does not)
        USERNAME = str(input("Enter in your username for this email (e.g., example@example.edu"))
        PASSWORD = str(input("Enter in your password for this email"))
        config.set(option, 'smtp', SMTP)
        config.set(option, 'username', USERNAME)
        config.set(option, 'password', PASSWORD)

        with open(".config.ini", "w") as configfile:
            config.write(configfile)

    def config_text(self):
        NUMBER = str(input("Enter in your mobile phone number"))
        CARRIER = str(input("Enter in your mobile carrier"))
        config.set(option, 'smtp', SMTP)
        config.set(option, 'number', USERNAME)
        config.set(option, 'carrier', CARRIER)

        with open(".config.ini", "w") as configfile:
            config.write(configfile)

    def is_configured(self, option, NUMBER=None, CARRIER=None, USERNAME=None, PASSWORD=None):
        '''We pass in the correct parameter. Others are by default None and should never be evaluated'''
        if option == "email":
            self.error_exit(USERNAME == "" or PASSWORD == "", "Username or Password not set. Please choose the \'Configure email\' option.") # TODO -- add more complicated and complete Regex
        if option == "text":
            self.error_exit(NUMBER == "" or CARRIER == "", "Number or Carrier not set. Please choose the \'Configure text\' option.") # TODO -- add more complicated and complete Regex

    def send_mail(self):
        '''Pull (and check) variables in the .ini file'''
        SMTP = config['email']['smtp']
        USERNAME = config['email']['username']
        PASSWORD = config['email']['password']
        is_configured("email")
        return SMTP, USERNAME, PASSWORD

    def send_text():
        '''Reads in configuration file for sending a text message'''
        NUMBER = config['text']['number']
        CARRIER = config['text']['carrier']
        is_configured("text", NUMBER=NUMBER, CARRIER=CARRIER)
        return NUMBER, CARRIER

    def error_exit(self, condition, err):
        '''print an error and exit when one occurs'''
        if condition:
            sys.stderr.write(err)
            sys.exit(1)

    def menu(self):
        '''Read in menu choices, return choice'''
        print("Choose From the Options Below: \n" +
                "1. Configure email.\n" +
                "2. Configure text.\n" +
                "3. Send e-mail.\n" +
                "4. Send text.\n" +
                "5. Exit.")

        num = int(input())
        if num > 0 and num < 6:
            return num
        else:
            error_exit(True, "Not a correct choice. Choose options 1-5.")

#if __name__=='__main__':
#    Config()
os.system("set +o history") # This disables the bash history for this current session (so as to not log passwords)

'''
# TODO Add logic here for default configuration.

# Main program

# program input
num = menu()

# program navigation
if num == 1:
    config()
elif num == 2:
    send_mail() # TODO -- do something with return values, or just send the message
elif num == 3:
    send_text() # TODO -- do something with return values, or just send the text
elif num == 4:
    sys.exit(0)
'''
